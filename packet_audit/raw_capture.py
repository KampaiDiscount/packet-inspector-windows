"""Independent dumpcap ring capture used as the durable packet source of truth."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import re
import signal
import stat
import subprocess
import sys
import time
from uuid import uuid4

from .config import AuditConfig
from .writer import prepare_private_directory
from .platform_tools import find_dumpcap


@dataclass(slots=True)
class RawCaptureStatus:
    enabled: bool
    running: bool
    pid: int | None
    returncode: int | None
    command: tuple[str, ...]
    stderr_path: str | None
    forced_termination: bool = False


def build_dumpcap_command(
    config: AuditConfig, *, basename: str = "packet-audit.pcapng"
) -> list[str]:
    if not basename or any(character in basename for character in ("/", "\\", ":", "\x00")) or basename in (".", ".."):
        raise ValueError("raw capture basename must be a single local filename")
    output_dir = config.raw_capture_dir
    base = output_dir / basename
    command = [
        config.dumpcap_path,
        "-i",
        config.interface,
        "-B",
        str(config.capture_buffer_mb),
        "-s",
        str(config.snaplen),
        "-f",
        config.bpf,
        "-b",
        f"filesize:{config.raw_capture_file_mb * 1000}",
        "-b",
        f"duration:{config.raw_capture_duration_seconds}",
        "-b",
        f"files:{config.raw_capture_files}",
        "-w",
        str(base),
        "-q",
    ]
    return command


class DumpcapRing:
    def __init__(self, config: AuditConfig):
        self.config = config
        self.command = build_dumpcap_command(
            config, basename=f"packet-audit-{uuid4().hex}.pcapng"
        ) if config.raw_capture_enabled else []
        self.process: subprocess.Popen | None = None
        self.stderr_handle = None
        self.stderr_path = config.raw_capture_dir / "dumpcap.stderr.log"
        self.forced_termination = False

    def preflight(self) -> tuple[bool, str]:
        if not self.config.raw_capture_enabled:
            return True, "raw ring disabled by configuration"
        resolved = find_dumpcap(self.config.dumpcap_path)
        if not resolved:
            return False, f"dumpcap not found: {self.config.dumpcap_path}"
        probe = subprocess.run(
            [resolved, "-D"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        combined = (probe.stdout or "") + (probe.stderr or "")
        if probe.returncode != 0:
            return False, f"dumpcap interface probe failed: {combined.strip()}"
        interface_tokens = {match.group(1) for line in combined.splitlines()
                            if (match := re.match(r"^\d+\.\s+(\S+)", line))}
        if self.config.interface not in interface_tokens:
            return False, f"interface {self.config.interface!r} not listed by dumpcap -D"
        return True, resolved

    def start(self) -> RawCaptureStatus:
        if not self.config.raw_capture_enabled:
            return self.status()
        if self.process and self.process.poll() is None:
            return self.status()
        self._close_stderr()
        resolved = find_dumpcap(self.config.dumpcap_path)
        if not resolved:
            raise RuntimeError("dumpcap is unavailable; install Wireshark capture tools")
        # dumpcap truncates rather than exclusively creates ring filenames.
        # A fresh unpredictable prefix avoids reusing a pre-existing file's
        # Windows ACL (or a same-second prior session), including on restart.
        self.command = build_dumpcap_command(
            self.config, basename=f"packet-audit-{uuid4().hex}.pcapng"
        )
        self.command[0] = resolved
        prepare_private_directory(self.config.raw_capture_dir)
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        fd = os.open(self.stderr_path, flags, 0o600)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise RuntimeError("dumpcap stderr destination is not a regular file")
        if os.name == "nt":
            from .windows_security import private_acl_error
            error = private_acl_error(self.stderr_path, fd=fd)
            if error:
                os.close(fd)
                raise PermissionError(error)
        try:
            os.chmod(self.stderr_path, 0o600)
        except OSError:
            pass
        self.stderr_handle = os.fdopen(fd, "ab", buffering=0)
        kwargs: dict[str, object] = {}
        if os.name != "nt":
            kwargs["start_new_session"] = True
        else:
            # A separate hidden console allows graceful Ctrl+Break even when
            # the Python caller itself has no console (desktop/GUI launches).
            startup = subprocess.STARTUPINFO()
            startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startup.wShowWindow = 0
            kwargs.update(creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
        try:
            self.process = subprocess.Popen(
                self.command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=self.stderr_handle, **kwargs,
            )
        except BaseException:
            self._close_stderr()
            raise
        time.sleep(0.25)
        if self.process.poll() is not None:
            status = self.status()
            self._close_stderr()
            raise RuntimeError(f"dumpcap exited during startup with {status.returncode}")
        return self.status()

    def stop(self, timeout: float = 10.0) -> RawCaptureStatus:
        process = self.process
        try:
            if not process:
                return self.status()
            if process.poll() is None:
                if os.name != "nt":
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                else:
                    try:
                        subprocess.run([sys.executable, *(['-I'] if sys.flags.isolated else []), '-m', 'packet_audit.windows_control', str(process.pid)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=min(timeout, 3.0), check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    except (OSError, subprocess.SubprocessError):
                        self.forced_termination = True
                        process.terminate()
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self.forced_termination = True
                    if os.name != "nt":
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        process.kill()
                    process.wait(timeout=5)
            return self.status()
        finally:
            self._close_stderr()

    def _close_stderr(self) -> None:
        if self.stderr_handle:
            self.stderr_handle.close()
            self.stderr_handle = None

    def status(self) -> RawCaptureStatus:
        returncode = self.process.poll() if self.process else None
        return RawCaptureStatus(
            enabled=self.config.raw_capture_enabled,
            running=bool(self.process and returncode is None),
            pid=self.process.pid if self.process else None,
            returncode=returncode,
            command=tuple(self.command),
            stderr_path=str(self.stderr_path) if self.config.raw_capture_enabled else None,
            forced_termination=self.forced_termination,
        )
