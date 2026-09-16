"""Single-writer append-only exporters for sensitive and operational events."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import json
import os
from pathlib import Path
import queue
import stat
import sys
import time
from typing import Any

from .models import Finding, STOP_SENTINEL
from .process_signals import ignore_windows_child_interrupts


def _private_directory_error(path: Path) -> str | None:
    """Return why ``path`` is not a private real directory, if anything."""

    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return "directory does not exist"
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return "must be a real directory and not a symbolic link"
    if os.name == "nt":
        from .windows_security import private_acl_error
        return private_acl_error(path)
    if os.name != "nt":
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o077:
            return f"permissions are {mode:03o}; expected no group/other access"
    return None


def prepare_private_directory(path: str | Path) -> Path:
    """Create or validate an owner-private evidence directory.

    Existing directories are never chmodded: an unexpectedly shared evidence
    location is a configuration error, not something this process should
    silently mutate.  Every missing component that this helper creates uses
    mode 0700, including under a conventional 0022 umask.
    """

    target = Path(os.path.abspath(os.fspath(path)))
    if os.name == "nt":
        from .windows_security import checked_local_path
        checked_local_path(target)
    missing: list[Path] = []
    cursor = target
    while True:
        try:
            os.lstat(cursor)
            break
        except FileNotFoundError:
            missing.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise OSError(f"cannot create private evidence directory: {target}")
            cursor = parent

    for directory in reversed(missing):
        try:
            if os.name == "nt":
                from .windows_security import create_private_directory
                create_private_directory(directory)
            else:
                os.mkdir(directory, 0o700)
        except FileExistsError:
            # A concurrent creator is acceptable only if it produced the same
            # private, real-directory invariant checked below.
            pass
        error = _private_directory_error(directory)
        if error is not None:
            raise PermissionError(
                f"refusing insecure evidence directory {directory}: {error}"
            )

    error = _private_directory_error(target)
    if error is not None:
        raise PermissionError(f"refusing insecure evidence directory {target}: {error}")
    return target


def prepare_private_parent(path: str | Path) -> Path:
    """Create or validate the immediate owner-private parent of ``path``."""

    return prepare_private_directory(Path(path).parent)


def _last_file_byte(fd: int, size: int) -> bytes:
    if hasattr(os, "pread"):
        return os.pread(fd, 1, size - 1)
    original = os.lseek(fd, 0, os.SEEK_CUR)
    try:
        os.lseek(fd, size - 1, os.SEEK_SET)
        return os.read(fd, 1)
    finally:
        os.lseek(fd, original, os.SEEK_SET)


def _validate_evidence_destination(
    path: Path,
) -> tuple[str | None, os.stat_result | None]:
    parent_error = _private_directory_error(path.parent)
    if parent_error is not None:
        return f"insecure immediate parent {path.parent}: {parent_error}", None
    if not os.access(path.parent, os.W_OK | os.X_OK):
        return f"immediate parent is not writable/searchable: {path.parent}", None

    try:
        path_metadata = os.lstat(path)
    except FileNotFoundError:
        return None, None
    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        return "existing destination must be a regular file and not a symbolic link", None
    if os.name == "nt":
        from .windows_security import private_acl_error
        error = private_acl_error(path)
        if error:
            return error, None
    if os.name != "nt":
        mode = stat.S_IMODE(path_metadata.st_mode)
        if mode != 0o600:
            return (
                f"existing destination permissions are {mode:03o}; expected 600"
            ), None
    if not os.access(path, os.R_OK | os.W_OK):
        return "existing destination is not readable and writable", None

    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        return f"existing destination cannot be safely opened: {exc}", None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return "existing destination must be a regular file", None
        if os.name == "nt":
            error = private_acl_error(path, fd=fd)
            if error:
                return error, None
        if metadata.st_size and _last_file_byte(fd, metadata.st_size) != b"\n":
            return "existing JSONL has a non-newline partial tail", None
        return None, metadata
    finally:
        os.close(fd)


def validate_evidence_paths(
    findings_path: str | Path,
    operations_path: str | Path,
    *,
    raw_capture_enabled: bool = False,
    raw_capture_dir: str | Path | None = None,
) -> tuple[bool, str]:
    """Read-only validation of evidence destinations used by startup doctors."""

    findings = Path(findings_path)
    operations = Path(operations_path)
    issues: list[str] = []
    findings_name = os.path.normcase(os.path.abspath(os.fspath(findings)))
    operations_name = os.path.normcase(os.path.abspath(os.fspath(operations)))
    if findings_name == operations_name:
        issues.append(
            "findings and operations destinations resolve to the same pathname"
        )
    opened: dict[str, os.stat_result] = {}
    for label, path in (("findings", findings), ("operations", operations)):
        error, metadata = _validate_evidence_destination(path)
        if error is not None:
            issues.append(f"{label}: {error}")
        elif metadata is not None:
            opened[label] = metadata

    if (
        "findings" in opened
        and "operations" in opened
        and os.path.samestat(opened["findings"], opened["operations"])
    ):
        issues.append(
            "findings and operations destinations resolve to the same file/inode"
        )

    if raw_capture_enabled:
        if raw_capture_dir is None:
            issues.append("raw capture is enabled but no destination directory was supplied")
        else:
            raw_path = Path(raw_capture_dir)
            raw_error = _private_directory_error(raw_path)
            if raw_error is not None:
                issues.append(f"raw capture directory {raw_path}: {raw_error}")
            elif not os.access(raw_path, os.W_OK | os.X_OK):
                issues.append(
                    f"raw capture directory is not writable/searchable: {raw_path}"
                )

    if issues:
        return False, "; ".join(issues)
    return True, "evidence destinations are private, distinct, and append-ready"


def _restricted_text_append(path: Path):
    path = Path(path)
    prepare_private_parent(path)
    if os.name == "nt" and path.exists():
        from .windows_security import private_acl_error
        error = private_acl_error(path)
        if error:
            raise PermissionError(f"refusing shared evidence file {path}: {error}")
    flags = os.O_APPEND | os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    fd = os.open(path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"refusing to write sensitive evidence to a non-regular file: {path}")
    metadata = os.fstat(fd)
    if os.name == "nt":
        from .windows_security import private_acl_error
        error = private_acl_error(path, fd=fd)
        if error:
            os.close(fd)
            raise PermissionError(f"refusing shared evidence file {path}: {error}")
    if metadata.st_size and _last_file_byte(fd, metadata.st_size) != b"\n":
        os.close(fd)
        raise OSError(
            f"refusing to append to JSONL with a non-newline partial tail: {path}"
        )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
    except OSError as exc:
        if os.name != "nt" and stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            os.close(fd)
            raise PermissionError(
                f"could not restrict evidence file permissions: {path}"
            ) from exc
    return os.fdopen(fd, "a", encoding="utf-8", buffering=1, newline="\n")


def _reject_same_open_file(left, right, left_path: Path, right_path: Path) -> None:
    left_stat = os.fstat(left.fileno())
    right_stat = os.fstat(right.fileno())
    if os.path.samestat(left_stat, right_stat):
        raise OSError(
            "findings and operations destinations resolve to the same file/inode: "
            f"{left_path} and {right_path}"
        )


def _json_safe(value: Any) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    return value


def write_json_line(handle, record: Any) -> str:
    line = (
        json.dumps(
            _json_safe(record), ensure_ascii=False, separators=(",", ":"), sort_keys=False
        )
        + "\n"
    )
    handle.write(line)
    return line


def _console_finding(finding: Finding, unredacted: bool) -> None:
    timestamp = finding.observed_timestamp_ns / 1_000_000_000
    material = finding.material if unredacted else "<written-unredacted-to-restricted-export>"
    message = {
        "time": timestamp,
        "event_id": finding.event_id,
        "protocol": finding.protocol,
        "type": finding.material_type,
        "confidence": finding.confidence,
        "flow": finding.flow_id,
        "attempt": finding.attempt_ordinal,
        "material": material,
    }
    print(json.dumps(_json_safe(message), ensure_ascii=False), flush=True)


def writer_process(
    finding_queue,
    operational_queue,
    output_jsonl: str,
    operational_jsonl: str,
    console_unredacted: bool,
    console_findings: bool = False,
    control_queue=None,
    heartbeat_seconds: float = 2.0,
) -> None:
    """Drain both queues without deduplicating or suppressing retries."""

    ignore_windows_child_interrupts()
    findings_path = Path(output_jsonl)
    operations_path = Path(operational_jsonl)

    def control(state: str, **fields: Any) -> None:
        if control_queue is None:
            return
        control_queue.put(
            {
                "role": "writer",
                "state": state,
                "pid": os.getpid(),
                "monotonic_ns": time.monotonic_ns(),
                **fields,
            }
        )

    with _restricted_text_append(findings_path) as findings_out, _restricted_text_append(
        operations_path
    ) as operations_out:
        _reject_same_open_file(
            findings_out, operations_out, findings_path, operations_path
        )
        write_json_line(
            operations_out,
            {
                "event": "writer_started",
                "timestamp_ns": time.time_ns(),
                "pid": os.getpid(),
                "unredacted_export": str(findings_path),
                "console_findings": console_findings or console_unredacted,
                "console_unredacted": console_unredacted,
            },
        )
        findings_written = 0
        operations_written = 1
        findings_digest = hashlib.sha256()
        control(
            "ready",
            findings_written=findings_written,
            operations_written=operations_written,
        )
        last_control = time.monotonic()
        findings_stopped = False
        operations_stopped = False
        while not (findings_stopped and operations_stopped):
            did_work = False
            if not findings_stopped:
                try:
                    item = finding_queue.get(timeout=0.1)
                    did_work = True
                    if item == STOP_SENTINEL:
                        findings_stopped = True
                    elif isinstance(item, Finding):
                        line = write_json_line(findings_out, item.to_dict())
                        findings_digest.update(line.encode("utf-8"))
                        findings_written += 1
                        if console_findings or console_unredacted:
                            _console_finding(item, console_unredacted)
                    else:
                        write_json_line(
                            operations_out,
                            {
                                "event": "writer_rejected_item",
                                "timestamp_ns": time.time_ns(),
                                "queue": "findings",
                                "type": type(item).__name__,
                            },
                        )
                        operations_written += 1
                except queue.Empty:
                    pass
            if not operations_stopped:
                for _ in range(256):
                    try:
                        item = operational_queue.get_nowait()
                        did_work = True
                    except queue.Empty:
                        break
                    if item == STOP_SENTINEL:
                        operations_stopped = True
                        break
                    write_json_line(operations_out, item)
                    operations_written += 1
            now = time.monotonic()
            if now - last_control >= heartbeat_seconds:
                control(
                    "heartbeat",
                    findings_written=findings_written,
                    operations_written=operations_written,
                )
                last_control = now
            if not did_work:
                time.sleep(0.01)

        write_json_line(
            operations_out,
            {
                "event": "writer_stopped",
                "timestamp_ns": time.time_ns(),
                "pid": os.getpid(),
                "findings_written": findings_written,
                "session_findings_sha256": findings_digest.hexdigest(),
            },
        )
        operations_written += 1
        findings_out.flush()
        operations_out.flush()
        os.fsync(findings_out.fileno())
        os.fsync(operations_out.fileno())
        control(
            "stopped",
            findings_written=findings_written,
            operations_written=operations_written,
            session_findings_sha256=findings_digest.hexdigest(),
        )


def verify_export_permissions(path: str | Path) -> tuple[bool, str]:
    target = Path(path)
    if not target.exists():
        return False, "file does not exist"
    if target.is_symlink() or not target.is_file():
        return False, "path must be a regular file and not a symbolic link"
    if os.name == "nt":
        from .windows_security import private_acl_error
        error = private_acl_error(target)
        if error:
            return False, error
    mode = target.stat().st_mode & 0o777
    if os.name != "nt" and mode & 0o077:
        return False, f"permissions are {mode:03o}; expected no group/other access"
    parent_error = _private_directory_error(target.parent)
    if parent_error is not None:
        return False, f"insecure immediate parent {target.parent}: {parent_error}"
    return True, ("Windows DACL is account/SYSTEM/Administrators-only; immediate parent is private"
                  if os.name == "nt" else f"permissions {mode:03o}; immediate parent is private")
