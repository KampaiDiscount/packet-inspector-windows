"""Resolve capture tools without searching the current Windows directory."""
import os
from pathlib import Path
import shutil


def find_dumpcap(configured: str = 'dumpcap') -> str | None:
    if os.name != 'nt' or configured not in {'dumpcap', 'dumpcap.exe'}:
        return shutil.which(configured)
    import winreg
    candidates = []
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Wireshark', 0, winreg.KEY_READ | view) as key:
                candidates.append(Path(winreg.QueryValueEx(key, 'InstallDir')[0]) / 'dumpcap.exe')
        except OSError:
            pass
    for variable in ('ProgramW6432', 'ProgramFiles', 'ProgramFiles(x86)'):
        if os.environ.get(variable):
            candidates.append(Path(os.environ[variable]) / 'Wireshark' / 'dumpcap.exe')
    return next((str(path) for path in candidates if path.is_absolute() and path.is_file()), None)
