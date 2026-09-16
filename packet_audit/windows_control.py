"""Short-lived helper: request graceful shutdown in our dumpcap child's console.

The child has its own hidden console. Attaching in this helper leaves the
manager's console and other applications untouched. Never invoke for other PIDs.
"""
import ctypes
from ctypes import wintypes
import os
import sys
import time


def signal_console(pid: int, event: int = 1) -> None:
    if os.name != 'nt' or pid <= 0 or event not in (0, 1):
        raise ValueError('Requires a Windows child PID')
    kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    kernel.FreeConsole.argtypes, kernel.FreeConsole.restype = [], wintypes.BOOL
    kernel.AttachConsole.argtypes, kernel.AttachConsole.restype = [wintypes.DWORD], wintypes.BOOL
    kernel.SetConsoleCtrlHandler.argtypes = [callback_type, wintypes.BOOL]
    kernel.SetConsoleCtrlHandler.restype = wintypes.BOOL
    kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.GenerateConsoleCtrlEvent.restype = wintypes.BOOL
    kernel.FreeConsole()
    if not kernel.AttachConsole(pid):
        raise ctypes.WinError(ctypes.get_last_error())
    handler = callback_type(lambda _event: True)
    try:
        if not kernel.SetConsoleCtrlHandler(handler, True):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GenerateConsoleCtrlEvent(event, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(0.15)
    finally:
        kernel.FreeConsole()


if __name__ == '__main__':
    signal_console(int(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 1)
