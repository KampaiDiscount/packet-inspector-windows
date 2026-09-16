"""Windows evidence ACLs, using system APIs rather than POSIX chmod emulation.

Only newly created directories receive an ACL. Existing shared destinations are
rejected. Administrators and SYSTEM remain trusted; other processes running as
the same account can read that account's evidence.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from functools import lru_cache
import os
from pathlib import Path
import stat


class SecurityAttributes(C.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit', W.BOOL)]


class AclSize(C.Structure):
    _fields_ = [('count', W.DWORD), ('used', W.DWORD), ('free', W.DWORD)]


@lru_cache(maxsize=1)
def _api():
    if os.name != 'nt':
        raise OSError('Windows ACL APIs are only available on Windows')
    kernel = C.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    advapi = C.WinDLL('advapi32.dll', use_last_error=True, winmode=0x800)
    specs = [
        (kernel, 'GetCurrentProcess', [], W.HANDLE),
        (kernel, 'CloseHandle', [W.HANDLE], W.BOOL),
        (kernel, 'LocalFree', [C.c_void_p], C.c_void_p),
        (kernel, 'CreateDirectoryW', [W.LPCWSTR, C.POINTER(SecurityAttributes)], W.BOOL),
        (advapi, 'OpenProcessToken', [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)], W.BOOL),
        (advapi, 'GetTokenInformation', [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)], W.BOOL),
        (advapi, 'ConvertSidToStringSidW', [C.c_void_p, C.POINTER(C.c_void_p)], W.BOOL),
        (advapi, 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
         [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.POINTER(W.DWORD)], W.BOOL),
        (advapi, 'GetNamedSecurityInfoW', [W.LPWSTR, C.c_int, W.DWORD,
         C.POINTER(C.c_void_p), C.c_void_p, C.POINTER(C.c_void_p), C.c_void_p, C.POINTER(C.c_void_p)], W.DWORD),
        (advapi, 'GetSecurityInfo', [W.HANDLE, C.c_int, W.DWORD,
         C.POINTER(C.c_void_p), C.c_void_p, C.POINTER(C.c_void_p), C.c_void_p, C.POINTER(C.c_void_p)], W.DWORD),
        (advapi, 'GetAclInformation', [C.c_void_p, C.c_void_p, W.DWORD, C.c_int], W.BOOL),
        (advapi, 'GetAce', [C.c_void_p, W.DWORD, C.POINTER(C.c_void_p)], W.BOOL),
    ]
    for dll, name, args, result in specs:
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
    return kernel, advapi


def _sid_text(pointer) -> str:
    kernel, advapi = _api()
    output = C.c_void_p()
    if not advapi.ConvertSidToStringSidW(pointer, C.byref(output)):
        raise C.WinError(C.get_last_error())
    try:
        return C.wstring_at(output)
    finally:
        kernel.LocalFree(output)


@lru_cache(maxsize=1)
def current_user_sid() -> str:
    kernel, advapi = _api()
    token, size = W.HANDLE(), W.DWORD()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x8, C.byref(token)):
        raise C.WinError(C.get_last_error())
    try:
        advapi.GetTokenInformation(token, 1, None, 0, C.byref(size))
        if not 0 < size.value < 1024 * 1024:
            raise OSError('Unable to size the current user token')
        buffer = C.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 1, buffer, size, C.byref(size)):
            raise C.WinError(C.get_last_error())
        return _sid_text(C.cast(buffer, C.POINTER(C.c_void_p))[0])
    finally:
        kernel.CloseHandle(token)


def checked_local_path(path: str | Path) -> Path:
    target = Path(os.path.abspath(os.fspath(path)))
    if str(target).startswith('\\\\') or any(':' in part for part in target.parts[1:]):
        raise PermissionError('Evidence must use a local path without device namespaces or alternate streams')
    for component in (target, *target.parents):
        try:
            info = os.lstat(component)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise PermissionError(f'Reparse points/junctions are not evidence destinations: {component}')
    return target


def private_acl_error(path: str | Path, *, fd: int | None = None) -> str | None:
    """Read-only ACL check; descriptor memory is always released by LocalFree."""
    try:
        target = checked_local_path(path)
        info = os.fstat(fd) if fd is not None else os.lstat(target)
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            return 'evidence files must not have additional hard links (same file/inode alias)'
        kernel, advapi = _api()
        owner, dacl, descriptor = C.c_void_p(), C.c_void_p(), C.c_void_p()
        if fd is not None:
            import msvcrt
            status = advapi.GetSecurityInfo(msvcrt.get_osfhandle(fd), 1, 0x5,
                C.byref(owner), None, C.byref(dacl), None, C.byref(descriptor))
        else:
            status = advapi.GetNamedSecurityInfoW(str(target), 1, 0x5,
                C.byref(owner), None, C.byref(dacl), None, C.byref(descriptor))
        if status:
            raise C.WinError(status)
        try:
            trusted = {current_user_sid(), 'S-1-5-18', 'S-1-5-32-544'}
            if not owner or _sid_text(owner) not in trusted:
                return 'evidence owner is not the current account, SYSTEM or Administrators'
            # Python's Windows mkdir(0700) uses OWNER RIGHTS rather than the
            # literal user SID. The owner was verified above, so this is private.
            trusted.add('S-1-3-4')
            if not dacl:
                return 'evidence has a null/unrestricted DACL'
            acl = AclSize()
            if not advapi.GetAclInformation(dacl, C.byref(acl), C.sizeof(acl), 2):
                raise C.WinError(C.get_last_error())
            for index in range(acl.count):
                ace = C.c_void_p()
                if not advapi.GetAce(dacl, index, C.byref(ace)):
                    raise C.WinError(C.get_last_error())
                kind = C.c_ubyte.from_address(ace.value).value
                # Also reject broad inherit-only grants: dumpcap creates raw
                # files below this directory and must inherit private access.
                if kind == 1:  # A deny ACE cannot expose the evidence.
                    continue
                if kind != 0:
                    return 'evidence has an unsupported conditional/object ACL entry'
                mask = W.DWORD.from_address(ace.value + 4).value
                if mask and _sid_text(ace.value + 8) not in trusted:
                    return 'evidence ACL grants access to another account or group'
            return None
        finally:
            kernel.LocalFree(descriptor)
    except OSError as exc:
        return str(exc)


def create_private_directory(path: str | Path) -> None:
    """Atomically create one directory with a protected inheritable DACL."""
    target = checked_local_path(path)
    kernel, advapi = _api()
    sid = current_user_sid()
    sddl = f'O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    descriptor = C.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(descriptor), None):
        raise C.WinError(C.get_last_error())
    try:
        attributes = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
        if not kernel.CreateDirectoryW(str(target), C.byref(attributes)):
            error = C.get_last_error()
            if error != 183:  # A concurrent creator still has to pass validation.
                raise C.WinError(error)
        error = private_acl_error(target)
        if error:
            raise PermissionError(f'Refusing shared evidence directory {target}: {error}')
    finally:
        kernel.LocalFree(descriptor)
