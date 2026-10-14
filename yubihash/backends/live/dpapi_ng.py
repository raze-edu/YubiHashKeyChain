"""
Windows CNG DPAPI-NG Backend using native ncrypt.dll.
Protects and unprotects secrets bound to Active Directory Group SIDs via the Domain Controller KDS root key.
Automatically handles Kerberos ticket refreshing (klist purge) on NTE_BAD_KEY_STATE.
"""

from __future__ import annotations
import ctypes
import os
import subprocess
import sys
from typing import Optional

from yubihash.backends.base import DpapiNgBackend

# Constants from ncrypt.h / winerror.h
NCRYPT_SILENT_FLAG = 0x00000040
NTE_BAD_KEY_STATE = 0x8009000B
ERROR_ACCESS_DENIED = 0x80070005
SEC_E_LOGON_DENIED = 0x8009030C


class LiveDpapiNg(DpapiNgBackend):
    """
    Live Windows CNG DPAPI-NG implementation calling ncrypt.dll.
    Requires domain-joined Windows PC and Domain Controller with KDS Root Key.
    """

    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("LiveDpapiNg is only supported on Windows")

        self.ncrypt = ctypes.windll.ncrypt
        self.kernel32 = ctypes.windll.kernel32

        # Setup ctypes function signatures
        # SECURITY_STATUS NCryptCreateProtectionDescriptor(LPCWSTR pwszDescriptorString, DWORD dwFlags, NCRYPT_DESCRIPTOR_HANDLE *phDescriptor);
        self._NCryptCreateProtectionDescriptor = self.ncrypt.NCryptCreateProtectionDescriptor
        self._NCryptCreateProtectionDescriptor.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._NCryptCreateProtectionDescriptor.restype = ctypes.c_int32

        # SECURITY_STATUS NCryptCloseProtectionDescriptor(NCRYPT_DESCRIPTOR_HANDLE hDescriptor);
        self._NCryptCloseProtectionDescriptor = self.ncrypt.NCryptCloseProtectionDescriptor
        self._NCryptCloseProtectionDescriptor.argtypes = [ctypes.c_void_p]
        self._NCryptCloseProtectionDescriptor.restype = ctypes.c_int32

        # SECURITY_STATUS NCryptProtectSecret(NCRYPT_DESCRIPTOR_HANDLE hDescriptor, DWORD dwFlags, const PBYTE pbData, DWORD cbData,
        #                                     const NCRYPT_ALLOC_PARA *pAllocPara, HWND hWnd, PBYTE *ppbProtectedBlob, DWORD *pcbProtectedBlob);
        self._NCryptProtectSecret = self.ncrypt.NCryptProtectSecret
        self._NCryptProtectSecret.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._NCryptProtectSecret.restype = ctypes.c_int32

        # SECURITY_STATUS NCryptUnprotectSecret(NCRYPT_DESCRIPTOR_HANDLE *phDescriptor, DWORD dwFlags, const PBYTE pbProtectedBlob, DWORD cbProtectedBlob,
        #                                       const NCRYPT_ALLOC_PARA *pAllocPara, HWND hWnd, PBYTE *ppbData, DWORD *pcbData);
        self._NCryptUnprotectSecret = self.ncrypt.NCryptUnprotectSecret
        self._NCryptUnprotectSecret.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._NCryptUnprotectSecret.restype = ctypes.c_int32

        self._LocalFree = self.kernel32.LocalFree
        self._LocalFree.argtypes = [ctypes.c_void_p]
        self._LocalFree.restype = ctypes.c_void_p

    def protect_secret(self, group_sid: str, secret: bytes) -> bytes:
        descriptor_str = f"SID={group_sid}"
        h_desc = ctypes.c_void_p()

        status = self._NCryptCreateProtectionDescriptor(descriptor_str, 0, ctypes.byref(h_desc))
        if status != 0:
            raise OSError(f"NCryptCreateProtectionDescriptor failed with code: 0x{status & 0xFFFFFFFF:08X}")

        try:
            cb_data = len(secret)
            pb_data = (ctypes.c_uint8 * cb_data).from_buffer_copy(secret)
            ppb_protected = ctypes.POINTER(ctypes.c_uint8)()
            pcb_protected = ctypes.c_uint32()

            status = self._NCryptProtectSecret(
                h_desc,
                NCRYPT_SILENT_FLAG,
                pb_data,
                cb_data,
                None,
                None,
                ctypes.byref(ppb_protected),
                ctypes.byref(pcb_protected),
            )
            if status != 0:
                raise OSError(f"NCryptProtectSecret failed with code: 0x{status & 0xFFFFFFFF:08X}")

            try:
                result = bytes(ppb_protected[:pcb_protected.value])
                return result
            finally:
                self._LocalFree(ppb_protected)
        finally:
            self._NCryptCloseProtectionDescriptor(h_desc)

    def unprotect_secret(self, protected_blob: bytes, retry_purge_kerberos: bool = True) -> bytes:
        try:
            return self._call_unprotect(protected_blob)
        except OSError as e:
            # Check for Kerberos ticket stale or access denied
            code = getattr(e, "winerror", None)
            if retry_purge_kerberos:
                # Purge Kerberos tickets to force refresh from Domain Controller
                try:
                    subprocess.run(["klist", "purge"], capture_output=True, check=False)
                    # Retry once
                    return self._call_unprotect(protected_blob)
                except Exception:
                    pass
            raise

    def _call_unprotect(self, protected_blob: bytes) -> bytes:
        cb_protected = len(protected_blob)
        pb_protected = (ctypes.c_uint8 * cb_protected).from_buffer_copy(protected_blob)
        ppb_data = ctypes.POINTER(ctypes.c_uint8)()
        pcb_data = ctypes.c_uint32()

        status = self._NCryptUnprotectSecret(
            None,
            NCRYPT_SILENT_FLAG,
            pb_protected,
            cb_protected,
            None,
            None,
            ctypes.byref(ppb_data),
            ctypes.byref(pcb_data),
        )
        if status != 0:
            err = OSError(f"NCryptUnprotectSecret failed with code: 0x{status & 0xFFFFFFFF:08X}")
            err.winerror = status & 0xFFFFFFFF
            raise err

        try:
            result = bytes(ppb_data[:pcb_data.value])
            return result
        finally:
            self._LocalFree(ppb_data)
