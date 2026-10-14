"""
Memory hygiene module: SecureBuffer with Windows VirtualLock and RtlSecureZeroMemory.
Prevents cryptographic secrets (FEK, Half_A, Half_B) from being swapped to disk
and ensures immediate zeroization upon release.
"""

from __future__ import annotations
import ctypes
import os
import sys
from typing import Optional, Union

# Windows API setup if running on Windows
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    try:
        kernel32 = ctypes.windll.kernel32
        _VirtualLock = kernel32.VirtualLock
        _VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _VirtualLock.restype = ctypes.c_bool

        _VirtualUnlock = kernel32.VirtualUnlock
        _VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _VirtualUnlock.restype = ctypes.c_bool

        # RtlSecureZeroMemory is guaranteed not to be optimized away by the compiler
        _RtlSecureZeroMemory = kernel32.RtlSecureZeroMemory
        _RtlSecureZeroMemory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _RtlSecureZeroMemory.restype = None
    except Exception:
        kernel32 = None
        _VirtualLock = None
        _VirtualUnlock = None
        _RtlSecureZeroMemory = None
else:
    kernel32 = None
    _VirtualLock = None
    _VirtualUnlock = None
    _RtlSecureZeroMemory = None


def secure_zero(address: int, size: int) -> None:
    """Zero-out memory block at address of given size."""
    if _RtlSecureZeroMemory is not None:
        _RtlSecureZeroMemory(ctypes.c_void_p(address), ctypes.c_size_t(size))
    else:
        ctypes.memset(address, 0, size)


def zero_bytearray(ba: bytearray) -> None:
    """Overwrites a bytearray with zeroes in-place."""
    for i in range(len(ba)):
        ba[i] = 0


class SecureBuffer:
    """
    A locked, mutable in-memory buffer for cryptographic key material.
    Automatically locks memory to avoid pagefile swapping (on Windows)
    and zeroizes memory upon exit or explicit wipe.
    """

    def __init__(self, size_or_data: Union[int, bytes, bytearray]):
        if isinstance(size_or_data, int):
            self._size = size_or_data
            self._buffer = ctypes.create_string_buffer(self._size)
        elif isinstance(size_or_data, (bytes, bytearray)):
            self._size = len(size_or_data)
            self._buffer = ctypes.create_string_buffer(bytes(size_or_data), self._size)
        else:
            raise TypeError("size_or_data must be int, bytes, or bytearray")

        self._locked = False
        self._wiped = False
        self._address = ctypes.addressof(self._buffer)

        # Attempt to lock page in RAM
        if IS_WINDOWS and _VirtualLock is not None:
            try:
                self._locked = bool(_VirtualLock(ctypes.c_void_p(self._address), ctypes.c_size_t(self._size)))
            except Exception:
                self._locked = False

    @property
    def size(self) -> int:
        return self._size

    @property
    def is_wiped(self) -> bool:
        return self._wiped

    def to_bytes(self) -> bytes:
        """Returns a copy of the buffer content as immutable bytes."""
        if self._wiped:
            raise ValueError("SecureBuffer has already been wiped")
        return self._buffer.raw[:self._size]

    def to_bytearray(self) -> bytearray:
        """Returns a copy of the buffer content as mutable bytearray."""
        if self._wiped:
            raise ValueError("SecureBuffer has already been wiped")
        return bytearray(self._buffer.raw[:self._size])

    def write(self, data: bytes, offset: int = 0) -> None:
        """Writes data into buffer at the specified offset."""
        if self._wiped:
            raise ValueError("SecureBuffer has already been wiped")
        if offset + len(data) > self._size:
            raise ValueError("Data exceeds buffer capacity")
        ctypes.memmove(self._address + offset, data, len(data))

    def wipe(self) -> None:
        """Securely zeroes out the memory buffer and unlocks it."""
        if not self._wiped:
            secure_zero(self._address, self._size)
            if self._locked and IS_WINDOWS and _VirtualUnlock is not None:
                try:
                    _VirtualUnlock(ctypes.c_void_p(self._address), ctypes.c_size_t(self._size))
                except Exception:
                    pass
                self._locked = False
            self._wiped = True

    def __enter__(self) -> SecureBuffer:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()

    def __del__(self) -> None:
        self.wipe()
