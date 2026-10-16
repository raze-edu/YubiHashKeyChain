"""
Local (non-Active-Directory) backends for lab testing on standalone machines:
- LocalDirectory: JSON-file directory replacing AD / LDAP
- LocalKdsDpapiNg: simulated KDS root key replacing AD-group DPAPI-NG
- SoftwareYubiKey: persistent, PIN-protected PIV emulation
"""

from yubihash.backends.local.local_directory import DirectoryEntryNotFound, LocalDirectory
from yubihash.backends.local.local_kds import LocalKdsDpapiNg
from yubihash.backends.local.software_yubikey import (
    DEFAULT_PIV_PIN,
    IncorrectPinError,
    SoftwareYubiKey,
)

__all__ = [
    "DEFAULT_PIV_PIN",
    "DirectoryEntryNotFound",
    "IncorrectPinError",
    "LocalDirectory",
    "LocalKdsDpapiNg",
    "SoftwareYubiKey",
]
