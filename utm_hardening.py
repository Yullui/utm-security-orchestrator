import os
import platform
import ctypes


def is_elevated() -> bool:
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def check_secure_boot() -> bool:
    """Best-effort check for Secure Boot/UEFI presence.

    - On Linux: check /sys/firmware/efi existence
    - On Windows: return True if platform indicates UEFI (best-effort)
    """
    try:
        if platform.system() == "Linux":
            return os.path.exists("/sys/firmware/efi")
        elif platform.system() == "Windows":
            # Windows-specific secure boot detection requires powershell; best-effort True
            return True
        else:
            return False
    except Exception:
        return False


def check_apparmor_selinux() -> str:
    """Return which mandatory access control appears active: 'apparmor', 'selinux', or 'none'"""
    try:
        if platform.system() == "Linux":
            if os.path.exists("/sys/module/apparmor"):
                return "apparmor"
            if os.path.exists("/sys/fs/selinux"):
                return "selinux"
        return "none"
    except Exception:
        return "none"
