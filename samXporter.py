import os
import sys
import ctypes
import logging
import argparse
from pathlib import Path
from ctypes import windll, c_int, c_long, Structure, POINTER, byref, c_void_p
from ctypes.wintypes import HANDLE, DWORD, LPCWSTR, BOOL, HKEY

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

SE_BACKUP_NAME   = "SeBackupPrivilege"
SE_SECURITY_NAME = "SeSecurityPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0000000002

ERROR_SUCCESS          = 0
KEY_READ               = 0x20019
KEY_WOW64_64KEY        = 0x0100
REG_NO_COMPRESSION     = 4
MAXIMUM_ALLOWED        = 0x02000000
HKEY_LOCAL_MACHINE     = HKEY(c_long(0x80000002).value)

class LUID(Structure):
    _fields_ = [("LowPart", DWORD), ("HighPart", c_int)]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [("Luid", LUID), ("Attributes", DWORD)]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [("PrivilegeCount", DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def setup_win_api():
    windll.advapi32.OpenProcessToken.argtypes = [c_void_p, DWORD, POINTER(HANDLE)]
    windll.advapi32.OpenProcessToken.restype = BOOL
    windll.advapi32.LookupPrivilegeValueW.argtypes = [LPCWSTR, LPCWSTR, POINTER(LUID)]
    windll.advapi32.LookupPrivilegeValueW.restype = BOOL
    windll.advapi32.AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, POINTER(TOKEN_PRIVILEGES), DWORD, c_void_p, c_void_p]
    windll.advapi32.AdjustTokenPrivileges.restype = BOOL
    windll.advapi32.RegOpenKeyExW.argtypes = [HKEY, LPCWSTR, DWORD, DWORD, POINTER(HKEY)]
    windll.advapi32.RegOpenKeyExW.restype = c_long
    windll.advapi32.RegSaveKeyExW.argtypes = [HKEY, LPCWSTR, c_void_p, DWORD]
    windll.advapi32.RegSaveKeyExW.restype = c_long
    windll.advapi32.RegCloseKey.argtypes = [HKEY]
    windll.advapi32.RegCloseKey.restype = c_long

def enable_privilege(privilege_name):
    try:
        hprocess = windll.kernel32.GetCurrentProcess()
        htoken = HANDLE()

        if not windll.advapi32.OpenProcessToken(hprocess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, byref(htoken)):
            logger.debug(f"OpenProcessToken failed (code: {ctypes.get_last_error()})")
            return False

        luid = LUID()
        if not windll.advapi32.LookupPrivilegeValueW(None, privilege_name, byref(luid)):
            logger.debug(f"LookupPrivilegeValue failed (code: {ctypes.get_last_error()})")
            windll.kernel32.CloseHandle(htoken)
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not windll.advapi32.AdjustTokenPrivileges(htoken, False, byref(tp), 0, None, None):
            logger.debug(f"AdjustTokenPrivileges failed (code: {ctypes.get_last_error()})")
            windll.kernel32.CloseHandle(htoken)
            return False

        windll.kernel32.CloseHandle(htoken)
        logger.debug(f"{privilege_name} enabled successfully")
        return True

    except Exception as e:
        logger.debug(f"Exception: {e}")
        return False

def save_registry_hive(hive_name, output_path):
    subkey = hive_name.split("\\", 1)[1]

    access = MAXIMUM_ALLOWED if subkey == "SECURITY" else KEY_READ | KEY_WOW64_64KEY

    if os.path.exists(output_path):
        try:
            os.remove(output_path)
        except OSError as e:
            logger.debug(f"Cannot remove existing file: {e}")
            return False

    hkey = HKEY()
    ret = windll.advapi32.RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, subkey, 0, access, byref(hkey)
    )
    if ret != ERROR_SUCCESS:
        logger.debug(f"RegOpenKeyExW({subkey}) failed, code={ret:#010x}")
        return False

    try:
        ret = windll.advapi32.RegSaveKeyExW(hkey, output_path, None, REG_NO_COMPRESSION)
        if ret == ERROR_SUCCESS:
            size = os.path.getsize(output_path)
            logger.info(f"Saved {hive_name} to {output_path} ({size} bytes)")
            return True
        else:
            logger.debug(f"RegSaveKeyExW({subkey}) failed, code={ret:#010x}")
            return False
    finally:
        windll.advapi32.RegCloseKey(hkey)

def backup_hives(output_dir):
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Backup directory: {output_dir}")
    except Exception as e:
        logger.debug(f"Failed to create directory: {e}")
        return False

    hives = {
        "HKLM\\SAM":      os.path.join(output_dir, "SAM"),
        "HKLM\\SYSTEM":   os.path.join(output_dir, "SYSTEM"),
        "HKLM\\SECURITY": os.path.join(output_dir, "SECURITY")
    }

    results = [save_registry_hive(hive, path) for hive, path in hives.items()]
    return all(results)

def main():
    parser = argparse.ArgumentParser(description="Registry Hives Backup")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    setup_win_api()

    script_dir = Path(__file__).parent
    backup_dir = script_dir / "Registry_Backup"

    logger.debug("Registry Hives Backup Script started")

    if not ctypes.windll.shell32.IsUserAnAdmin():
        logger.debug("Admin privileges not detected")
        sys.exit(1)

    logger.debug("Admin privileges detected")

    if not enable_privilege(SE_BACKUP_NAME):
        logger.debug("Unable to enable SeBackupPrivilege")
        sys.exit(1)

    if not enable_privilege(SE_SECURITY_NAME):
        logger.debug("Unable to enable SeSecurityPrivilege")
        sys.exit(1)

    if backup_hives(str(backup_dir)):
        logger.debug("Backup completed successfully")
    else:
        logger.debug("Backup completed with errors")

if __name__ == "__main__":
    main()