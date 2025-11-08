import os
import sys
import ctypes
import subprocess
import logging
from pathlib import Path
from ctypes import windll, c_int, Structure, POINTER, byref, c_void_p
from ctypes.wintypes import HANDLE, DWORD, LPCWSTR, BOOL

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

SE_BACKUP_NAME = "SeBackupPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x0000000002

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

def enable_backup_privilege():
    try:
        setup_win_api()
        
        hprocess = windll.kernel32.GetCurrentProcess()
        htoken = HANDLE()
        
        if not windll.advapi32.OpenProcessToken(hprocess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, byref(htoken)):
            logger.debug(f"OpenProcessToken failed (code: {ctypes.get_last_error()})")
            return False
        
        luid = LUID()
        if not windll.advapi32.LookupPrivilegeValueW(None, SE_BACKUP_NAME, byref(luid)):
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
        logger.debug("SeBackupPrivilege enabled successfully")
        return True
        
    except Exception as e:
        logger.debug(f"Exception: {e}")
        return False

def save_registry_hive(hive_name, output_path):
    try:
        result = subprocess.run(["reg", "save", hive_name, output_path, "/y"], capture_output=True, text=True, check=False)
        
        if result.returncode == 0:
            size = os.path.getsize(output_path)
            logger.info(f"Saved {hive_name} to {output_path} ({size} bytes)")
            return True
        else:
            logger.debug(f"Failed to save {hive_name}")
            if result.stderr:
                logger.debug(f"Error details: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        logger.debug(f"Exception during save: {e}")
        return False

def backup_hives(output_dir):
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Backup directory: {output_dir}")
    except Exception as e:
        logger.debug(f"Failed to create directory: {e}")
        return False
    
    hives = {
        "HKLM\\SAM": os.path.join(output_dir, "SAM"),
        "HKLM\\SYSTEM": os.path.join(output_dir, "SYSTEM"),
        "HKLM\\SECURITY": os.path.join(output_dir, "SECURITY")
    }
    
    results = [save_registry_hive(hive, path) for hive, path in hives.items()]
    return all(results)

def main():
    script_dir = Path(__file__).parent
    backup_dir = script_dir / "Registry_Backup"
    
    logger.debug("Registry Hives Backup Script started")
    
    if not ctypes.windll.shell32.IsUserAnAdmin():
        logger.debug("Admin privileges not detected")
        sys.exit(1)
    
    logger.debug("Admin privileges detected")
    
    if not enable_backup_privilege():
        logger.debug("Unable to enable SeBackupPrivilege")
        sys.exit(1)
    
    if backup_hives(str(backup_dir)):
        logger.debug("Backup completed successfully")
    else:
        logger.debug("Backup completed with errors")

if __name__ == "__main__":
    main()