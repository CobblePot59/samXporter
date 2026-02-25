#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <shlobj.h>

#define BACKUP_FOLDER_NAME L"Registry_Backup"

BOOL EnablePrivilege(const wchar_t* privName);
BOOL SaveHive(HKEY rootKey, const wchar_t* subKey, const wchar_t* destfile);
void PrintError(const wchar_t* msg);

int wmain(void)
{
    wchar_t exePath[MAX_PATH];
    wchar_t backupDir[MAX_PATH];
    wchar_t samPath[MAX_PATH];
    wchar_t sysPath[MAX_PATH];
    wchar_t secPath[MAX_PATH];

    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        PrintError(L"GetModuleFileNameW");
        return 1;
    }

    if (!PathRemoveFileSpecW(exePath)) {
        fwprintf(stderr, L"PathRemoveFileSpecW failed\n");
        return 1;
    }

    if (!PathCombineW(backupDir, exePath, BACKUP_FOLDER_NAME)) {
        fwprintf(stderr, L"PathCombineW failed (backupDir)\n");
        return 1;
    }

    if (!CreateDirectoryW(backupDir, NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            PrintError(L"CreateDirectoryW");
            return 1;
        }
    }

    PathCombineW(samPath, backupDir, L"SAM");
    PathCombineW(sysPath, backupDir, L"SYSTEM");
    PathCombineW(secPath, backupDir, L"SECURITY");

    fwprintf(stderr, L"[*] Backup directory: %ls\n", backupDir);

    if (!IsUserAnAdmin()) {
        fwprintf(stderr, L"[!] This program must be run as administrator.\n");
        return 1;
    }

    fwprintf(stderr, L"[+] Administrator rights detected\n");

    if (!EnablePrivilege(L"SeBackupPrivilege")) {
        fwprintf(stderr, L"[!] Failed to enable SeBackupPrivilege\n");
        return 1;
    }
    fwprintf(stderr, L"[+] SeBackupPrivilege enabled\n");

    if (!EnablePrivilege(L"SeSecurityPrivilege")) {
        fwprintf(stderr, L"[!] Failed to enable SeSecurityPrivilege\n");
        return 1;
    }
    fwprintf(stderr, L"[+] SeSecurityPrivilege enabled\n");

    BOOL success = TRUE;
    success &= SaveHive(HKEY_LOCAL_MACHINE, L"SAM",      samPath);
    success &= SaveHive(HKEY_LOCAL_MACHINE, L"SYSTEM",   sysPath);
    success &= SaveHive(HKEY_LOCAL_MACHINE, L"SECURITY", secPath);

    if (success) {
        wprintf(L"\n[+] Backup completed successfully\n");
    } else {
        fwprintf(stderr, L"\n[-] Backup finished with errors\n");
    }

    return success ? 0 : 1;
}

BOOL EnablePrivilege(const wchar_t* privName)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PrintError(L"OpenProcessToken");
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
        PrintError(L"LookupPrivilegeValueW");
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        PrintError(L"AdjustTokenPrivileges");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
}

BOOL SaveHive(HKEY rootKey, const wchar_t* subKey, const wchar_t* destfile)
{
    if (GetFileAttributesW(destfile) != INVALID_FILE_ATTRIBUTES)
        DeleteFileW(destfile);

    HKEY hKey = NULL;
    LSTATUS ret = RegOpenKeyExW(rootKey, subKey, 0, MAXIMUM_ALLOWED, &hKey);
    if (ret != ERROR_SUCCESS) {
        fwprintf(stderr, L"[-] RegOpenKeyExW(%ls) failed (error %ld)\n", subKey, ret);
        return FALSE;
    }

    ret = RegSaveKeyExW(hKey, destfile, NULL, REG_NO_COMPRESSION);
    RegCloseKey(hKey);

    if (ret != ERROR_SUCCESS) {
        fwprintf(stderr, L"[-] RegSaveKeyExW(%ls) failed (error %ld)\n", subKey, ret);
        return FALSE;
    }

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(destfile, GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER size = { .LowPart = fad.nFileSizeLow, .HighPart = fad.nFileSizeHigh };
        wprintf(L"[+] %-8ls → %ls  (%llu bytes)\n", subKey, destfile, size.QuadPart);
    } else {
        wprintf(L"[+] %-8ls → %ls\n", subKey, destfile);
    }

    return TRUE;
}

void PrintError(const wchar_t* msg)
{
    wchar_t* errBuf = NULL;
    DWORD err = GetLastError();

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&errBuf, 0, NULL);

    if (errBuf) {
        fwprintf(stderr, L"[!] %ls : %ls (error %lu)\n", msg, errBuf, err);
        LocalFree(errBuf);
    } else {
        fwprintf(stderr, L"[!] %ls : error %lu\n", msg, err);
    }
}