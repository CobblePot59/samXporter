#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>    // PathCombineW, PathRemoveFileSpecW
#include <shlobj.h>     // IsUserAnAdmin

#define BACKUP_FOLDER_NAME L"Registry_Backup"

BOOL EnableSeBackupPrivilege(void);
BOOL SaveHive(const wchar_t* hive, const wchar_t* destfile);
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

    if (!EnableSeBackupPrivilege()) {
        fwprintf(stderr, L"[!] Failed to enable SeBackupPrivilege\n");
        return 1;
    }

    fwprintf(stderr, L"[+] SeBackupPrivilege enabled\n");

    BOOL success = TRUE;
    success &= SaveHive(L"HKLM\\SAM",     samPath);
    success &= SaveHive(L"HKLM\\SYSTEM",  sysPath);
    success &= SaveHive(L"HKLM\\SECURITY", secPath);

    if (success) {
        wprintf(L"\n[+] Backup completed successfully\n");
    } else {
        fwprintf(stderr, L"\n[-] Backup finished with errors\n");
    }

    return success ? 0 : 1;
}

BOOL EnableSeBackupPrivilege(void)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        PrintError(L"OpenProcessToken");
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &luid)) {
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

BOOL SaveHive(const wchar_t* hive, const wchar_t* destfile)
{
    wchar_t cmd[1024];
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    swprintf_s(cmd, _countof(cmd), L"reg.exe save \"%s\" \"%s\" /y", hive, destfile);

    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                        NULL, NULL, &si, &pi))
    {
        PrintError(L"CreateProcessW (reg save)");
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode;
    BOOL success = FALSE;

    if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == 0) {
        success = TRUE;

        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExW(destfile, GetFileExInfoStandard, &fad)) {
            ULARGE_INTEGER size = { .LowPart = fad.nFileSizeLow, .HighPart = fad.nFileSizeHigh };
            wprintf(L"[+] %-8s → %ls  (%llu bytes)\n", hive + 5, destfile, size.QuadPart);
        } else {
            wprintf(L"[+] %-8s → %ls\n", hive + 5, destfile);
        }
    } else {
        fwprintf(stderr, L"[-] Failed to save %ls  (exit code %lu)\n", hive, exitCode);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return success;
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