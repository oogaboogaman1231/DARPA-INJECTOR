#pragma once

// Windows headers first
#include <windows.h>

// Standard library headers
#include <iostream>

// Custom headers
#include "Logger.h"
#include "Syscalls.h"
#include "XorStr.h"

class PrivilegeEscalator {
public:
  static bool EnableDebugPrivilege() {
    // Dynamic API Resolution
    using f_OpenProcessToken = BOOL(WINAPI *)(HANDLE, DWORD, PHANDLE);
    using f_LookupPrivilegeValueA = BOOL(WINAPI *)(LPCSTR, LPCSTR, PLUID);
    using f_AdjustTokenPrivileges = BOOL(WINAPI *)(
        HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    using f_CloseHandle = BOOL(WINAPI *)(HANDLE);
    using f_GetLastError = DWORD(WINAPI *)(VOID);

    auto pOpenProcessToken =
        (f_OpenProcessToken)Syscalls::GetAPI(XSTRING("OpenProcessToken"));
    auto pLookupPrivilegeValueA = (f_LookupPrivilegeValueA)Syscalls::GetAPI(
        XSTRING("LookupPrivilegeValueA"));
    auto pAdjustTokenPrivileges = (f_AdjustTokenPrivileges)Syscalls::GetAPI(
        XSTRING("AdjustTokenPrivileges"));
    auto pCloseHandle = (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));
    auto pGetLastError =
        (f_GetLastError)Syscalls::GetAPI(XSTRING("GetLastError"));

    if (!pOpenProcessToken || !pLookupPrivilegeValueA ||
        !pAdjustTokenPrivileges) {
      Logger::Log("Failed to resolve privilege escalation APIs.");
      return false;
    }

    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!pOpenProcessToken(GetCurrentProcess(),
                           TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
      Logger::Log("Failed to open process token.");
      return false;
    }

    if (!pLookupPrivilegeValueA(NULL, XSTRING("SeDebugPrivilege"), &luid)) {
      Logger::Log("Failed to lookup SeDebugPrivilege.");
      pCloseHandle(hToken);
      return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!pAdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
      Logger::Log("Failed to adjust token privileges.");
      pCloseHandle(hToken);
      return false;
    }

    if (pGetLastError && pGetLastError() == ERROR_NOT_ALL_ASSIGNED) {
      Logger::Log(
          "Not all privileges were assigned. Insufficient permissions.");
      pCloseHandle(hToken);
      return false;
    }

    pCloseHandle(hToken);
    Logger::Log("SeDebugPrivilege enabled successfully.");
    return true;
  }
};
