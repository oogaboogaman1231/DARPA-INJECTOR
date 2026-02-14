// Windows headers first
#include <windows.h>

// Standard library headers
#include <cstring>
#include <iostream>


// Custom headers
#include "ApcInjector.h"
#include "CrashHandler.h"
#include "Logger.h"
#include "ManualMapper.h"
#include "ModuleStomper.h"
#include "PrivilegeEscalator.h"
#include "Syscalls.h"
#include "ThreadHijacker.h"
#include "XorStr.h"

// DLL Entry Point - Initialize Crash Handler
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    // Initialize crash handler on DLL load
    CrashHandler::Initialize();
    Logger::Log("DarpaInjector.Core.dll loaded successfully");
    break;
  case DLL_PROCESS_DETACH:
    // Cleanup crash handler on DLL unload
    CrashHandler::Shutdown();
    Logger::Log("DarpaInjector.Core.dll unloaded");
    break;
  }
  return TRUE;
}

extern "C" __declspec(dllexport) bool EnablePrivileges() {
  return CrashHandler::SafeExecute("EnablePrivileges", []() {
    Logger::Log("Attempting to enable debug privileges...");
    bool res = PrivilegeEscalator::EnableDebugPrivilege();
    if (res)
      Logger::Log("Debug privileges enabled.");
    else
      Logger::Log("Failed to enable debug privileges! Check user context.");
    return res;
  });
}

// Exported function to retrieve logs from UI
extern "C" __declspec(dllexport) int GetDebugLog(char *buffer, int size) {
  return Logger::GetLog(buffer, size);
}

extern "C" __declspec(dllexport) bool InjectRemote(int pid, const char *dllPath,
                                                   int method) {
  // Wrap entire injection in crash handler
  return CrashHandler::SafeExecute("InjectRemote", [&]() {
    Logger::Clear();
    Logger::Log("Injection initiated. PID: %d, DLL: %s, Method: %d", pid,
                dllPath, method);

    if (!EnablePrivileges()) {
      Logger::Log("Continuing injection attempt despite privilege failure...");
    }

    // Method Map:
    // 0: LoadLibrary (Standard)
    // 1: Manual Map (Reflective) [Stealth: Header Erasing]
    // 2: Thread Hijack [Stealth: No CreateRemoteThread]
    // 3: Module Stomping [Stealth: Overwrites benign DLL]
    // 4: APC Injection [Stealth: QueueUserAPC]

    switch (method) {
    case 0: { // Standard LoadLibrary (Hardened with Dynamic Resolution)
      Logger::Log("Method 0: LoadLibrary (Standard/Hardened)");

      return CrashHandler::SafeExecute("LoadLibrary Injection", [&]() {
        using f_OpenProcess = HANDLE(WINAPI *)(DWORD, BOOL, DWORD);
        using f_VirtualAllocEx =
            LPVOID(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
        using f_WriteProcessMemory =
            BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
        using f_CreateRemoteThread =
            HANDLE(WINAPI *)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                             LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
        using f_WaitForSingleObject = DWORD(WINAPI *)(HANDLE, DWORD);
        using f_CloseHandle = BOOL(WINAPI *)(HANDLE);
        using f_GetLastError = DWORD(WINAPI *)(VOID);

        auto pOpenProcess =
            (f_OpenProcess)Syscalls::GetAPI(XSTRING("OpenProcess"));
        auto pVirtualAllocEx =
            (f_VirtualAllocEx)Syscalls::GetAPI(XSTRING("VirtualAllocEx"));
        auto pWriteProcessMemory = (f_WriteProcessMemory)Syscalls::GetAPI(
            XSTRING("WriteProcessMemory"));
        auto pCreateRemoteThread = (f_CreateRemoteThread)Syscalls::GetAPI(
            XSTRING("CreateRemoteThread"));
        auto pWaitForSingleObject = (f_WaitForSingleObject)Syscalls::GetAPI(
            XSTRING("WaitForSingleObject"));
        auto pCloseHandle =
            (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));
        auto pGetLastError =
            (f_GetLastError)Syscalls::GetAPI(XSTRING("GetLastError"));

        if (!pOpenProcess || !pCreateRemoteThread) {
          Logger::Log("FATAL: Failed to resolve critical APIs.");
          return false;
        }

        Logger::Log("Opening target process...");
        HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
          Logger::Log("Failed to open process. Error: %d",
                      pGetLastError ? pGetLastError() : 0);
          return false;
        }

        Logger::Log("Allocating memory for DLL path...");
        void *pPath = pVirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                      MEM_COMMIT, PAGE_READWRITE);
        if (!pPath) {
          Logger::Log("Failed to allocate memory remotely. Error: %d",
                      pGetLastError ? pGetLastError() : 0);
          pCloseHandle(hProcess);
          return false;
        }

        Logger::Log("Writing DLL path...");
        if (!pWriteProcessMemory(hProcess, pPath, dllPath, strlen(dllPath) + 1,
                                 NULL)) {
          Logger::Log("Failed to write memory. Error: %d",
                      pGetLastError ? pGetLastError() : 0);
        }

        HMODULE hKernel32 = Syscalls::GetModuleHandle_Custom(L"kernel32.dll");
        FARPROC pLoadLibraryA =
            Syscalls::GetProcAddress_Custom(hKernel32, XSTRING("LoadLibraryA"));
        Logger::Log("LoadLibraryA Address: %p", pLoadLibraryA);

        Logger::Log("Creating remote thread...");
        HANDLE hThread = pCreateRemoteThread(
            hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pPath, 0,
            NULL);

        if (hThread) {
          Logger::Log("Thread created successfully. Waiting...");
          pWaitForSingleObject(hThread, INFINITE);
          pCloseHandle(hThread);
          pCloseHandle(hProcess);
          Logger::Log("Injection completed (LL).");
          return true;
        } else {
          Logger::Log("Failed to create remote thread. Error: %d",
                      pGetLastError ? pGetLastError() : 0);
        }
        pCloseHandle(hProcess);
        return false;
      });
    }
    case 1:
      Logger::Log("Method 1: Manual Map (Reflective)");
      return CrashHandler::SafeExecute(
          "Manual Map", [&]() { return ManualMapper::Inject(pid, dllPath); });
    case 2:
      Logger::Log("Method 2: Thread Hijack");
      return CrashHandler::SafeExecute("Thread Hijack", [&]() {
        return ThreadHijacker::Inject(pid, dllPath);
      });
    case 3:
      Logger::Log("Method 3: Module Stomping");
      return CrashHandler::SafeExecute("Module Stomping", [&]() {
        return ModuleStomper::Inject(pid, dllPath);
      });
    case 4:
      Logger::Log("Method 4: APC Injection");
      return CrashHandler::SafeExecute(
          "APC Injection", [&]() { return ApcInjector::Inject(pid, dllPath); });
    default:
      Logger::Log("Unknown method ID: %d", method);
      return false;
    }
  });
}
