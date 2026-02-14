#pragma once

// Windows headers first
#include <windows.h>

// Standard library headers
#include <cstring>
#include <iostream>
#include <string>


// Custom headers
#include "Logger.h"
#include "Nt.h"
#include "PE.h"
#include "Syscalls.h"
#include "XorStr.h"

// Manual Mapping with Logging, Relocations, and Imports.

class ManualMapper {
public:
  static bool Inject(int pid, const char *dllPath) {
    // Resolve APIs dynamically
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

    auto pOpenProcess = (f_OpenProcess)Syscalls::GetAPI(XSTRING("OpenProcess"));
    auto pVirtualAllocEx =
        (f_VirtualAllocEx)Syscalls::GetAPI(XSTRING("VirtualAllocEx"));
    auto pWriteProcessMemory =
        (f_WriteProcessMemory)Syscalls::GetAPI(XSTRING("WriteProcessMemory"));
    auto pCreateRemoteThread =
        (f_CreateRemoteThread)Syscalls::GetAPI(XSTRING("CreateRemoteThread"));
    auto pWaitForSingleObject =
        (f_WaitForSingleObject)Syscalls::GetAPI(XSTRING("WaitForSingleObject"));
    auto pCloseHandle = (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));

    if (!pOpenProcess || !pVirtualAllocEx || !pWriteProcessMemory ||
        !pCreateRemoteThread) {
      Logger::Log("Failed to resolve ManualMap APIs.");
      return false;
    }

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
      Logger::Log("Failed to open process. PID: %d", pid);
      return false;
    }

    Logger::Log("Reading DLL from disk...");
    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
      Logger::Log("Failed to open DLL file: %s", dllPath);
      pCloseHandle(hProcess);
      return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) {
      Logger::Log("Invalid file size.");
      CloseHandle(hFile);
      pCloseHandle(hProcess);
      return false;
    }

    BYTE *pDllBuffer = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, pDllBuffer, fileSize, &bytesRead, NULL)) {
      Logger::Log("Failed to read DLL file.");
      delete[] pDllBuffer;
      CloseHandle(hFile);
      pCloseHandle(hProcess);
      return false;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
      Logger::Log("Invalid DLL format (MZ signature missing).");
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders =
        (PIMAGE_NT_HEADERS)(pDllBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
      Logger::Log("Invalid PE signature.");
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    Logger::Log("Allocating remote memory (Size: %d)...",
                pNtHeaders->OptionalHeader.SizeOfImage);
    void *pRemoteImage =
        pVirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteImage) {
      Logger::Log("Failed to allocate remote memory.");
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    Logger::Log("Remote memory allocated at: %p", pRemoteImage);

    // Allocate local buffer for fixups
    void *pLocalImage =
        VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalImage) {
      Logger::Log("Failed to allocate local memory.");
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    // Copy headers
    memcpy(pLocalImage, pDllBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
      void *pDest = (BYTE *)pLocalImage + pSectionHeader[i].VirtualAddress;
      void *pSrc = pDllBuffer + pSectionHeader[i].PointerToRawData;
      DWORD size = pSectionHeader[i].SizeOfRawData;
      if (size > 0) {
        memcpy(pDest, pSrc, size);
      }
    }

    // Apply relocations
    Logger::Log("Applying relocations...");
    if (!PE::ApplyRelocations(pLocalImage, (ULONG_PTR)pRemoteImage,
                              pDllBuffer)) {
      Logger::Log("Failed to apply relocations.");
    }

    // Resolve imports
    Logger::Log("Resolving imports...");
    if (!PE::ResolveImports(pLocalImage, pDllBuffer, hProcess)) {
      Logger::Log("Failed to resolve imports.");
      VirtualFree(pLocalImage, 0, MEM_RELEASE);
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    // Write to remote process
    Logger::Log("Writing to remote process...");
    if (!pWriteProcessMemory(hProcess, pRemoteImage, pLocalImage,
                             pNtHeaders->OptionalHeader.SizeOfImage, NULL)) {
      Logger::Log("Failed to write to remote process.");
      VirtualFree(pLocalImage, 0, MEM_RELEASE);
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    // Erase PE header for stealth
    Logger::Log("Erasing PE header...");
    BYTE zeroHeader[0x1000];
    memset(zeroHeader, 0, sizeof(zeroHeader));
    pWriteProcessMemory(hProcess, pRemoteImage, zeroHeader, sizeof(zeroHeader),
                        NULL);

    // Execute DllMain
    void *pEntryPoint =
        (BYTE *)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    Logger::Log("Creating remote thread at entry point: %p", pEntryPoint);

    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pEntryPoint,
                                         pRemoteImage, 0, NULL);

    // Cleanup
    VirtualFree(pLocalImage, 0, MEM_RELEASE);
    delete[] pDllBuffer;

    if (hThread) {
      Logger::Log("Remote thread created successfully.");
      if (pWaitForSingleObject) {
        pWaitForSingleObject(hThread, INFINITE);
      }
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      Logger::Log("Manual Map injection completed.");
      return true;
    }

    Logger::Log("Failed to create remote thread.");
    pCloseHandle(hProcess);
    return false;
  }
};
