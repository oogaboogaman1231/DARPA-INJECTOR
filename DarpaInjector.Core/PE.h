#pragma once
#include <cstring>
#include <iostream>
#include <vector>
#include <windows.h>


#include "Logger.h"
#include "Nt.h"
#include "Syscalls.h"
#include "XorStr.h"

class PE {
public:
  // Apply Base Relocations
  static bool ApplyRelocations(void *pLocalImage, ULONG_PTR newBase,
                               void *pOriginalBuffer) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pOriginalBuffer;
    PIMAGE_NT_HEADERS pNtHeaders =
        (PIMAGE_NT_HEADERS)((LPBYTE)pOriginalBuffer + pDos->e_lfanew);

    ULONG_PTR imageBase = pNtHeaders->OptionalHeader.ImageBase;
    ULONG_PTR delta = newBase - imageBase;

    if (delta == 0)
      return true;

    if (pNtHeaders->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .Size == 0) {
      return true;
    }

    PIMAGE_BASE_RELOCATION pReloc =
        (PIMAGE_BASE_RELOCATION)((LPBYTE)pLocalImage +
                                 pNtHeaders->OptionalHeader
                                     .DataDirectory
                                         [IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     .VirtualAddress);

    while (pReloc->VirtualAddress != 0) {
      DWORD count =
          (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
      WORD *list = (WORD *)(pReloc + 1);

      for (DWORD i = 0; i < count; i++) {
        if (list[i] > 0) {
          DWORD type = list[i] >> 12;
          DWORD offset = list[i] & 0xFFF;

          switch (type) {
          case IMAGE_REL_BASED_HIGHLOW:
            *(DWORD *)((LPBYTE)pLocalImage + pReloc->VirtualAddress + offset) +=
                (DWORD)delta;
            break;
          case IMAGE_REL_BASED_DIR64:
            *(ULONG_PTR *)((LPBYTE)pLocalImage + pReloc->VirtualAddress +
                           offset) += delta;
            break;
          }
        }
      }
      pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
    }
    Logger::Log("Relocations applied. Delta: %p", (void *)delta);
    return true;
  }

  // Resolve Imports
  static bool ResolveImports(void *pLocalImage, void *pOriginalBuffer,
                             HANDLE hProcess) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pOriginalBuffer;
    PIMAGE_NT_HEADERS pNtHeaders =
        (PIMAGE_NT_HEADERS)((LPBYTE)pOriginalBuffer + pDos->e_lfanew);

    if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .Size == 0)
      return true;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
        (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pLocalImage +
                                   pNtHeaders->OptionalHeader
                                       .DataDirectory
                                           [IMAGE_DIRECTORY_ENTRY_IMPORT]
                                       .VirtualAddress);

    using f_LoadLibraryA = HMODULE(WINAPI *)(LPCSTR);
    using f_CreateRemoteThread =
        HANDLE(WINAPI *)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                         LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using f_WaitForSingleObject = DWORD(WINAPI *)(HANDLE, DWORD);
    using f_GetExitCodeThread = BOOL(WINAPI *)(HANDLE, LPDWORD);
    using f_CloseHandle = BOOL(WINAPI *)(HANDLE);
    using f_VirtualAllocEx =
        LPVOID(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using f_WriteProcessMemory =
        BOOL(WINAPI *)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
    using f_VirtualFreeEx = BOOL(WINAPI *)(HANDLE, LPVOID, SIZE_T, DWORD);

    auto pCreateRemoteThread =
        (f_CreateRemoteThread)Syscalls::GetAPI(XSTRING("CreateRemoteThread"));
    auto pWaitForSingleObject =
        (f_WaitForSingleObject)Syscalls::GetAPI(XSTRING("WaitForSingleObject"));
    auto pGetExitCodeThread =
        (f_GetExitCodeThread)Syscalls::GetAPI(XSTRING("GetExitCodeThread"));
    auto pCloseHandle = (f_CloseHandle)Syscalls::GetAPI(XSTRING("CloseHandle"));
    auto pVirtualAllocEx =
        (f_VirtualAllocEx)Syscalls::GetAPI(XSTRING("VirtualAllocEx"));
    auto pWriteProcessMemory =
        (f_WriteProcessMemory)Syscalls::GetAPI(XSTRING("WriteProcessMemory"));
    auto pVirtualFreeEx =
        (f_VirtualFreeEx)Syscalls::GetAPI(XSTRING("VirtualFreeEx"));

    HMODULE hKernel32 = Syscalls::GetModuleHandle_Custom(L"kernel32.dll");
    auto pLoadLibraryA = (f_LoadLibraryA)Syscalls::GetProcAddress_Custom(
        hKernel32, XSTRING("LoadLibraryA"));

    while (pImportDesc->Name != 0) {
      char *szModName = (char *)((LPBYTE)pLocalImage + pImportDesc->Name);

      // Force load dependency in remote process
      void *pRemoteModName = pVirtualAllocEx(
          hProcess, NULL, strlen(szModName) + 1, MEM_COMMIT, PAGE_READWRITE);
      pWriteProcessMemory(hProcess, pRemoteModName, szModName,
                          strlen(szModName) + 1, NULL);

      HANDLE hThread = pCreateRemoteThread(
          hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA,
          pRemoteModName, 0, NULL);
      pWaitForSingleObject(hThread, INFINITE);
      DWORD dwExit = 0;
      pGetExitCodeThread(hThread, &dwExit);
      pCloseHandle(hThread);
      pVirtualFreeEx(hProcess, pRemoteModName, 0, MEM_RELEASE);

      ULONG_PTR hRemoteMod = (ULONG_PTR)dwExit;
      if (!hRemoteMod) {
        Logger::Log("Failed to load dependency: %s", szModName);
        return false;
      }

      // Load locally to calculate offsets
      HMODULE hLocalMod = LoadLibraryA(szModName);
      if (!hLocalMod) {
        Logger::Log("Failed to load dependency locally: %s", szModName);
        return false;
      }

      PIMAGE_THUNK_DATA pThunk =
          (PIMAGE_THUNK_DATA)((LPBYTE)pLocalImage + pImportDesc->FirstThunk);
      PIMAGE_THUNK_DATA pOriginalThunk =
          (PIMAGE_THUNK_DATA)((LPBYTE)pLocalImage +
                              pImportDesc->OriginalFirstThunk);

      if (pImportDesc->OriginalFirstThunk == 0)
        pOriginalThunk = pThunk;

      while (pOriginalThunk->u1.AddressOfData != 0) {
        if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
          WORD ordinal = IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
          ULONG_PTR localFunc =
              (ULONG_PTR)GetProcAddress(hLocalMod, (LPCSTR)ordinal);
          if (localFunc) {
            ULONG_PTR offset = localFunc - (ULONG_PTR)hLocalMod;
            pThunk->u1.Function = hRemoteMod + offset;
          }
        } else {
          PIMAGE_IMPORT_BY_NAME pIBN =
              (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pLocalImage +
                                      pOriginalThunk->u1.AddressOfData);
          char *szFuncName = (char *)pIBN->Name;

          ULONG_PTR localFunc =
              (ULONG_PTR)GetProcAddress(hLocalMod, szFuncName);
          if (localFunc) {
            ULONG_PTR offset = localFunc - (ULONG_PTR)hLocalMod;
            pThunk->u1.Function = hRemoteMod + offset;
          }
        }
        pThunk++;
        pOriginalThunk++;
      }
      pImportDesc++;
    }
    return true;
  }
};
