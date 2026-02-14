#pragma once
#include <windows.h>
#include <winternl.h>

// Ensure NTSTATUS is defined if winternl.h doesn't or if there are conflicts.
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

// Some structures might be missing or incomplete in winternl.h depending on SDK
// version. We define FULL versions of PEB_LDR_DATA and LDR_DATA_TABLE_ENTRY for
// manual mapping.

typedef struct _PEB_LDR_DATA_FULL {
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  void *EntryInProgress;
  BOOLEAN ShutdownInProgress;
  HANDLE ShutdownThreadId;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  void *DllBase;
  void *EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  WORD LoadCount;
  WORD TlsIndex;
  union {
    LIST_ENTRY HashLinks;
    struct {
      void *SectionPointer;
      ULONG CheckSum;
    };
  };
  union {
    ULONG TimeDateStamp;
    void *LoadedImports;
  };
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

// Function pointer typedefs for dynamic resolution

typedef NTSTATUS(NTAPI *pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void *ObjectAttributes,
    HANDLE ProcessHandle, void *StartRoutine, void *Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    void *AttributeList);

typedef NTSTATUS(NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI *pNtWriteVirtualMemory)(HANDLE ProcessHandle,
                                               PVOID BaseAddress, PVOID Buffer,
                                               SIZE_T NumberOfBytesToWrite,
                                               PSIZE_T NumberOfBytesWritten);

typedef NTSTATUS(NTAPI *pNtProtectVirtualMemory)(HANDLE ProcessHandle,
                                                 PVOID *BaseAddress,
                                                 PSIZE_T RegionSize,
                                                 ULONG NewProtect,
                                                 PULONG OldProtect);

typedef NTSTATUS(NTAPI *pNtQueueApcThread)(HANDLE ThreadHandle,
                                           PIO_APC_ROUTINE ApcRoutine,
                                           PVOID ApcArgument1,
                                           PVOID ApcArgument2,
                                           PVOID ApcArgument3);

typedef NTSTATUS(NTAPI *pNtOpenProcess)(PHANDLE ProcessHandle,
                                        ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes,
                                        PCLIENT_ID ClientId);

// Advanced internal structures for Manual Mapping
using f_LoadLibraryA = HINSTANCE(WINAPI *)(const char *lpLibFileName);
using f_GetProcAddress = UINT_PTR(WINAPI *)(HINSTANCE hModule,
                                            const char *lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI *)(void *hDll, DWORD dwReason,
                                         void *pReserved);

struct MANUAL_MAPPING_DATA {
  f_LoadLibraryA pLoadLibraryA;
  f_GetProcAddress pGetProcAddress;
  HINSTANCE hMod; // Base address of the injected module
};
