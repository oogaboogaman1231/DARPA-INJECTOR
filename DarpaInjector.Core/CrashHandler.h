#pragma once
#include <ctime>
#include <dbghelp.h>
#include <string>
#include <utility>
#include <windows.h>


#include "Logger.h"

#pragma comment(lib, "dbghelp.lib")

// Comprehensive Crash Handler to prevent system-wide crashes
// Uses SEH (Structured Exception Handling) and VEH (Vectored Exception
// Handling)

class CrashHandler {
private:
  static PVOID s_VectoredHandler;
  static bool s_Initialized;

  // Vectored Exception Handler - catches exceptions before SEH
  static LONG WINAPI
  VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    DWORD exceptionCode = pExceptionInfo->ExceptionRecord->ExceptionCode;
    void *exceptionAddress = pExceptionInfo->ExceptionRecord->ExceptionAddress;

    // Log the exception
    Logger::Log("[CRASH HANDLER] Exception caught: 0x%08X at address %p",
                exceptionCode, exceptionAddress);

    // Decode exception type
    const char *exceptionName = GetExceptionName(exceptionCode);
    Logger::Log("[CRASH HANDLER] Exception type: %s", exceptionName);

    // Log register state (x64)
#ifdef _WIN64
    Logger::Log("[CRASH HANDLER] RAX=%p RBX=%p RCX=%p RDX=%p",
                (void *)pExceptionInfo->ContextRecord->Rax,
                (void *)pExceptionInfo->ContextRecord->Rbx,
                (void *)pExceptionInfo->ContextRecord->Rcx,
                (void *)pExceptionInfo->ContextRecord->Rdx);
    Logger::Log("[CRASH HANDLER] RSI=%p RDI=%p RBP=%p RSP=%p",
                (void *)pExceptionInfo->ContextRecord->Rsi,
                (void *)pExceptionInfo->ContextRecord->Rdi,
                (void *)pExceptionInfo->ContextRecord->Rbp,
                (void *)pExceptionInfo->ContextRecord->Rsp);
    Logger::Log("[CRASH HANDLER] RIP=%p",
                (void *)pExceptionInfo->ContextRecord->Rip);
#else
    Logger::Log("[CRASH HANDLER] EAX=%p EBX=%p ECX=%p EDX=%p",
                (void *)pExceptionInfo->ContextRecord->Eax,
                (void *)pExceptionInfo->ContextRecord->Ebx,
                (void *)pExceptionInfo->ContextRecord->Ecx,
                (void *)pExceptionInfo->ContextRecord->Edx);
    Logger::Log("[CRASH HANDLER] EIP=%p ESP=%p EBP=%p",
                (void *)pExceptionInfo->ContextRecord->Eip,
                (void *)pExceptionInfo->ContextRecord->Esp,
                (void *)pExceptionInfo->ContextRecord->Ebp);
#endif

    // Create minidump for debugging
    CreateMiniDump(pExceptionInfo);

    // Continue search - let SEH handlers try to handle it
    return EXCEPTION_CONTINUE_SEARCH;
  }

  static const char *GetExceptionName(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
      return "Access Violation";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
      return "Array Bounds Exceeded";
    case EXCEPTION_BREAKPOINT:
      return "Breakpoint";
    case EXCEPTION_DATATYPE_MISALIGNMENT:
      return "Datatype Misalignment";
    case EXCEPTION_FLT_DENORMAL_OPERAND:
      return "Float Denormal Operand";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
      return "Float Divide by Zero";
    case EXCEPTION_FLT_INEXACT_RESULT:
      return "Float Inexact Result";
    case EXCEPTION_FLT_INVALID_OPERATION:
      return "Float Invalid Operation";
    case EXCEPTION_FLT_OVERFLOW:
      return "Float Overflow";
    case EXCEPTION_FLT_STACK_CHECK:
      return "Float Stack Check";
    case EXCEPTION_FLT_UNDERFLOW:
      return "Float Underflow";
    case EXCEPTION_ILLEGAL_INSTRUCTION:
      return "Illegal Instruction";
    case EXCEPTION_IN_PAGE_ERROR:
      return "In Page Error";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
      return "Integer Divide by Zero";
    case EXCEPTION_INT_OVERFLOW:
      return "Integer Overflow";
    case EXCEPTION_INVALID_DISPOSITION:
      return "Invalid Disposition";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
      return "Noncontinuable Exception";
    case EXCEPTION_PRIV_INSTRUCTION:
      return "Privileged Instruction";
    case EXCEPTION_SINGLE_STEP:
      return "Single Step";
    case EXCEPTION_STACK_OVERFLOW:
      return "Stack Overflow";
    default:
      return "Unknown Exception";
    }
  }

  static void CreateMiniDump(PEXCEPTION_POINTERS pExceptionInfo) {
    __try {
      // Create crash dump directory
      CreateDirectoryA("CrashDumps", NULL);

      // Generate filename with timestamp
      char filename[MAX_PATH];
      time_t now = time(NULL);
      struct tm timeinfo;
      localtime_s(&timeinfo, &now);
      sprintf_s(filename, "CrashDumps\\crash_%04d%02d%02d_%02d%02d%02d.dmp",
                timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);

      HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

      if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mdei;
        mdei.ThreadId = GetCurrentThreadId();
        mdei.ExceptionPointers = pExceptionInfo;
        mdei.ClientPointers = FALSE;

        MINIDUMP_TYPE dumpType =
            (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData |
                            MiniDumpWithThreadInfo |
                            MiniDumpWithUnloadedModules);

        BOOL success = MiniDumpWriteDump(
            GetCurrentProcess(), GetCurrentProcessId(), hFile, dumpType,
            pExceptionInfo ? &mdei : NULL, NULL, NULL);

        CloseHandle(hFile);

        if (success) {
          Logger::Log("[CRASH HANDLER] Minidump created: %s", filename);
        } else {
          Logger::Log("[CRASH HANDLER] Failed to create minidump. Error: %d",
                      GetLastError());
        }
      }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      // Silently fail if minidump creation crashes
    }
  }

public:
  static void Initialize() {
    if (s_Initialized)
      return;

    Logger::Log("[CRASH HANDLER] Initializing crash handler...");

    // Install Vectored Exception Handler (VEH)
    // VEH is called before SEH, giving us first chance at exceptions
    s_VectoredHandler =
        AddVectoredExceptionHandler(1, VectoredExceptionHandler);

    if (s_VectoredHandler) {
      Logger::Log(
          "[CRASH HANDLER] Vectored Exception Handler installed successfully");
    } else {
      Logger::Log("[CRASH HANDLER] Failed to install VEH. Error: %d",
                  GetLastError());
    }

    // Set unhandled exception filter as last resort
    SetUnhandledExceptionFilter([](PEXCEPTION_POINTERS pExceptionInfo) -> LONG {
      Logger::Log("[CRASH HANDLER] Unhandled exception filter triggered!");
      VectoredExceptionHandler(pExceptionInfo);
      return EXCEPTION_EXECUTE_HANDLER; // Terminate gracefully
    });

    s_Initialized = true;
    Logger::Log("[CRASH HANDLER] Crash handler initialized successfully");
  }

  static void Shutdown() {
    if (!s_Initialized)
      return;

    if (s_VectoredHandler) {
      RemoveVectoredExceptionHandler(s_VectoredHandler);
      s_VectoredHandler = NULL;
      Logger::Log("[CRASH HANDLER] Vectored Exception Handler removed");
    }

    s_Initialized = false;
  }

  // Safe execution wrapper for injection methods
  template <typename Func, typename... Args>
  static bool SafeExecute(const char *operationName, Func &&func,
                          Args &&...args) {
    Logger::Log("[CRASH HANDLER] SafeExecute: %s", operationName);

    __try {
      return func(std::forward<Args>(args)...);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      DWORD exceptionCode = GetExceptionCode();
      Logger::Log("[CRASH HANDLER] Exception in %s: 0x%08X (%s)", operationName,
                  exceptionCode, GetExceptionName(exceptionCode));
      return false;
    }
  }
};

// Static member initialization
PVOID CrashHandler::s_VectoredHandler = NULL;
bool CrashHandler::s_Initialized = false;
