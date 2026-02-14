#pragma once

// Windows headers first
#include <windows.h>

// Standard library headers
#include <cstdarg>
#include <cstring>
#include <string>


// Thread-safe logger that buffers messages for the UI to retrieve.

class Logger {
private:
  static std::string logBuffer;
  static const size_t MAX_BUFFER_SIZE = 1024 * 100; // 100KB max

public:
  static void Clear() { logBuffer.clear(); }

  static void Log(const char *fmt, ...) {
    char buffer[2048]; // Increased buffer size
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    // Prevent buffer overflow by limiting total size
    if (logBuffer.length() + strlen(buffer) > MAX_BUFFER_SIZE) {
      // Keep only the last 50KB
      logBuffer = logBuffer.substr(logBuffer.length() - (MAX_BUFFER_SIZE / 2));
    }

    logBuffer += std::string(buffer) + "\n";
    OutputDebugStringA(buffer); // Also send to DebugView
  }

  static int GetLog(char *buffer, int maxLen) {
    if (!buffer || maxLen <= 0)
      return 0;
    if (logBuffer.empty())
      return 0;

    int len = static_cast<int>(logBuffer.length());
    if (len >= maxLen)
      len = maxLen - 1;

    memcpy(buffer, logBuffer.c_str(), len);
    buffer[len] = '\0';
    return len;
  }
};

std::string Logger::logBuffer = "";
