#pragma once
#include <cstddef>

// Compile-time XOR String Encryption
// This hides strings from static analysis tools like IDA and strings.exe

namespace detail {
// Compile-time random seed based on __TIME__
constexpr unsigned int seed() {
  return (__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 +
         (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 +
         (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000;
}

// Linear congruential generator for compile-time random numbers
constexpr unsigned int random(unsigned int x) {
  return (1013904223 + 1664525 * x) % 4294967296;
}

// Generate key based on index and seed
constexpr char key(size_t index) {
  return static_cast<char>((random(seed() + index) % 254) + 1);
}

// XOR encrypted string holder
template <size_t N> class XorString {
private:
  char encrypted[N];
  mutable char decrypted[N];
  mutable bool is_decrypted;

public:
  // Encrypt at compile time
  constexpr XorString(const char (&str)[N])
      : encrypted{}, decrypted{}, is_decrypted(false) {
    for (size_t i = 0; i < N; ++i) {
      encrypted[i] = str[i] ^ key(i);
    }
  }

  // Decrypt at runtime - returns pointer to internal buffer
  const char *decrypt() const {
    if (!is_decrypted) {
      for (size_t i = 0; i < N; ++i) {
        decrypted[i] = encrypted[i] ^ key(i);
      }
      is_decrypted = true;
    }
    return decrypted;
  }

  // Clear decrypted string from memory (anti-forensics)
  void clear() const {
    if (is_decrypted) {
      for (size_t i = 0; i < N; ++i) {
        decrypted[i] = 0;
      }
      is_decrypted = false;
    }
  }

  ~XorString() { clear(); }
};
} // namespace detail

// FIXED: Use static storage to prevent dangling pointers
// The lambda creates a static instance that persists
#define XSTRING(str)                                                           \
  ([]() -> const char * {                                                      \
    static detail::XorString<sizeof(str)> xorStr(str);                         \
    return xorStr.decrypt();                                                   \
  }())
