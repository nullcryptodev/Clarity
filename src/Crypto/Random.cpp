// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Random.h"

#include <cstring>

#if defined(__linux__)
#include <sys/random.h>
#include <errno.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h> // arc4random_buf
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#error "Unsupported platform: no CSPRNG available"
#endif

namespace Crypto
{

  bool randomBytes(void *buf, size_t len) noexcept
  {
    if (len == 0)
      return true;

#if defined(__linux__)
    size_t total = 0;
    while (total < len)
    {
      ssize_t n = ::getrandom(static_cast<char *>(buf) + total, len - total, 0);
      if (n < 0)
      {
        if (errno == EINTR)
          continue; // interrupted, retry
        return false;
      }
      total += static_cast<size_t>(n);
    }
    return true;

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(buf, len);
    return true;

#elif defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(
        nullptr,
        static_cast<PUCHAR>(buf),
        static_cast<ULONG>(len),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0;
#endif
  }

  uint64_t randomUniform(uint64_t bound) noexcept
  {
    if (bound <= 1)
      return 0;

    // Rejection sampling to avoid modulo bias.
    const uint64_t limit = UINT64_MAX - (UINT64_MAX % bound);

    uint64_t r;
    do
    {
      if (!randomBytes(&r, sizeof(r)))
        return 0;
    } while (r >= limit);

    return r % bound;
  }

} // namespace Crypto