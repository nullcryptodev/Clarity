#pragma once

#include "Types.h"
#include "Blake2b.h"

namespace Crypto
{
  static inline Hash hashDomain(const char *domain, const uint8_t *data, size_t len)
  {
    size_t dlen = std::strlen(domain);
    std::vector<uint8_t> buf;
    buf.reserve(dlen + len);
    buf.insert(buf.end(),
               reinterpret_cast<const uint8_t *>(domain),
               reinterpret_cast<const uint8_t *>(domain) + dlen);
    buf.insert(buf.end(), data, data + len);

    Hash h;
    blake2b(buf.data(), buf.size(), h.data.data(), 32);
    return h;
  }
}