// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Hmac.h"
#include "Sha512.h"
#include "SecureZero.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    // Compute the padded key schedule used by HMAC.
    // Writes HMAC_SHA512_BLOCK_SIZE bytes into `k_pad`.
    //
    // If the key is longer than the block size, it is hashed first.
    // If shorter, it is zero-padded to the block size.
    void prepareKey(const uint8_t *key, size_t key_len,
                    uint8_t k_pad[HMAC_SHA512_BLOCK_SIZE]) noexcept
    {
      std::memset(k_pad, 0, HMAC_SHA512_BLOCK_SIZE);

      if (key_len > HMAC_SHA512_BLOCK_SIZE)
      {
        uint8_t hashed[64];
        Crypto::sha512(key, key_len, hashed);
        std::memcpy(k_pad, hashed, 64);
        Crypto::secureZero(hashed, sizeof(hashed));
      }
      else if (key_len > 0)
      {
        std::memcpy(k_pad, key, key_len);
      }
    }
  } // namespace

  //  One-shot

  void hmacSha512(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t out[HMAC_SHA512_OUTPUT_SIZE]) noexcept
  {
    uint8_t k_pad[HMAC_SHA512_BLOCK_SIZE];
    prepareKey(key, key_len, k_pad);

    // Inner: H((K xor ipad) || msg)
    uint8_t ipad[HMAC_SHA512_BLOCK_SIZE];
    for (size_t i = 0; i < HMAC_SHA512_BLOCK_SIZE; ++i)
      ipad[i] = k_pad[i] ^ 0x36;

    uint8_t inner[64];
    {
      Crypto::Sha512 h;
      h.update(ipad, HMAC_SHA512_BLOCK_SIZE);
      if (msg_len > 0)
        h.update(msg, msg_len);
      h.finalize(inner);
    }

    // Outer: H((K xor opad) || inner)
    uint8_t opad[HMAC_SHA512_BLOCK_SIZE];
    for (size_t i = 0; i < HMAC_SHA512_BLOCK_SIZE; ++i)
      opad[i] = k_pad[i] ^ 0x5c;

    {
      Crypto::Sha512 h;
      h.update(opad, HMAC_SHA512_BLOCK_SIZE);
      h.update(inner, sizeof(inner));
      h.finalize(out);
    }

    Crypto::secureZero(k_pad, sizeof(k_pad));
    Crypto::secureZero(ipad, sizeof(ipad));
    Crypto::secureZero(opad, sizeof(opad));
    Crypto::secureZero(inner, sizeof(inner));
  }

  //  Streaming

  struct HmacSha512::Impl
  {
    uint8_t k_pad[HMAC_SHA512_BLOCK_SIZE];
    Crypto::Sha512 inner;
    bool finalized{false};
  };

  HmacSha512::HmacSha512(const uint8_t *key, size_t key_len) noexcept
      : impl_(new Impl)
  {
    prepareKey(key, key_len, impl_->k_pad);

    // Prime the inner hash with (K xor ipad).
    uint8_t ipad[HMAC_SHA512_BLOCK_SIZE];
    for (size_t i = 0; i < HMAC_SHA512_BLOCK_SIZE; ++i)
      ipad[i] = impl_->k_pad[i] ^ 0x36;
    impl_->inner.update(ipad, HMAC_SHA512_BLOCK_SIZE);
    Crypto::secureZero(ipad, sizeof(ipad));
  }

  HmacSha512::~HmacSha512() noexcept
  {
    if (impl_)
    {
      Crypto::secureZero(impl_->k_pad, sizeof(impl_->k_pad));
      delete impl_;
      impl_ = nullptr;
    }
  }

  HmacSha512::HmacSha512(HmacSha512 &&o) noexcept
      : impl_(o.impl_)
  {
    o.impl_ = nullptr;
  }

  HmacSha512 &HmacSha512::operator=(HmacSha512 &&o) noexcept
  {
    if (this != &o)
    {
      if (impl_)
      {
        Crypto::secureZero(impl_->k_pad, sizeof(impl_->k_pad));
        delete impl_;
      }
      impl_ = o.impl_;
      o.impl_ = nullptr;
    }
    return *this;
  }

  void HmacSha512::update(const uint8_t *data, size_t len) noexcept
  {
    if (!impl_ || impl_->finalized)
      return;
    if (len > 0)
      impl_->inner.update(data, len);
  }

  void HmacSha512::update(std::string_view s) noexcept
  {
    update(reinterpret_cast<const uint8_t *>(s.data()), s.size());
  }

  void HmacSha512::update(const std::vector<uint8_t> &v) noexcept
  {
    update(v.data(), v.size());
  }

  void HmacSha512::finalize(uint8_t out[HMAC_SHA512_OUTPUT_SIZE]) noexcept
  {
    if (!impl_ || impl_->finalized)
    {
      std::memset(out, 0, HMAC_SHA512_OUTPUT_SIZE);
      return;
    }
    impl_->finalized = true;

    uint8_t inner[64];
    impl_->inner.finalize(inner);

    uint8_t opad[HMAC_SHA512_BLOCK_SIZE];
    for (size_t i = 0; i < HMAC_SHA512_BLOCK_SIZE; ++i)
      opad[i] = impl_->k_pad[i] ^ 0x5c;

    Crypto::Sha512 outer;
    outer.update(opad, HMAC_SHA512_BLOCK_SIZE);
    outer.update(inner, sizeof(inner));
    outer.finalize(out);

    Crypto::secureZero(opad, sizeof(opad));
    Crypto::secureZero(inner, sizeof(inner));
  }

} // namespace Crypto