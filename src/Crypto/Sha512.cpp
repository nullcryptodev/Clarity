// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Sha512.h"
#include "SecureZero.h"

extern "C"
{
#include "monocypher.h"
#include "monocypher-ed25519.h"
}

namespace Crypto
{

  void sha512(const uint8_t *in, size_t len, uint8_t out[64]) noexcept
  {
    crypto_sha512(out, in, len);
  }

  struct Sha512::Impl
  {
    crypto_sha512_ctx ctx;
  };

  Sha512::Sha512() noexcept
      : impl_(new Impl)
  {
    crypto_sha512_init(&impl_->ctx);
  }

  Sha512::~Sha512() noexcept
  {
    if (impl_)
    {
      secureZero(impl_, sizeof(Impl));
      delete impl_;
    }
  }

  Sha512::Sha512(Sha512 &&other) noexcept
      : impl_(other.impl_)
  {
    other.impl_ = nullptr;
  }

  Sha512 &Sha512::operator=(Sha512 &&other) noexcept
  {
    if (this != &other)
    {
      if (impl_)
      {
        secureZero(impl_, sizeof(Impl));
        delete impl_;
      }
      impl_ = other.impl_;
      other.impl_ = nullptr;
    }
    return *this;
  }

  void Sha512::update(const uint8_t *data, size_t len) noexcept
  {
    crypto_sha512_update(&impl_->ctx, data, len);
  }

  void Sha512::update(std::string_view s) noexcept
  {
    update(reinterpret_cast<const uint8_t *>(s.data()), s.size());
  }

  void Sha512::update(const std::vector<uint8_t> &v) noexcept
  {
    update(v.data(), v.size());
  }

  void Sha512::finalize(uint8_t out[64]) noexcept
  {
    crypto_sha512_final(&impl_->ctx, out);
    crypto_sha512_init(&impl_->ctx); // reset for reuse
  }

} // namespace Crypto