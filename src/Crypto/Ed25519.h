// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "Types.h"

namespace Crypto
{
  inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
  inline constexpr size_t ED25519_SECRET_KEY_SIZE = 32;
  inline constexpr size_t ED25519_SIGNATURE_SIZE = 64;

  KeyPair generateKeyPair();
  KeyPair generateKeyPairFromSeed(const SecretKey &seed) noexcept;
  PublicKey derivePublicKey(const SecretKey &sk) noexcept;

  void sign(const Hash &msg, const SecretKey &sk, Signature &out) noexcept;
  void sign(const uint8_t *msg, size_t msgLen,
            const SecretKey &sk, Signature &out) noexcept;

  Signature sign(const Hash &msg, const SecretKey &sk) noexcept;
  Signature sign(const uint8_t *msg, size_t msgLen,
                 const SecretKey &sk) noexcept;

  bool verify(const Hash &msg,
              const PublicKey &pk,
              const Signature &sig) noexcept;

  bool verify(const uint8_t *msg, size_t msgLen,
              const PublicKey &pk,
              const Signature &sig) noexcept;

  bool verifyBatch(const Hash &msg,
                   const std::vector<PublicKey> &pks,
                   const std::vector<Signature> &sigs) noexcept;

} // namespace Crypto