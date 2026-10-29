// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>

#include "Crypto/Types.h"

namespace Crypto
{
  //  RIPEMD-160, as specified in the original Dobbertin/Bosselaers/
  //  Preneel paper and used throughout Bitcoin (P2PKH, P2SH,
  //  P2WPKH, BIP32 fingerprints).
  //
  //  One-shot and streaming interfaces, matching the shape of
  //  Crypto/Sha256.h so call sites look the same.
  //
  //  This is NOT a general-purpose hash recommendation. RIPEMD-160
  //  is used here because Bitcoin's script and address formats
  //  hardcode it; do not reach for it for new designs.

  class Ripemd160
  {
  public:
    Ripemd160() noexcept;

    void reset() noexcept;

    void update(const uint8_t *data, size_t len) noexcept;

    //  Finalize and write exactly 20 bytes into out.
    //  After this call the object is reset and may be reused.
    void finalize(uint8_t *out) noexcept;

    //  One-shot. Writes 20 bytes into out.
    static void hash(const uint8_t *data, size_t len,
                     uint8_t *out) noexcept;

  private:
    void processBlock(const uint8_t *block) noexcept;

    uint32_t h_[5];
    uint64_t total_bits_;
    uint8_t buffer_[64];
    size_t buffer_len_;
  };
} // namespace Crypto