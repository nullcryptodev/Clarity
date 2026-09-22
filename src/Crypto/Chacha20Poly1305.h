// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>

namespace Crypto
{
  inline constexpr size_t AEAD_KEY_SIZE = 32;
  inline constexpr size_t AEAD_NONCE_SIZE = 24; // XChaCha20-Poly1305
  inline constexpr size_t AEAD_MAC_SIZE = 16;

  // XChaCha20-Poly1305 AEAD (extended nonce, safe for random nonces).
  //
  // Returns true on success.
  bool aeadEncrypt(const uint8_t *plaintext, size_t plaintextLen,
                   const uint8_t *ad, size_t adLen,
                   const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   uint8_t *ciphertext,
                   uint8_t mac[AEAD_MAC_SIZE]) noexcept;

  // Returns true on success (authentication verified).
  // On failure, `plaintext` contents are undefined.
  bool aeadDecrypt(const uint8_t *ciphertext, size_t ciphertextLen,
                   const uint8_t *ad, size_t adLen,
                   const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   const uint8_t mac[AEAD_MAC_SIZE],
                   uint8_t *plaintext) noexcept;
}