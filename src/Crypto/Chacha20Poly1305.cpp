// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Chacha20Poly1305.h"

extern "C"
{
#include "monocypher.h"
}

namespace Crypto
{

  bool aeadEncrypt(const uint8_t *plaintext, size_t plaintextLen,
                   const uint8_t *ad, size_t adLen,
                   const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   uint8_t *ciphertext,
                   uint8_t mac[AEAD_MAC_SIZE]) noexcept
  {
    crypto_aead_lock(ciphertext, mac,
                     key, nonce,
                     ad, adLen,
                     plaintext, plaintextLen);
    return true;
  }

  bool aeadDecrypt(const uint8_t *ciphertext, size_t ciphertextLen,
                   const uint8_t *ad, size_t adLen,
                   const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   const uint8_t mac[AEAD_MAC_SIZE],
                   uint8_t *plaintext) noexcept
  {
    return crypto_aead_unlock(plaintext,
                              mac,
                              key, nonce,
                              ad, adLen,
                              ciphertext, ciphertextLen) == 0;
  }

} // namespace Crypto