// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Chacha20Poly1305.h"

extern "C"
{
#include "monocypher.h"
}

#include <cstring>

namespace Crypto
{
  namespace
  {
    // Derive the Poly1305 key. XChaCha20 uses HChaCha20 to derive a
    // subkey from the first 16 bytes of the 24-byte nonce, then the
    // subkey plus the remaining 8 bytes of nonce drive ChaCha20. The
    // Poly1305 key is the first 32 bytes of the ChaCha20 keystream at
    // counter 0.
    void derivePolyKey(uint8_t poly_key[32],
                       const uint8_t key[AEAD_KEY_SIZE],
                       const uint8_t nonce[AEAD_NONCE_SIZE])
    {
      uint8_t sub_key[32];
      crypto_chacha20_h(sub_key, key, nonce);

      uint8_t zero[32] = {0};
      crypto_chacha20_djb(poly_key, zero, 32, sub_key, nonce + 16, 0);

      crypto_wipe(sub_key, sizeof(sub_key));
      crypto_wipe(zero, sizeof(zero));
    }

    // ChaCha20 encryption starting at counter 1 (keystream block 1).
    void chachaEncrypt(uint8_t *out, const uint8_t *in, size_t len,
                       const uint8_t key[AEAD_KEY_SIZE],
                       const uint8_t nonce[AEAD_NONCE_SIZE])
    {
      uint8_t sub_key[32];
      crypto_chacha20_h(sub_key, key, nonce);
      crypto_chacha20_djb(out, in, len, sub_key, nonce + 16, 1);
      crypto_wipe(sub_key, sizeof(sub_key));
    }

    // Compute the Poly1305 tag over
    //   (AAD || pad16 || ciphertext || pad16 || len(AAD) || len(CT))
    // per RFC 8439 §2.8.
    void computeTag(uint8_t tag[AEAD_MAC_SIZE],
                    const uint8_t poly_key[32],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *ct, size_t ct_len)
    {
      crypto_poly1305_ctx ctx;
      crypto_poly1305_init(&ctx, poly_key);

      static const uint8_t zeros[16] = {0};

      crypto_poly1305_update(&ctx, aad, aad_len);
      crypto_poly1305_update(&ctx, zeros, (16 - (aad_len % 16)) % 16);

      crypto_poly1305_update(&ctx, ct, ct_len);
      crypto_poly1305_update(&ctx, zeros, (16 - (ct_len % 16)) % 16);

      uint8_t lengths[16];
      for (int i = 0; i < 8; ++i)
      {
        lengths[i] = uint8_t(aad_len >> (8 * i));
        lengths[8 + i] = uint8_t(ct_len >> (8 * i));
      }
      crypto_poly1305_update(&ctx, lengths, 16);

      crypto_poly1305_final(&ctx, tag);
    }
  } // namespace

  bool aeadEncrypt(const uint8_t *plaintext, size_t plaintextLen,
                   const uint8_t *ad, size_t adLen,
                   const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   uint8_t *ciphertext,
                   uint8_t mac[AEAD_MAC_SIZE]) noexcept
  {
    uint8_t poly_key[32];
    derivePolyKey(poly_key, key, nonce);
    chachaEncrypt(ciphertext, plaintext, plaintextLen, key, nonce);
    computeTag(mac, poly_key, ad, adLen, ciphertext, plaintextLen);
    crypto_wipe(poly_key, sizeof(poly_key));
    return true;
  }

  bool aeadDecrypt(const uint8_t *ciphertext, size_t ciphertextLen,
                   const uint8_t *ad, size_t adLen,
                   const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   const uint8_t mac[AEAD_MAC_SIZE],
                   uint8_t *plaintext) noexcept
  {
    uint8_t poly_key[32];
    derivePolyKey(poly_key, key, nonce);

    uint8_t expected_mac[16];
    computeTag(expected_mac, poly_key, ad, adLen, ciphertext, ciphertextLen);
    crypto_wipe(poly_key, sizeof(poly_key));

    int mismatch = crypto_verify16(mac, expected_mac);
    crypto_wipe(expected_mac, sizeof(expected_mac));

    if (mismatch)
      return false;

    chachaEncrypt(plaintext, ciphertext, ciphertextLen, key, nonce);
    return true;
  }

} // namespace Crypto