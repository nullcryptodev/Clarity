// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Ed25519.h"
#include "Random.h"
#include "SecureZero.h"
#include "Keccak.h"
#include "Sha512.h"

#include <cstring>
#include <stdexcept>

extern "C"
{
#include "monocypher.h"
#include "monocypher-ed25519.h"

//  Vendored CCX ref10 group arithmetic (crypto-ops.{c,h}).
//  See extern/cryptonote-ref10/README for provenance.
#include "crypto-ops.h"
}

namespace Crypto
{

  //  =====================================================================
  //  Existing key generation / signing / verification
  //  =====================================================================

  KeyPair generateKeyPairFromSeed(const SecretKey &seed) noexcept
  {
    KeyPair kp;
    kp.secretKey = seed;

    uint8_t mutable_seed[32];
    std::memcpy(mutable_seed, seed.data.data(), 32);

    uint8_t expanded_sk[64];

    crypto_ed25519_key_pair(expanded_sk,
                            kp.publicKey.data.data(),
                            mutable_seed);

    secureZero(expanded_sk, sizeof(expanded_sk));
    secureZero(mutable_seed, sizeof(mutable_seed));
    return kp;
  }

  KeyPair generateKeyPair()
  {
    SecretKey seed;
    if (!randomBytes(seed.data.data(), seed.data.size()))
    {
      throw std::runtime_error("Ed25519: CSPRNG unavailable");
    }

    KeyPair kp = generateKeyPairFromSeed(seed);
    secureZero(seed.data.data(), seed.data.size());
    return kp;
  }

  PublicKey derivePublicKey(const SecretKey &sk) noexcept
  {
    PublicKey pk;

    uint8_t mutable_seed[32];
    std::memcpy(mutable_seed, sk.data.data(), 32);

    uint8_t expanded_sk[64];

    crypto_ed25519_key_pair(expanded_sk,
                            pk.data.data(),
                            mutable_seed);

    secureZero(expanded_sk, sizeof(expanded_sk));
    secureZero(mutable_seed, sizeof(mutable_seed));
    return pk;
  }

  void sign(const uint8_t *msg, size_t msgLen,
            const SecretKey &sk, Signature &out) noexcept
  {
    uint8_t mutable_seed[32];
    std::memcpy(mutable_seed, sk.data.data(), 32);

    uint8_t expanded_sk[64];
    uint8_t pk[32];

    crypto_ed25519_key_pair(expanded_sk, pk, mutable_seed);

    crypto_ed25519_sign(out.data.data(),
                        expanded_sk,
                        msg,
                        msgLen);

    secureZero(expanded_sk, sizeof(expanded_sk));
    secureZero(pk, sizeof(pk));
    secureZero(mutable_seed, sizeof(mutable_seed));
  }

  void sign(const Hash &msg, const SecretKey &sk, Signature &out) noexcept
  {
    sign(msg.data.data(), msg.data.size(), sk, out);
  }

  Signature sign(const Hash &msg, const SecretKey &sk) noexcept
  {
    Signature s;
    sign(msg, sk, s);
    return s;
  }

  Signature sign(const uint8_t *msg, size_t msgLen, const SecretKey &sk) noexcept
  {
    Signature s;
    sign(msg, msgLen, sk, s);
    return s;
  }

  bool verify(const uint8_t *msg, size_t msgLen,
              const PublicKey &pk, const Signature &sig) noexcept
  {
    if (pk.isNull() || sig.isNull())
      return false;

    return crypto_ed25519_check(sig.data.data(),
                                pk.data.data(),
                                msg,
                                msgLen) == 0;
  }

  bool verify(const Hash &msg,
              const PublicKey &pk,
              const Signature &sig) noexcept
  {
    return verify(msg.data.data(), msg.data.size(), pk, sig);
  }

  bool verifyBatch(const Hash &msg,
                   const std::vector<PublicKey> &pks,
                   const std::vector<Signature> &sigs) noexcept
  {
    if (pks.size() != sigs.size() || pks.empty())
      return false;

    for (size_t i = 0; i < pks.size(); ++i)
    {
      if (!verify(msg, pks[i], sigs[i]))
        return false;
    }
    return true;
  }

  //  =====================================================================
  //  CryptoNote output-key derivation
  //  =====================================================================
  //
  //  Thin adapter over the vendored ref10 curve arithmetic. The
  //  hash-to-scalar step calls Clarity's existing keccak-1600 with
  //  the original-Keccak padding (0x01) — the same padding CCX's
  //  cn_fast_hash uses. No CCX hash code is vendored.
  //
  //  See Crypto/Ed25519.h for the full rationale; the short version
  //  is that the derivation is a silent-failure primitive and the
  //  vendored crypto-ops code is the same code that produced the
  //  on-chain outputs, so byte-for-byte parity is guaranteed by
  //  construction. The static_asserts below pin the byte layouts.
  //  =====================================================================

  //  cn_fast_hash — CCX's fast hash.
  //
  //  In conceald this is keccak-1600 (original Keccak, not SHA3)
  //  with a 32-byte output and no length suffix. Clarity already
  //  has keccak-1600 in Crypto/keccak.h; the default padding of
  //  Crypto::keccak() is 0x01, which is original Keccak. So the
  //  shim is a single call.
  //
  //  If Crypto::keccak() ever changes its default padding to
  //  SHA3's 0x06, this shim must pass 0x01 explicitly. The
  //  known-answer test in Tests/Crypto/Ed25519Derivation.cpp
  //  pins this: cn_fast_hash("") must equal the empty-string
  //  Keccak-256 digest c5d24601..., not the SHA3-256 digest
  //  a7ffc6f8...
  void cnFastHash(const void *data, size_t len, uint8_t out[32]) noexcept
  {
    Crypto::keccak(reinterpret_cast<const uint8_t *>(data),
                   len, out, 32, 0x01);
  }

  namespace
  {
    static_assert(sizeof(fe) == 10 * sizeof(int32_t),
                  "fe must be 10 x int32");
    static_assert(sizeof(Crypto::EllipticCurvePoint) == 32,
                  "EllipticCurvePoint must be 32 bytes");
    static_assert(sizeof(Crypto::SecretKey) == 32,
                  "SecretKey must be 32 bytes");
    static_assert(sizeof(Crypto::PublicKey) == 32,
                  "PublicKey must be 32 bytes");
    static_assert(sizeof(Crypto::KeyDerivation) == 32,
                  "KeyDerivation must be 32 bytes");

    //  LEB128-style varint, matching Common::write_varint in the CCX
    //  tree for non-negative values. The encoding is unambiguous for
    //  uint64_t: 7 bits per byte, low bits first, high bit set on
    //  all but the last byte. Only canonical representations are
    //  produced, so there is no parity risk with CCX.
    size_t writeVarint(uint8_t *out, size_t value)
    {
      size_t n = 0;
      do
      {
        uint8_t b = uint8_t(value & 0x7F);
        value >>= 7;
        if (value != 0)
          b |= 0x80;
        out[n++] = b;
      } while (value != 0);
      return n;
    }

    //  Hs(derivation || varint(index)) reduced mod ℓ.
    //  Exactly the layout from conceald's derivation_to_scalar():
    //    struct { KeyDerivation derivation; char output_index[...]; }
    //  hashed with cn_fast_hash, then reduced with sc_reduce32.
    void derivationToScalar(const KeyDerivation &derivation,
                            size_t outputIndex,
                            unsigned char scalarOut[32]) noexcept
    {
      unsigned char buf[32 + 10]; // 32 + max uint64 varint
      std::memcpy(buf, derivation.data.data(), 32);

      size_t vlen = writeVarint(buf + 32, outputIndex);

      unsigned char h[32];
      cnFastHash(buf, 32 + vlen, h);

      std::memcpy(scalarOut, h, 32);
      sc_reduce32(scalarOut);

      secureZero(buf, sizeof(buf));
      secureZero(h, sizeof(h));
    }
  }

  bool generateKeyDerivation(const PublicKey &txPubKey,
                             const SecretKey &viewSecretKey,
                             KeyDerivation &out) noexcept
  {
    //  ccx crypto::generate_key_derivation:
    //    ge_frombytes_vartime(&R, tx_pub)
    //    ge_scalarmult(&p2, view_sec, &R)
    //    ge_mul8(&p3, &p2)                ← Conceal-specific cofactor step
    //    ge_p1p1_to_p2(&p2, &p3)
    //    ge_tobytes(derivation, &p2)
    //
    //  The ge_mul8 is NOT in textbook CryptoNote and is easy to omit
    //  on a rewrite. Omitting it produces a valid-looking 32-byte
    //  value that never matches on-chain output keys. Do not remove.

    ge_p3 R;
    if (ge_frombytes_vartime(&R,
                             reinterpret_cast<const unsigned char *>(txPubKey.data.data())) != 0)
      return false;

    if (sc_check(reinterpret_cast<const unsigned char *>(viewSecretKey.data.data())) != 0)
      return false;

    ge_p2 p2;
    ge_p1p1 p3;

    ge_scalarmult(&p2,
                  reinterpret_cast<const unsigned char *>(viewSecretKey.data.data()),
                  &R);

    ge_mul8(&p3, &p2);
    ge_p1p1_to_p2(&p2, &p3);

    unsigned char buf[32];
    ge_tobytes(buf, &p2);
    std::memcpy(out.data.data(), buf, 32);
    secureZero(buf, sizeof(buf));
    return true;
  }

  bool derivePublicKey(const KeyDerivation &derivation,
                       size_t outputIndex,
                       const PublicKey &spendPubKey,
                       PublicKey &out) noexcept
  {
    //  ccx crypto::derive_public_key:
    //    ge_frombytes_vartime(&base, spend_pub)
    //    derivation_to_scalar(derivation, index, scalar)
    //    ge_scalarmult_base(&sG, scalar)
    //    ge_p3_to_cached(&cached, &sG)
    //    ge_add(&p1p1, &base, &cached)
    //    ge_p1p1_to_p2(&p2, &p1p1)
    //    ge_tobytes(derived_key, &p2)

    ge_p3 base;
    if (ge_frombytes_vartime(&base,
                             reinterpret_cast<const unsigned char *>(spendPubKey.data.data())) != 0)
      return false;

    unsigned char scalar[32];
    derivationToScalar(derivation, outputIndex, scalar);

    ge_p3 sG;
    ge_cached cached;
    ge_p1p1 p1p1;
    ge_p2 p2;

    ge_scalarmult_base(&sG, scalar);
    ge_p3_to_cached(&cached, &sG);
    ge_add(&p1p1, &base, &cached);
    ge_p1p1_to_p2(&p2, &p1p1);

    unsigned char buf[32];
    ge_tobytes(buf, &p2);
    std::memcpy(out.data.data(), buf, 32);

    secureZero(scalar, sizeof(scalar));
    secureZero(buf, sizeof(buf));
    return true;
  }

  //  derivationToScalar lives in the anonymous namespace above as a
  //  helper for derivePublicKey. reverseDeriveCandidate below needs
  //  the same scalar, so we reuse the helper directly — no new hash
  //  or reduction logic, just the existing one.

  PublicKey scalarMultBase(const SecretKey &scalar) noexcept
  {
    if (sc_check(reinterpret_cast<const unsigned char *>(
            scalar.data.data())) != 0)
    {
      return PublicKey{};
    }

    ge_p3 R;
    ge_scalarmult_base(&R,
                       reinterpret_cast<const unsigned char *>(
                           scalar.data.data()));

    PublicKey out;
    unsigned char buf[32];
    ge_p3_tobytes(buf, &R);
    std::memcpy(out.data.data(), buf, 32);
    secureZero(buf, sizeof(buf));
    return out;
  }

  PublicKey pointSubtract(const PublicKey &a,
                          const PublicKey &b) noexcept
  {
    ge_p3 A, B;
    if (ge_frombytes_vartime(
            &A,
            reinterpret_cast<const unsigned char *>(a.data.data())) != 0)
      return PublicKey{};
    if (ge_frombytes_vartime(
            &B,
            reinterpret_cast<const unsigned char *>(b.data.data())) != 0)
      return PublicKey{};

    ge_cached B_cached;
    ge_p3_to_cached(&B_cached, &B);

    ge_p1p1 diff;
    ge_sub(&diff, &A, &B_cached);

    ge_p2 diff_p2;
    ge_p1p1_to_p2(&diff_p2, &diff);

    PublicKey out;
    unsigned char buf[32];
    ge_tobytes(buf, &diff_p2);
    std::memcpy(out.data.data(), buf, 32);
    secureZero(buf, sizeof(buf));
    return out;
  }

  bool reverseDeriveCandidate(const PublicKey &P,
                              const KeyDerivation &derivation,
                              size_t outputIndex,
                              PublicKey &candidate_out) noexcept
  {
    ge_p3 P_p3;
    if (ge_frombytes_vartime(
            &P_p3,
            reinterpret_cast<const unsigned char *>(P.data.data())) != 0)
      return false;

    //  Compute s = Hs(derivation, outputIndex). This is the same
    //  scalar derivePublicKey computes internally, and it is what
    //  derivePublicKey multiplies by G to get the term added to
    //  the spend pubkey.
    unsigned char s[32];
    derivationToScalar(derivation, outputIndex, s);

    //  candidate = P - s*G.
    //
    //  No ×8 here. The ×8 (ge_mul8 cofactor adjustment) is
    //  applied inside generateKeyDerivation, to the shared secret
    //  before it becomes the KeyDerivation. By the time we have a
    //  KeyDerivation and compute Hs(derivation, index), the
    //  cofactor has already been accounted for — the scalar
    //  derived from the KeyDerivation is exactly the scalar
    //  derivePublicKey adds to spend_pub. Subtracting it back is
    //  what reverses the derivation.
    ge_p3 sG;
    ge_scalarmult_base(&sG, s);

    ge_cached sG_cached;
    ge_p3_to_cached(&sG_cached, &sG);

    ge_p1p1 diff;
    ge_sub(&diff, &P_p3, &sG_cached);

    ge_p2 diff_p2;
    ge_p1p1_to_p2(&diff_p2, &diff);

    unsigned char buf[32];
    ge_tobytes(buf, &diff_p2);
    std::memcpy(candidate_out.data.data(), buf, 32);

    secureZero(s, sizeof(s));
    secureZero(buf, sizeof(buf));
    return true;
  }

  KeyPair generateScalarKeyPairFromSeed(const SecretKey &seed) noexcept
  {
    KeyPair kp;

    //  Hash the seed to 32 bytes, then reduce mod ℓ.
    //
    //  This is *not* how ed25519's key expansion works (that
    //  clamps the scalar into [2^254, 2^255), almost never < ℓ,
    //  and would fail sc_check). It IS how CryptoNote derives
    //  a view key from a seed: Hs(seed) = sc_reduce32(hash(seed)).
    //  The reduced value is always in [0, ℓ), so sc_check passes
    //  and it's usable as the secret half of a CryptoNote
    //  derivation.
    //
    //  The public key is the corresponding group element
    //  scalar * G, not the ed25519 public key of `seed`.
    uint8_t hash[32];
    Crypto::sha512(seed.data.data(), 32, hash);
    //  (or Crypto::blake2b, whichever is in scope — the point is
    //  any cryptographic hash; sc_reduce32 gives uniform output.)

    uint8_t scalar[32];
    std::memcpy(scalar, hash, 32);
    sc_reduce32(scalar);

    std::memcpy(kp.secretKey.data.data(), scalar, 32);

    ge_p3 R;
    ge_scalarmult_base(&R, scalar);
    unsigned char pub[32];
    ge_p3_tobytes(pub, &R);
    std::memcpy(kp.publicKey.data.data(), pub, 32);

    secureZero(hash, sizeof(hash));
    secureZero(scalar, sizeof(scalar));
    secureZero(pub, sizeof(pub));
    return kp;
  }

  bool isValidScalar(const SecretKey &sk) noexcept
  {
    return sc_check(reinterpret_cast<const unsigned char *>(
               sk.data.data())) == 0;
  }
} // namespace Crypto