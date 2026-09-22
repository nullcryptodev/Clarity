// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Ed25519.h"
#include "Random.h"
#include "SecureZero.h"

#include <cstring>
#include <stdexcept>

extern "C"
{
#include "monocypher.h"
#include "monocypher-ed25519.h"
}

namespace Crypto
{

  //  Key generation

  KeyPair generateKeyPairFromSeed(const SecretKey &seed) noexcept
  {
    KeyPair kp;
    kp.secretKey = seed;

    // Make a mutable copy of the seed. Monocypher takes a non-const
    // seed pointer. Passing const-cast pointers is undefined behavior
    // and lets the compiler assume the original is unchanged. A local
    // copy is safe and correct.
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

  //  Signing

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

  //  Verification

  bool verify(const uint8_t *msg, size_t msgLen,
              const PublicKey &pk, const Signature &sig) noexcept
  {
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

  //  Batch verification

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

} // namespace Crypto