// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BitcoinEcdsa.h"

#include <secp256k1.h>

#include <cstring>

namespace Crypto
{
  namespace
  {
    //  The process-wide secp256k1 context, shared with
    //  BitcoinBip32 and BitcoinBip32Private. Same flags as those
    //  modules (SIGN | VERIFY); whichever module runs first pays
    //  the construction cost.
    secp256k1_context *context()
    {
      static secp256k1_context *ctx = []
      {
        return secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
      }();
      return ctx;
    }
  } // anonymous namespace

  std::optional<Signature> signHash(
      const ExtendedPrivKey &key,
      const Hash &hash,
      std::string *error_out)
  {
    if (key.isNull())
    {
      if (error_out)
        *error_out = "ExtendedPrivKey is null";
      return std::nullopt;
    }
    if (hash.isNull())
    {
      if (error_out)
        *error_out = "hash is null";
      return std::nullopt;
    }

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_sign(context(),
                             &sig,
                             hash.data.data(),
                             key.key.data(),
                             /*noncefp=*/nullptr,
                             /*ndata=*/nullptr) != 1)
    {
      //  Per secp256k1's docs this cannot fail for a valid
      //  secret key and a 32-byte message hash — the nonce
      //  function (RFC 6979 by default) never fails. The check
      //  is defensive: a failure here means either the key or
      //  the context is broken, and returning nullopt is better
      //  than a signature-shaped garbage.
      if (error_out)
        *error_out = "secp256k1_ecdsa_sign failed";
      return std::nullopt;
    }

    //  Normalize to low-S (BIP62). secp256k1_ecdsa_sign
    //  produces low-S in practice, but normalizing makes the
    //  property unconditional. The function returns 1 if the
    //  input was already low-S and 0 if it was normalized; both
    //  are success.
    secp256k1_ecdsa_signature normalized;
    secp256k1_ecdsa_signature_normalize(context(), &normalized, &sig);

    Signature out;
    if (secp256k1_ecdsa_signature_serialize_compact(
            context(), out.data.data(), &normalized) != 1)
    {
      if (error_out)
        *error_out = "secp256k1_ecdsa_signature_serialize_compact failed";
      return std::nullopt;
    }
    return out;
  }

  std::vector<uint8_t> derEncode(const Signature &sig)
  {
    //  Parse the 64-byte (r || s) compact form back into a
    //  secp256k1 signature object. This rejects (r, s) pairs
    //  where r or s is >= the curve order.
    secp256k1_ecdsa_signature parsed;
    if (secp256k1_ecdsa_signature_parse_compact(
            context(), &parsed, sig.data.data()) != 1)
    {
      return {};
    }

    //  DER is variable-length: at most 72 bytes for secp256k1
    //  (0x30 len 0x02 len_r r 0x02 len_s s, with the minimal
    //  leading-zero rules). 72 is the well-known upper bound;
    //  allocate that and let secp256k1 write the actual length.
    uint8_t der[72];
    size_t der_len = sizeof(der);
    if (secp256k1_ecdsa_signature_serialize_der(
            context(), der, &der_len, &parsed) != 1)
    {
      return {};
    }

    return std::vector<uint8_t>(der, der + der_len);
  }

  std::optional<std::vector<uint8_t>> signDerWithHashType(
      const ExtendedPrivKey &key,
      const Hash &hash,
      uint32_t hash_type,
      std::string *error_out)
  {
    if (hash_type != 0x01) // SIGHASH_ALL only; see the header
    {
      if (error_out)
        *error_out = "hash_type must be 0x01 (SIGHASH_ALL); got " +
                     std::to_string(hash_type);
      return std::nullopt;
    }

    auto sig = signHash(key, hash, error_out);
    if (!sig.has_value())
      return std::nullopt;

    auto der = derEncode(*sig);
    if (der.empty())
    {
      if (error_out)
        *error_out = "DER encoding failed";
      return std::nullopt;
    }

    //  Witness stack item: [ DER signature || 0x01 ].
    der.push_back(static_cast<uint8_t>(hash_type));
    return der;
  }

} // namespace Crypto