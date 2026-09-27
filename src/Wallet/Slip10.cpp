// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Slip10.h"

#include "Crypto/Ed25519.h"
#include "Crypto/Hmac.h"
#include "Crypto/SecureZero.h"

#include <cstring>

namespace Wallet
{
  namespace
  {
    // SLIP-0010 specifies this exact byte string as the HMAC key for
    // the master node. It is not configurable and must match the spec
    // for cross-wallet interoperability.
    constexpr char SLIP10_CURVE_SEED[] = "ed25519 seed";
    constexpr size_t SLIP10_CURVE_SEED_LEN = sizeof(SLIP10_CURVE_SEED) - 1;

    // SLIP-0010 §2: seed length must be 16-64 bytes inclusive.
    constexpr size_t SLIP10_MIN_SEED_LEN = 16;
    constexpr size_t SLIP10_MAX_SEED_LEN = 64;

    // Split a 64-byte HMAC output into IL (secret) and IR (chain code).
    void splitI(const uint8_t I[64],
                Crypto::SecretKey &out_secret,
                Crypto::Hash &out_chain_code) noexcept
    {
      std::memcpy(out_secret.data.data(), I, 32);
      std::memcpy(out_chain_code.data.data(), I + 32, 32);
    }
  } // namespace

  std::optional<Slip10Node> slip10Master(const uint8_t *seed,
                                         size_t seed_len,
                                         WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<Slip10Node>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    if (seed == nullptr || seed_len == 0)
      return fail(WalletError::DerivationFailed, "empty seed");

    if (seed_len < SLIP10_MIN_SEED_LEN)
      return fail(WalletError::DerivationFailed,
                  "seed must be at least 16 bytes");

    if (seed_len > SLIP10_MAX_SEED_LEN)
      return fail(WalletError::DerivationFailed,
                  "seed must be at most 64 bytes");

    uint8_t I[64];
    Crypto::hmacSha512(
        reinterpret_cast<const uint8_t *>(SLIP10_CURVE_SEED),
        SLIP10_CURVE_SEED_LEN,
        seed, seed_len,
        I);

    Slip10Node node;
    splitI(I, node.secret, node.chain_code);
    node.depth = 0;
    node.child_number = 0;

    Crypto::secureZero(I, sizeof(I));
    return node;
  }

  std::optional<Slip10Node> slip10DeriveChild(const Slip10Node &parent,
                                              const PathElement &element,
                                              WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<Slip10Node>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    if (!element.hardened)
      return fail(WalletError::InvalidPath,
                  "SLIP-0010 for Ed25519 requires hardened derivation");

    if (element.index > MAX_INDEX)
      return fail(WalletError::DerivationIndexOutOfRange,
                  "index exceeds 2^31 - 1");

    // data = 0x00 || IL || index_be32
    //
    // The leading 0x00 byte is a SLIP-0010 convention that mirrors
    // BIP-32's padded private key serialization. It is what makes the
    // input unambiguous when a caller might have passed a compressed
    // public key instead. For hardened-only derivation it is always
    // 0x00, always present, never omitted.
    uint8_t data[1 + 32 + 4];
    data[0] = 0x00;
    std::memcpy(data + 1, parent.secret.data.data(), 32);

    const uint32_t index_raw = element.raw(); // includes the hardened bit
    data[33] = uint8_t((index_raw >> 24) & 0xFF);
    data[34] = uint8_t((index_raw >> 16) & 0xFF);
    data[35] = uint8_t((index_raw >> 8) & 0xFF);
    data[36] = uint8_t(index_raw & 0xFF);

    uint8_t I[64];
    Crypto::hmacSha512(parent.chain_code.data.data(), 32,
                       data, sizeof(data),
                       I);

    Slip10Node child;
    splitI(I, child.secret, child.chain_code);
    child.depth = parent.depth + 1;
    child.child_number = index_raw;

    Crypto::secureZero(I, sizeof(I));
    Crypto::secureZero(data, sizeof(data));
    return child;
  }

  std::optional<Slip10Node> slip10DerivePath(const Slip10Node &master,
                                             const HdPath &path,
                                             WalletStatus *error_out)
  {
    if (error_out)
      *error_out = WalletStatus::success();

    if (path.length == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(WalletError::InvalidPath,
                                        "empty path");
      return std::nullopt;
    }

    Slip10Node current = master;
    for (size_t i = 0; i < path.length; ++i)
    {
      auto next = slip10DeriveChild(current, path.elements[i], error_out);
      if (!next)
      {
        wipeNode(current);
        return std::nullopt;
      }
      // Wipe the intermediate. We only keep the leaf.
      wipeNode(current);
      current = *next;
    }

    return current;
  }

  Crypto::PublicKey slip10PublicKey(const Slip10Node &node) noexcept
  {
    return Crypto::derivePublicKey(node.secret);
  }

  void wipeNode(Slip10Node &node) noexcept
  {
    Crypto::secureZero(node.secret.data.data(), 32);
    Crypto::secureZero(node.chain_code.data.data(), 32);
    node.depth = 0;
    node.child_number = 0;
  }

} // namespace Wallet