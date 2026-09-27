// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "KeyDerivation.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "Crypto/SecureZero.h"

#include <cstring>

namespace Wallet
{
  //  Free functions

  Crypto::Hash160 pubkeyHash160(const Crypto::PublicKey &pk) noexcept
  {
    Crypto::Hash160 out;
    // Blake2b-160 takes the public key as input and produces 20 bytes.
    // We use the same Blake2b variant the rest of the codebase uses
    // for address-adjacent hashing. If the protocol ever changes the
    // hash used for the fingerprint, this is the one place to update.
    Crypto::blake2b(pk.data.data(), pk.data.size(), out.data.data(), 20);
    return out;
  }

  SeedFingerprint fingerprintForMaster(const Slip10Node &master) noexcept
  {
    const Crypto::PublicKey pk = Crypto::derivePublicKey(master.secret);
    const Crypto::Hash160 h = pubkeyHash160(pk);

    SeedFingerprint fp;
    fp.bytes[0] = h.data[0];
    fp.bytes[1] = h.data[1];
    fp.bytes[2] = h.data[2];
    fp.bytes[3] = h.data[3];
    return fp;
  }

  std::string SeedFingerprint::toHex() const
  {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(8);
    for (uint8_t b : bytes)
    {
      out.push_back(hex[b >> 4]);
      out.push_back(hex[b & 0x0F]);
    }
    return out;
  }

  //  SeedMaterial

  SeedMaterial::SeedMaterial(SeedMaterial &&o) noexcept
      : seed_(std::move(o.seed_)),
        master_(o.master_),
        fingerprint_(o.fingerprint_)
  {
    // The moved-from object still holds a valid (but empty) master.
    // Wipe its master node since we copied the secrets across.
    wipeNode(o.master_);
    o.fingerprint_ = {};
  }

  SeedMaterial &SeedMaterial::operator=(SeedMaterial &&o) noexcept
  {
    if (this != &o)
    {
      // Wipe our current secrets before overwriting.
      Crypto::secureZero(seed_.data(), seed_.size());
      wipeNode(master_);

      seed_ = std::move(o.seed_);
      master_ = o.master_;
      fingerprint_ = o.fingerprint_;

      wipeNode(o.master_);
      o.fingerprint_ = {};
    }
    return *this;
  }

  SeedMaterial::~SeedMaterial()
  {
    Crypto::secureZero(seed_.data(), seed_.size());
    wipeNode(master_);
  }

  void SeedMaterial::computeFingerprint() noexcept
  {
    fingerprint_ = fingerprintForMaster(master_);
  }

  std::optional<SeedMaterial> SeedMaterial::fromMnemonic(
      std::string_view mnemonic,
      std::string_view passphrase,
      WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<SeedMaterial>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    // Validate first. This catches typos before we go through the
    // 2048-iteration PBKDF2, which is the expensive part.
    const WalletError ve = validateMnemonic(mnemonic);
    if (ve != WalletError::Ok)
      return fail(ve, walletErrorMessage(ve));

    // mnemonic -> 64-byte seed.
    // Resolves to Wallet::mnemonicToSeed from Bip39.h (included via
    // KeyDerivation.h).
    std::vector<uint8_t> seed(64);
    mnemonicToSeed(mnemonic, passphrase, seed.data());

    // seed -> master SLIP-0010 node.
    WalletStatus status;
    auto master_opt = slip10Master(seed, &status);
    if (!master_opt)
    {
      Crypto::secureZero(seed.data(), seed.size());
      return fail(status.code, std::move(status.detail));
    }

    SeedMaterial out;
    out.seed_ = std::move(seed);
    out.master_ = *master_opt;
    out.computeFingerprint();

    // Wipe the local copy of the master now that it's inside `out`.
    wipeNode(*master_opt);

    return out;
  }

  std::optional<SeedMaterial> SeedMaterial::fromSeed(
      const std::vector<uint8_t> &seed,
      WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<SeedMaterial>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    if (seed.empty())
      return fail(WalletError::DerivationFailed, "empty seed");

    WalletStatus status;
    auto master_opt = slip10Master(seed.data(), seed.size(), &status);
    if (!master_opt)
      return fail(status.code, std::move(status.detail));

    SeedMaterial out;
    out.seed_ = seed; // copy, caller keeps theirs
    out.master_ = *master_opt;
    out.computeFingerprint();

    wipeNode(*master_opt);
    return out;
  }

  std::optional<DerivedKey> SeedMaterial::deriveKey(
      const HdPath &path,
      WalletStatus *error_out) const
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<DerivedKey>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    if (path.length == 0)
      return fail(WalletError::InvalidPath, "empty path");

    // Walk the path from the master node.
    //
    // We deliberately do NOT use slip10DerivePath here. That function
    // wipes intermediates as it goes, which is fine, but it also wipes
    // the input on failure — and the input is our master_, which
    // belongs to `this`. Walking the path manually lets us keep
    // master_ intact regardless of failure mode.
    Slip10Node current = master_;

    for (size_t i = 0; i < path.length; ++i)
    {
      WalletStatus step_status;
      auto next = slip10DeriveChild(current, path.elements[i], &step_status);
      wipeNode(current);

      if (!next)
      {
        return fail(step_status.code, std::move(step_status.detail));
      }
      current = *next;
    }

    DerivedKey key;
    key.secret = current.secret;
    key.pubkey = Crypto::derivePublicKey(current.secret);
    key.path = path;

    wipeNode(current);
    return key;
  }

} // namespace Wallet