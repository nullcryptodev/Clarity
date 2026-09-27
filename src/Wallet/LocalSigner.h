// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include "Crypto/Types.h"
#include "KeyStore.h"
#include "Signer.h"
#include "WalletError.h"

namespace Wallet
{
  //  LocalSigner — Signer backed by a KeyStore
  //
  //  Wraps a KeyStore and provides the Signer interface on top of it.
  //  Holds a cache of derived public keys, indexed by their 32-byte
  //  value, so sign() can look up "which path produces this key"
  //  without scanning the entire tree.
  //
  //  The cache is populated lazily:
  //    - The default account's receive and change keys are registered
  //      at construction (paths 0/0/0 and 0/1/0).
  //    - Additional keys are registered on demand via registerPath().
  //    - signAtPath() will register the path on first use and then
  //      sign.
  //
  //  Ownership: LocalSigner stores a reference to the KeyStore. The
  //  caller is responsible for keeping the KeyStore alive for at
  //  least as long as the signer. In practice the KeyStore is owned
  //  by whoever created it (the wallet facade), and signers are
  //  short-lived per-operation helpers, so this constraint is trivially
  //  satisfied.
  //
  //  Thread safety: sign() and registerPath() take a lock on the
  //  cache. The underlying KeyStore is not required to be thread-safe
  //  — the LocalSigner serializes access to it.

  class LocalSigner : public Signer
  {
  public:
    // The KeyStore reference must outlive the signer.
    explicit LocalSigner(KeyStore &key_store);
    ~LocalSigner() override;

    // ---- Signer interface ----

    std::string name() const override;

    bool isReady() const override;

    std::vector<Crypto::PublicKey> publicKeys() const override;

    std::optional<Crypto::Signature> sign(
        const Crypto::PublicKey &pubkey,
        const Crypto::Hash &hash,
        WalletStatus *error_out = nullptr) override;

    // LocalSigner can derive on demand, so it implements signAtPath.
    std::optional<Crypto::Signature> signAtPath(
        const HdPath &path,
        const Crypto::Hash &hash,
        WalletStatus *error_out = nullptr) override;

    //  Register a path so its public key is recognized by sign().
    //
    //  Returns the public key at that path, or std::nullopt on failure
    //  (typically because the key store is locked).
    //
    //  Registration is idempotent: registering the same path twice is
    //  cheap and has no effect on the second call.
    std::optional<Crypto::PublicKey> registerPath(
        const HdPath &path,
        WalletStatus *error_out = nullptr);

    //  Register a contiguous range of receive addresses:
    //  (account, 0, 0) through (account, 0, count - 1).
    //
    //  This is what a wallet does at startup: register the first N
    //  addresses so it can recognize incoming payments to any of them.
    //  N is usually 100-500.
    //
    //  Returns the number of paths successfully registered.
    size_t registerAddressRange(uint32_t account,
                                uint32_t count,
                                WalletStatus *error_out = nullptr);

    //  Convenience: get the KeyStore this signer wraps.
    const KeyStore &keyStore() const noexcept { return key_store_; }

  private:
    // Look up the path for a known public key. Returns nullopt if the
    // key hasn't been registered.
    std::optional<HdPath> pathForPubkey(const Crypto::PublicKey &pk) const;

    // Register a path's public key in the cache. Caller holds the lock.
    bool registerPathLocked(const HdPath &path,
                            Crypto::PublicKey &out_pubkey);

    //  Non-owning reference to the key store. The caller guarantees
    //  it stays alive for the signer's lifetime.
    KeyStore &key_store_;

    // Cache: pubkey (32 bytes, via std::hash specialization) -> path.
    // Protected by mutex_.
    mutable std::mutex mutex_;
    std::unordered_map<Crypto::PublicKey, HdPath> pubkey_to_path_;
  };

} // namespace Wallet