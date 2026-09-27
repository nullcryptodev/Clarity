// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "LocalSigner.h"

#include "Crypto/Ed25519.h"
#include "Crypto/SecureZero.h"

namespace Wallet
{
  //  Signer default implementations
  //
  //  These are declared in Signer.h; we define them in this .cpp
  //  because they're small and don't warrant their own file.

  std::vector<std::optional<Crypto::Signature>> Signer::signBatch(
      const Crypto::PublicKey &pubkey,
      const std::vector<Crypto::Hash> &hashes,
      WalletStatus *error_out)
  {
    std::vector<std::optional<Crypto::Signature>> out;
    out.reserve(hashes.size());
    for (const auto &h : hashes)
    {
      out.push_back(sign(pubkey, h, error_out));
      // On the first failure, stop. Batch semantics: either all
      // succeed or we report the failure that stopped us.
      if (!out.back())
        return out;
    }
    return out;
  }

  //  LocalSigner

  LocalSigner::LocalSigner(KeyStore &key_store)
      : key_store_(key_store)
  {
    // Register the default account's receive and change keys. This
    // is best-effort; if the key store is locked, it fails silently
    // and the caller can register later.
    std::lock_guard<std::mutex> lock(mutex_);

    Crypto::PublicKey pk;
    registerPathLocked(receivePath(0, 0), pk);
    registerPathLocked(changePath(0, 0), pk);
  }

  LocalSigner::~LocalSigner() = default;

  std::string LocalSigner::name() const
  {
    return "LocalSigner(" + key_store_.name() + ")";
  }

  bool LocalSigner::isReady() const
  {
    return key_store_.isUnlocked();
  }

  std::vector<Crypto::PublicKey> LocalSigner::publicKeys() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Crypto::PublicKey> out;
    out.reserve(pubkey_to_path_.size());
    for (const auto &kv : pubkey_to_path_)
      out.push_back(kv.first);
    return out;
  }

  std::optional<HdPath> LocalSigner::pathForPubkey(
      const Crypto::PublicKey &pk) const
  {
    auto it = pubkey_to_path_.find(pk);
    if (it == pubkey_to_path_.end())
      return std::nullopt;
    return it->second;
  }

  bool LocalSigner::registerPathLocked(const HdPath &path,
                                       Crypto::PublicKey &out_pubkey)
  {
    // Derive the key. If the key store is locked, derive() fails
    // and we return false.
    auto key = key_store_.derive(path, nullptr);
    if (!key)
      return false;

    out_pubkey = key->pubkey;

    // Cache it. Insertion is idempotent — if the pubkey is already
    // present, we just leave the existing entry.
    pubkey_to_path_.emplace(key->pubkey, path);

    // Wipe the secret half.
    Crypto::secureZero(key->secret.data.data(), 32);
    return true;
  }

  std::optional<Crypto::PublicKey> LocalSigner::registerPath(
      const HdPath &path,
      WalletStatus *error_out)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    Crypto::PublicKey pk;
    if (!registerPathLocked(path, pk))
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreLocked,
            "key store is locked or derive failed");
      return std::nullopt;
    }

    if (error_out)
      *error_out = WalletStatus::success();
    return pk;
  }

  size_t LocalSigner::registerAddressRange(uint32_t account,
                                           uint32_t count,
                                           WalletStatus *error_out)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t registered = 0;
    for (uint32_t i = 0; i < count; ++i)
    {
      Crypto::PublicKey pk;
      if (!registerPathLocked(receivePath(account, i), pk))
      {
        // Stop at the first failure. Common cause: the key store
        // got locked mid-loop, or was never unlocked. Report what
        // we managed to register.
        break;
      }
      ++registered;
    }

    if (error_out)
      *error_out = WalletStatus::success();
    return registered;
  }

  std::optional<Crypto::Signature> LocalSigner::sign(
      const Crypto::PublicKey &pubkey,
      const Crypto::Hash &hash,
      WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<Crypto::Signature>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (!key_store_.isUnlocked())
      return fail(WalletError::KeyStoreLocked, "key store is locked");

    // Find the path for this public key.
    HdPath path;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto p = pathForPubkey(pubkey);
      if (!p)
      {
        return fail(WalletError::KeyNotInStore,
                    "public key is not registered with this signer");
      }
      path = *p;
    }

    // Derive the secret key for that path, sign, wipe.
    auto key = key_store_.derive(path, error_out);
    if (!key)
      return std::nullopt;

    Crypto::Signature sig;
    Crypto::sign(hash, key->secret, sig);

    // Wipe the secret. The signature is derived from it but doesn't
    // reveal it.
    Crypto::secureZero(key->secret.data.data(), 32);

    // Sanity check: the derived public key must match what we were
    // asked to sign for. If it doesn't, the cache is out of sync
    // with the key store, which is a bug.
    if (key->pubkey != pubkey)
    {
      Crypto::secureZero(sig.data.data(), sig.data.size());
      return fail(WalletError::Internal,
                  "key cache inconsistency: derived pubkey mismatch");
    }

    if (error_out)
      *error_out = WalletStatus::success();
    return sig;
  }

  std::optional<Crypto::Signature> LocalSigner::signAtPath(
      const HdPath &path,
      const Crypto::Hash &hash,
      WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<Crypto::Signature>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (!key_store_.isUnlocked())
      return fail(WalletError::KeyStoreLocked, "key store is locked");

    // Derive and sign. Also register the resulting pubkey in the
    // cache, so a subsequent sign(pubkey, hash) works without the
    // caller having to register explicitly.
    auto key = key_store_.derive(path, error_out);
    if (!key)
      return std::nullopt;

    Crypto::Signature sig;
    Crypto::sign(hash, key->secret, sig);

    {
      std::lock_guard<std::mutex> lock(mutex_);
      pubkey_to_path_.emplace(key->pubkey, path);
    }

    Crypto::secureZero(key->secret.data.data(), 32);

    if (error_out)
      *error_out = WalletStatus::success();
    return sig;
  }

} // namespace Wallet