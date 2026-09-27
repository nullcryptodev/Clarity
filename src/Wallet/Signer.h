// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "HdPath.h"
#include "WalletError.h"

namespace Wallet
{
  //  Signer — abstract signing interface
  //
  //  A Signer produces Ed25519 signatures for a known set of public
  //  keys. It is deliberately decoupled from KeyStore because not
  //  every signer is backed by a local key store:
  //
  //    LocalSigner      — wraps a KeyStore; keys live in this process
  //    RemoteSigner     — talks to a signing daemon over a socket
  //    HardwareSigner   — HID/BLE to a device; keys never leave it
  //    MultisigSigner   — aggregates partial signatures from children
  //    WatchOnlySigner  — exposes public keys, refuses to sign
  //
  //  The interface is small enough that any of those can implement it
  //  with minimal effort. All methods are synchronous and thread-safe.

  class Signer
  {
  public:
    virtual ~Signer() = default;

    Signer(const Signer &) = delete;
    Signer &operator=(const Signer &) = delete;

    // ---- Identity ----

    // Human-readable name for logs and diagnostics. Not used
    // programmatically.
    virtual std::string name() const = 0;

    // ---- Capabilities ----

    // Is the signer currently able to sign?
    //
    // For LocalSigner, true iff the underlying KeyStore is unlocked.
    // For hardware, true iff the device is connected and ready.
    // For remote, true iff the daemon is reachable.
    //
    // Does not perform any network I/O; a cached state is fine.
    virtual bool isReady() const = 0;

    // List of public keys this signer can produce signatures for.
    //
    // For HD-backed signers, this is the set of public keys the
    // signer is willing to sign for — typically the account-level
    // keys at (account, 0, 0) and (account, 1, 0), plus any keys
    // the caller has derived and registered with the signer.
    //
    // Watch-only signers return their public keys but isReady() is
    // false and sign() fails.
    virtual std::vector<Crypto::PublicKey> publicKeys() const = 0;

    // ---- Signing ----

    // Sign a 32-byte hash with the private key corresponding to
    // `pubkey`.
    //
    // Returns std::nullopt on failure. Failure modes:
    //   - isReady() is false (locked, disconnected)
    //   - pubkey is not one this signer knows about
    //   - the underlying signing operation failed
    //
    // On failure, `error_out` (if non-null) is set to a WalletError
    // code and a human-readable detail.
    //
    // For remote or hardware signers, this may block for a
    // meaningful amount of time. Callers should not hold locks
    // across this call.
    virtual std::optional<Crypto::Signature> sign(
        const Crypto::PublicKey &pubkey,
        const Crypto::Hash &hash,
        WalletStatus *error_out = nullptr) = 0;

    // Batch variant: sign multiple hashes with the same key in one
    // call. Default implementation loops. Hardware signers may
    // override to send a single APDU.
    virtual std::vector<std::optional<Crypto::Signature>> signBatch(
        const Crypto::PublicKey &pubkey,
        const std::vector<Crypto::Hash> &hashes,
        WalletStatus *error_out = nullptr);

    //  Extended variant: sign with a key derived at a given path.
    //
    //  The base interface assumes the caller has already registered
    //  or identified the public key they want to sign with. For
    //  HD-backed signers, callers may want to derive-then-sign in one
    //  step. This method is optional; the default implementation
    //  derives the key from `path` (if it can), checks the pubkey
    //  matches, then calls sign().
    //
    //  Signers that can't derive (hardware, remote) return
    //  std::nullopt with WalletError::SignerRejected.
    virtual std::optional<Crypto::Signature> signAtPath(
        const HdPath &path,
        const Crypto::Hash &hash,
        WalletStatus *error_out = nullptr)
    {
      (void)path;
      (void)hash;
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::SignerRejected,
            "signAtPath not supported by this signer");
      return std::nullopt;
    }

  protected:
    Signer() = default;
  };

} // namespace Wallet