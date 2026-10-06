// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

namespace Wallet
{
  //  Error codes
  //
  //  Every wallet API that can fail returns one of these. Errors are
  //  values, not exceptions; the wallet is used from RPC handlers,
  //  GUI event loops, and CLI parsers where exceptions are inconvenient.
  //
  //  Categories:
  //    - Input validation (Bad*, Invalid*)
  //    - Keystore (KeyStore*, WrongPassword)
  //    - Derivation (Derivation*)
  //    - Signing (Sign*)
  //    - Chain access (Chain*, NotFound)
  //    - Wallet state (Locked, NotInitialized, AlreadyExists)
  //    - Internal (Internal)

  enum class WalletError
  {
    Ok = 0,

    // Input validation
    BadArgument,
    InvalidMnemonic,
    InvalidWordCount,
    InvalidWord,
    InvalidChecksum,
    InvalidPath,
    InvalidAddress,
    InvalidAmount,
    InvalidNetwork,
    InvalidHex,
    InvalidPubkey,
    InvalidSignature,
    InvalidParameter,

    // Keystore
    KeyStoreNotFound,
    KeyStoreCorrupt,
    KeyStoreUnsupportedVersion,
    KeyStoreUnsupportedKdf,
    KeyStoreUnsupportedCipher,
    WrongPassword,
    KeyStoreLocked,

    // Derivation
    DerivationFailed,
    DerivationIndexOutOfRange,
    DerivationSeedFingerprintMismatch,

    // Signing
    SigningFailed,
    SignerNotReady,
    SignerRejected,
    KeyNotInStore,

    // Chain access
    ChainNotConnected,
    ChainError,
    TransactionRejected,
    TransactionNotFound,
    AccountNotFound,
    InsufficientFunds,
    NonceConflict,

    // Wallet state
    NotInitialized,
    AlreadyInitialized,
    AlreadyExists,
    NotFound,
    Locked,

    // Proof / light-client verification
    ProofVerificationFailed,
    RootDisagreement,
    NoTrustedRoot,
    PeerUnreachable,

    // Internal
    Internal,
  };

  // Human-readable name (for logs and error strings).
  const char *walletErrorName(WalletError e) noexcept;

  // Human-readable description (for user-facing messages).
  const char *walletErrorMessage(WalletError e) noexcept;

  // A WalletError plus an optional free-form detail string. The detail
  // is meant for logs; the code is what callers switch on.
  struct WalletStatus
  {
    WalletError code{WalletError::Ok};
    std::string detail;

    bool ok() const noexcept { return code == WalletError::Ok; }
    explicit operator bool() const noexcept { return ok(); }

    static WalletStatus success() { return {}; }
    static WalletStatus fail(WalletError c, std::string d = {})
    {
      return WalletStatus{c, std::move(d)};
    }
  };

} // namespace Wallet