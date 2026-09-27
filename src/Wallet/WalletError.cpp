// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletError.h"

namespace Wallet
{
  const char *walletErrorName(WalletError e) noexcept
  {
    switch (e)
    {
    case WalletError::Ok:
      return "Ok";

    case WalletError::BadArgument:
      return "BadArgument";
    case WalletError::InvalidMnemonic:
      return "InvalidMnemonic";
    case WalletError::InvalidWordCount:
      return "InvalidWordCount";
    case WalletError::InvalidWord:
      return "InvalidWord";
    case WalletError::InvalidChecksum:
      return "InvalidChecksum";
    case WalletError::InvalidPath:
      return "InvalidPath";
    case WalletError::InvalidAddress:
      return "InvalidAddress";
    case WalletError::InvalidAmount:
      return "InvalidAmount";
    case WalletError::InvalidNetwork:
      return "InvalidNetwork";
    case WalletError::InvalidHex:
      return "InvalidHex";
    case WalletError::InvalidPubkey:
      return "InvalidPubkey";
    case WalletError::InvalidSignature:
      return "InvalidSignature";

    case WalletError::KeyStoreNotFound:
      return "KeyStoreNotFound";
    case WalletError::KeyStoreCorrupt:
      return "KeyStoreCorrupt";
    case WalletError::KeyStoreUnsupportedVersion:
      return "KeyStoreUnsupportedVersion";
    case WalletError::KeyStoreUnsupportedKdf:
      return "KeyStoreUnsupportedKdf";
    case WalletError::KeyStoreUnsupportedCipher:
      return "KeyStoreUnsupportedCipher";
    case WalletError::WrongPassword:
      return "WrongPassword";
    case WalletError::KeyStoreLocked:
      return "KeyStoreLocked";

    case WalletError::DerivationFailed:
      return "DerivationFailed";
    case WalletError::DerivationIndexOutOfRange:
      return "DerivationIndexOutOfRange";
    case WalletError::DerivationSeedFingerprintMismatch:
      return "DerivationSeedFingerprintMismatch";

    case WalletError::SigningFailed:
      return "SigningFailed";
    case WalletError::SignerNotReady:
      return "SignerNotReady";
    case WalletError::SignerRejected:
      return "SignerRejected";
    case WalletError::KeyNotInStore:
      return "KeyNotInStore";

    case WalletError::ChainNotConnected:
      return "ChainNotConnected";
    case WalletError::ChainError:
      return "ChainError";
    case WalletError::TransactionRejected:
      return "TransactionRejected";
    case WalletError::TransactionNotFound:
      return "TransactionNotFound";
    case WalletError::AccountNotFound:
      return "AccountNotFound";
    case WalletError::InsufficientFunds:
      return "InsufficientFunds";
    case WalletError::NonceConflict:
      return "NonceConflict";

    case WalletError::NotInitialized:
      return "NotInitialized";
    case WalletError::AlreadyInitialized:
      return "AlreadyInitialized";
    case WalletError::AlreadyExists:
      return "AlreadyExists";
    case WalletError::NotFound:
      return "NotFound";
    case WalletError::Locked:
      return "Locked";

    case WalletError::Internal:
      return "Internal";
    }
    return "Unknown";
  }

  const char *walletErrorMessage(WalletError e) noexcept
  {
    switch (e)
    {
    case WalletError::Ok:
      return "Success";

    case WalletError::BadArgument:
      return "Invalid argument";
    case WalletError::InvalidMnemonic:
      return "Mnemonic is not valid";
    case WalletError::InvalidWordCount:
      return "Mnemonic has an invalid number of words";
    case WalletError::InvalidWord:
      return "Mnemonic contains a word not in the wordlist";
    case WalletError::InvalidChecksum:
      return "Mnemonic checksum does not match";
    case WalletError::InvalidPath:
      return "Derivation path is malformed";
    case WalletError::InvalidAddress:
      return "Address is not valid";
    case WalletError::InvalidAmount:
      return "Amount is not valid";
    case WalletError::InvalidNetwork:
      return "Network is not recognized";
    case WalletError::InvalidHex:
      return "Hex string is malformed";
    case WalletError::InvalidPubkey:
      return "Public key is not valid";
    case WalletError::InvalidSignature:
      return "Signature is not valid";

    case WalletError::KeyStoreNotFound:
      return "Keystore file not found";
    case WalletError::KeyStoreCorrupt:
      return "Keystore is corrupt or truncated";
    case WalletError::KeyStoreUnsupportedVersion:
      return "Keystore version is not supported";
    case WalletError::KeyStoreUnsupportedKdf:
      return "Keystore uses an unsupported KDF";
    case WalletError::KeyStoreUnsupportedCipher:
      return "Keystore uses an unsupported cipher";
    case WalletError::WrongPassword:
      return "Password is incorrect";
    case WalletError::KeyStoreLocked:
      return "Keystore is locked";

    case WalletError::DerivationFailed:
      return "Key derivation failed";
    case WalletError::DerivationIndexOutOfRange:
      return "Derivation index out of range";
    case WalletError::DerivationSeedFingerprintMismatch:
      return "Seed does not match keystore fingerprint";

    case WalletError::SigningFailed:
      return "Signing failed";
    case WalletError::SignerNotReady:
      return "Signer is not ready";
    case WalletError::SignerRejected:
      return "Signer rejected the request";
    case WalletError::KeyNotInStore:
      return "Key is not present in the store";

    case WalletError::ChainNotConnected:
      return "Not connected to a chain";
    case WalletError::ChainError:
      return "Chain access error";
    case WalletError::TransactionRejected:
      return "Transaction was rejected";
    case WalletError::TransactionNotFound:
      return "Transaction not found";
    case WalletError::AccountNotFound:
      return "Account not found";
    case WalletError::InsufficientFunds:
      return "Insufficient funds";
    case WalletError::NonceConflict:
      return "Nonce conflict";

    case WalletError::NotInitialized:
      return "Wallet is not initialized";
    case WalletError::AlreadyInitialized:
      return "Wallet is already initialized";
    case WalletError::AlreadyExists:
      return "Object already exists";
    case WalletError::NotFound:
      return "Object not found";
    case WalletError::Locked:
      return "Wallet is locked";

    case WalletError::Internal:
      return "Internal error";
    }
    return "Unknown error";
  }

} // namespace Wallet