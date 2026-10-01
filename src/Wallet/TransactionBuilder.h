// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "Core/Transaction.h"
#include "Crypto/Types.h"
#include "GlobalConfig.h"
#include "HdPath.h"
#include "WalletError.h"

namespace Wallet
{
  class Signer;

  //  TransactionBuilder
  //
  //  Constructs Core::Transaction objects from typed parameters, and
  //  signs them. This is the layer between "the wallet knows the
  //  account address and has an unlocked signer" and "we have a
  //  serialized transaction to submit."
  //
  //  Design:
  //
  //    - Each build* function fills the transaction's fixed fields
  //      (version, chain_id, tx_type, nonce, fee, from, to) and the
  //      type-specific payload. It does NOT sign.
  //
  //    - signTransaction takes an unsigned transaction and a Signer,
  //      computes the signing hash, calls signAtPath, and copies the
  //      signature in. It's separated so callers can inspect or log
  //      the transaction before signing, and so a future hardware
  //      signer can be plugged in without changing the builders.
  //
  //    - Builders are pure functions: same inputs, same output. No
  //      global state, no clock reads, no chain queries. The chain_id
  //      and nonce are passed in by the caller, who is responsible
  //      for knowing them.
  //
  //  Amounts and fees are in atomic units. Callers that accept
  //  human-readable input should use Wallet::parseAmount() to convert
  //  before calling these functions.
  //
  //  Every builder returns std::nullopt on failure, populating
  //  error_out (if non-null) with a WalletError and a detail string.
  //  Failure modes are parameter validation (zero fee, null address,
  //  oversized payload) — never chain state (the builder doesn't
  //  know the chain).

  //  ---- Common parameters ----
  //
  //  The fields every user-submitted transaction shares. Bundling
  //  them keeps the per-type parameter structs small.

  struct TxCommonParams
  {
    uint64_t chain_id{0};
    uint64_t nonce{0};
    uint64_t fee{0};
    uint64_t valid_until_height{0}; // 0 = no expiry
  };

  //  ---- Transfer ----

  struct TransferParams
  {
    TxCommonParams common;
    Crypto::Address to{};
    Id token_id{NATIVE_TOKEN_ID}; // 0 = native CLRTY
    uint64_t amount{0};
  };

  std::optional<Core::Transaction> buildTransfer(
      const Crypto::Address &from,
      const TransferParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Staking ----
  //
  //  Opt-in, opt-out, and claim-rewards share the same shape: an
  //  empty payload, no `to`, no `amount`. Only the tx_type differs.

  struct StakingParams
  {
    TxCommonParams common;
  };

  std::optional<Core::Transaction> buildOptInStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  std::optional<Core::Transaction> buildOptOutStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  std::optional<Core::Transaction> buildClaimRewards(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Register Validator ----
  //
  //  Payload is the validator's P2P node public key (32 bytes).
  //  The reward address is `from` — the account signing the
  //  registration becomes the validator's reward address.
  //
  //  The stake is `amount` in the transaction. It must be at least
  //  GlobalConfig::VALIDATOR_MIN_STAKE; the executor enforces this,
  //  but the builder checks it too so the caller gets an early error.

  struct RegisterValidatorParams
  {
    TxCommonParams common;
    Crypto::PublicKey node_key{};
    uint64_t stake{0};
  };

  std::optional<Core::Transaction> buildRegisterValidator(
      const Crypto::Address &from,
      const RegisterValidatorParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Unregister Validator ----
  //
  //  Empty payload. The executor looks up the validator by `from`.

  std::optional<Core::Transaction> buildUnregisterValidator(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Update Reward Address ----
  //
  //  Payload is the new reward address (32 bytes). The executor looks
  //  up the validator by `from` — the current reward address — and
  //  rewrites both `reward_address` and `owner` to the new value.
  //
  //  Note: after this transaction, the new address is the one that
  //  controls the validator. The old address can no longer update or
  //  unregister it. This is the current executor behavior and matches
  //  the model where reward_address == owner.

  struct UpdateRewardParams
  {
    TxCommonParams common;
    Crypto::Address new_reward_address{};
  };

  std::optional<Core::Transaction> buildUpdateRewardAddress(
      const Crypto::Address &from,
      const UpdateRewardParams &params,
      WalletStatus *error_out = nullptr);

  //  ---- Sign ----

  //  Compute the transaction's signing hash, ask the signer to sign
  //  it at `path`, and write the signature into tx.signature.
  //
  //  Returns the signing hash on success — which equals the txid —
  //  so the caller can log it or use it to track the transaction.
  //
  //  Requires signer.isReady() to be true. Passes through the
  //  signer's error_out on failure.
  //
  //  Default path is the account-0 receive address at index 0, which
  //  is what the keystore's `address()` field corresponds to.
  std::optional<Crypto::Hash> signTransaction(
      Core::Transaction &tx,
      Signer &signer,
      const HdPath &path = clrtyPath(0, 0, 0),
      WalletStatus *error_out = nullptr);

} // namespace Wallet