// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionBuilder.h"

#include "Signer.h"

#include "Core/TransactionTypes.h"

#include <cstring>

namespace Wallet
{
  namespace
  {
    //  Common validation applied to every user-submitted transaction.
    //  Builders call this first, then apply type-specific checks.
    //
    //  The executor will re-check all of these on-chain; the builder
    //  checks them so the user gets an error before signing, not after.
    bool validateCommon(const Crypto::Address &from,
                        const TxCommonParams &common,
                        WalletStatus *error_out)
    {
      if (from.isNull())
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "from address is null");
        return false;
      }

      if (common.chain_id == 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "chain_id is zero");
        return false;
      }

      if (common.fee == 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "fee must be non-zero");
        return false;
      }

      return true;
    }

    //  Build a transaction skeleton. The builder fills in the type,
    //  common fields, and payload; the type-specific code fills in
    //  `to`, `amount`, `token_id` if it uses them.
    Core::Transaction makeBase(Core::TxType type,
                               const Crypto::Address &from,
                               const TxCommonParams &common)
    {
      Core::Transaction tx;
      tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
      tx.chain_id = common.chain_id;
      tx.tx_type = type;
      tx.nonce = common.nonce;
      tx.valid_until_height = common.valid_until_height;
      tx.from = from;
      // tx.to, token_id, amount, fee left at defaults; caller fills.
      tx.fee = common.fee;
      return tx;
    }
  } // anonymous namespace

  //  ---- Transfer ----

  std::optional<Core::Transaction> buildTransfer(
      const Crypto::Address &from,
      const TransferParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.to.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "transfer destination is null");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "transfer amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::Transfer, from, params.common);
    tx.to = params.to;
    tx.token_id = params.token_id;
    tx.amount = params.amount;
    // Payload is empty: the executor reads `to`, `token_id`, and
    // `amount` from the fixed fields.

    return tx;
  }

  //  ---- Staking (opt-in / opt-out / claim) ----

  namespace
  {
    std::optional<Core::Transaction> buildStakingTx(
        Core::TxType type,
        const Crypto::Address &from,
        const StakingParams &params,
        WalletStatus *error_out)
    {
      if (!validateCommon(from, params.common, error_out))
        return std::nullopt;

      Core::Transaction tx = makeBase(type, from, params.common);
      // No `to`, no `amount`, no payload. The executor uses `from`
      // to identify the account and does the rest itself.
      return tx;
    }
  } // anonymous namespace

  std::optional<Core::Transaction> buildOptInStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    return buildStakingTx(Core::TxType::OptInStaking,
                          from, params, error_out);
  }

  std::optional<Core::Transaction> buildOptOutStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    return buildStakingTx(Core::TxType::OptOutStaking,
                          from, params, error_out);
  }

  std::optional<Core::Transaction> buildClaimRewards(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    return buildStakingTx(Core::TxType::ClaimRewards,
                          from, params, error_out);
  }

  //  ---- Register Validator ----

  std::optional<Core::Transaction> buildRegisterValidator(
      const Crypto::Address &from,
      const RegisterValidatorParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.node_key.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "validator node key is null");
      return std::nullopt;
    }

    if (params.stake < GlobalConfig::VALIDATOR_MIN_STAKE)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "stake below VALIDATOR_MIN_STAKE");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::RegisterValidator, from, params.common);
    // The stake moves from the sender's balance into the validator
    // record. It goes in `amount`.
    tx.amount = params.stake;
    // The payload carries the P2P node key (32 bytes).
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(),
                params.node_key.data.data(),
                params.node_key.data.size());
    return tx;
  }

  //  ---- Unregister Validator ----

  std::optional<Core::Transaction> buildUnregisterValidator(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    Core::Transaction tx =
        makeBase(Core::TxType::UnregisterValidator, from, params.common);
    // Empty payload. The executor looks up the validator by `from`.
    return tx;
  }

  //  ---- Update Reward Address ----

  std::optional<Core::Transaction> buildUpdateRewardAddress(
      const Crypto::Address &from,
      const UpdateRewardParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.new_reward_address.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new reward address is null");
      return std::nullopt;
    }

    if (params.new_reward_address == from)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new reward address equals current address");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::UpdateRewardAddress, from, params.common);
    // The payload carries the new reward address (32 bytes).
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(),
                params.new_reward_address.data.data(),
                params.new_reward_address.data.size());
    return tx;
  }

  //  ---- Sign ----

  std::optional<Crypto::Hash> signTransaction(
      Core::Transaction &tx,
      Signer &signer,
      const HdPath &path,
      WalletStatus *error_out)
  {
    if (!signer.isReady())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreLocked,
            "signer is not ready");
      return std::nullopt;
    }

    // The signing hash commits to every field except the signature
    // itself. See Transaction::signingHash().
    const Crypto::Hash hash = tx.signingHash();

    // Derive-and-sign in one call. The signer handles the derivation
    // path and the signature format.
    auto sig = signer.signAtPath(path, hash, error_out);
    if (!sig.has_value())
      return std::nullopt;

    tx.signature = *sig;
    return hash;
  }

} // namespace Wallet