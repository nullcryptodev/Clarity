// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionExecutor.h"

#include "ActiveRouter.h"
#include "AmmPool.h"
#include "AmmPosition.h"
#include "BlockProcessor.h"
#include "Order.h"
#include "TokenTypes.h"
#include "ValidatorTypes.h"
#include "GlobalState.h"
#include "RewardTypes.h"
#include "KeyRotation.h"

#include "State/StateAccess.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include <algorithm>
#include <cstring>

namespace Core
{

  //  Dispatch

  Receipt TransactionExecutor::execute(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // ---- Structural validation ----
    if (!tx.isWellFormed())
    {
      return failure;
    }

    // ---- Chain ID ----
    if (tx.chain_id != ctx.chain_id)
    {
      return failure;
    }

    // ---- Expiry ----
    if (!checkExpiry(tx, ctx))
    {
      return failure;
    }

    // ---- Signature ----
    if (!verifySignature(tx))
    {
      return failure;
    }

    // ---- Nonce ----
    if (!verifyNonce(state, tx))
    {
      return failure;
    }

    // ---- Fee charge ----
    // Charge fee before dispatch. If the sender can't pay, fail.
    if (!chargeFee(state, tx))
    {
      return failure;
    }

    // ---- Dispatch by type ----
    Receipt receipt{ReceiptStatus::Failure, tx.fee};

    switch (tx.tx_type)
    {
    case TxType::Transfer:
      receipt = executeTransfer(state, tx, ctx);
      break;

    case TxType::OptInStaking:
      receipt = executeOptInStaking(state, tx, ctx);
      break;

    case TxType::OptOutStaking:
      receipt = executeOptOutStaking(state, tx, ctx);
      break;

    case TxType::ClaimRewards:
      receipt = executeClaimRewards(state, tx, ctx);
      break;

    case TxType::RegisterValidator:
      receipt = executeRegisterValidator(state, tx, ctx);
      break;

    case TxType::UnregisterValidator:
      receipt = executeUnregisterValidator(state, tx, ctx);
      break;

    case TxType::UpdateRewardAddress:
      receipt = executeUpdateRewardAddress(state, tx, ctx);
      break;

    case TxType::RotateConsensusKey:
      receipt = executeRotateConsensusKey(state, tx, ctx);
      break;

    case TxType::CreateToken:
      receipt = executeCreateToken(state, tx, ctx);
      break;

    case TxType::MintToken:
      receipt = executeMintToken(state, tx, ctx);
      break;

    case TxType::BurnToken:
      receipt = executeBurnToken(state, tx, ctx);
      break;

    case TxType::UpdateTokenMeta:
      receipt = executeUpdateTokenMeta(state, tx, ctx);
      break;

    case TxType::CreatePool:
      receipt = executeCreatePool(state, tx, ctx);
      break;

    case TxType::AddLiquidity:
      receipt = executeAddLiquidity(state, tx, ctx);
      break;

    case TxType::RemoveLiquidity:
      receipt = executeRemoveLiquidity(state, tx, ctx);
      break;

    case TxType::Swap:
      receipt = executeSwap(state, tx, ctx);
      break;

    case TxType::CreateOrder:
      receipt = executeCreateOrder(state, tx, ctx);
      break;

    case TxType::CancelOrder:
      receipt = executeCancelOrder(state, tx, ctx);
      break;

    default:
      // Unhandled type — fail.
      return failure;
    }

    // ---- Nonce bump on success ----
    if (receipt.status == ReceiptStatus::Success)
    {
      bumpNonce(state, tx);
    }

    return receipt;
  }

  //  Common helpers

  bool TransactionExecutor::verifySignature(const Transaction &tx)
  {
    Crypto::Hash hash = tx.signingHash();
    return Crypto::verify(hash, tx.from, tx.signature);
  }

  bool TransactionExecutor::verifyNonce(State::StateAccess &state,
                                        const Transaction &tx)
  {
    Account acct = state.getAccount(tx.from);
    return acct.nonce == tx.nonce;
  }

  bool TransactionExecutor::checkExpiry(const Transaction &tx,
                                        const TxExecutionContext &ctx)
  {
    if (tx.valid_until_height == 0)
      return true;
    return ctx.current_height <= tx.valid_until_height;
  }

  bool TransactionExecutor::chargeFee(State::StateAccess &state,
                                      const Transaction &tx)
  {
    Account sender = state.getAccount(tx.from);

    if (sender.balance < tx.fee)
    {
      return false;
    }

    sender.balance -= tx.fee;
    state.putAccount(tx.from, sender);
    return true;
  }

  void TransactionExecutor::refundFee(State::StateAccess &state,
                                      const Transaction &tx)
  {
    Account sender = state.getAccount(tx.from);
    sender.balance += tx.fee;
    state.putAccount(tx.from, sender);
  }

  void TransactionExecutor::bumpNonce(State::StateAccess &state,
                                      const Transaction &tx)
  {
    Account sender = state.getAccount(tx.from);
    sender.nonce++;
    state.putAccount(tx.from, sender);
  }

  std::vector<Id> TransactionExecutor::loadActiveSet(
      State::StateAccess &state)
  {
    std::vector<Id> result;

    std::vector<uint8_t> set_bytes;
    if (!state.getGlobal("active_set", set_bytes))
      return result;

    size_t count = set_bytes.size() / 8;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t id = 0;
      for (int j = 0; j < 8; ++j)
        id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
      result.push_back(id);
    }

    return result;
  }

  void TransactionExecutor::saveActiveSet(
      State::StateAccess &state,
      const std::vector<Id> &active_set)
  {
    std::vector<uint8_t> set_bytes;
    set_bytes.reserve(active_set.size() * 8);
    for (auto vid : active_set)
    {
      for (int i = 0; i < 8; ++i)
        set_bytes.push_back(uint8_t(vid >> (i * 8)));
    }
    state.putGlobal("active_set", set_bytes);
  }

  //  Transfer

  Receipt TransactionExecutor::executeTransfer(State::StateAccess &state,
                                               const Transaction &tx,
                                               const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.amount == 0)
      return failure;
    if (tx.to.isNull())
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
    {
      Account sender = state.getAccount(tx.from);

      if (sender.balance < tx.amount)
        return failure;

      sender.balance -= tx.amount;
      state.putAccount(tx.from, sender);

      Account receiver = state.getAccount(tx.to);
      receiver.balance += tx.amount;
      if (receiver.created_at_height == 0)
      {
        receiver.created_at_height = ctx.current_height;
      }
      state.putAccount(tx.to, receiver);

      return {ReceiptStatus::Success, tx.fee};
    }

    uint64_t sender_balance = state.getTokenBalance(tx.from, tx.token_id);
    if (sender_balance < tx.amount)
      return failure;

    state.putTokenBalance(tx.from, tx.token_id, sender_balance - tx.amount);

    uint64_t receiver_balance = state.getTokenBalance(tx.to, tx.token_id);
    state.putTokenBalance(tx.to, tx.token_id, receiver_balance + tx.amount);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Opt-In Staking

  Receipt TransactionExecutor::executeOptInStaking(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext & /*ctx*/)
  {
    Account acct = state.getAccount(tx.from);
    acct.staking_opted_out = false;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Opt-Out Staking

  Receipt TransactionExecutor::executeOptOutStaking(State::StateAccess &state,
                                                    const Transaction &tx,
                                                    const TxExecutionContext & /*ctx*/)
  {
    Account acct = state.getAccount(tx.from);
    acct.staking_opted_out = true;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Claim Rewards

  Receipt TransactionExecutor::executeClaimRewards(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext & /*ctx*/)
  {
    Account acct = state.getAccount(tx.from);

    acct.balance += acct.pending_rewards;
    acct.pending_rewards = 0;

    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);

    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Register Validator

  Receipt TransactionExecutor::executeRegisterValidator(State::StateAccess &state,
                                                        const Transaction &tx,
                                                        const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    Account acct = state.getAccount(tx.from);

    if (acct.balance < GlobalConfig::VALIDATOR_MIN_STAKE)
      return failure;

    if (tx.payload.size() != 32)
      return failure;

    uint64_t existing_id = 0;
    if (state.getValidatorByAddress(tx.from, existing_id))
      return failure;

    std::vector<uint8_t> id_bytes;
    if (!state.getGlobal("next_validator_id", id_bytes))
    {
      id_bytes.resize(8, 0);
      id_bytes[0] = 1;
    }

    uint64_t next_id = 0;
    for (int i = 0; i < 8; ++i)
    {
      if (i < (int)id_bytes.size())
      {
        next_id |= uint64_t(id_bytes[i]) << (i * 8);
      }
    }

    ValidatorInfo validator;
    validator.id = next_id;
    validator.reward_address = tx.from;
    validator.owner = tx.from;
    validator.stake = acct.balance;
    validator.registered_at_height = ctx.current_height;
    validator.uptime_score = 10'000;
    validator.is_seed = false;
    validator.is_active = false;
    std::memcpy(validator.consensus_key.data.data(), tx.payload.data(), 32);

    state.putValidator(validator);
    state.putValidatorByAddress(validator.reward_address, validator.id);

    //  Initialize the key history with a single entry covering
    //  from registration onward. The initial signing key is
    //  whatever the record carries, which for a fresh
    //  registration is the payload key.
    {
      std::vector<Core::KeyRotation> history;
      Core::KeyRotation entry;
      entry.key = validator.effectiveConsensusKey();
      entry.valid_from_height = ctx.current_height;
      entry.valid_until_height = 0;
      history.push_back(entry);
      state.putValidatorKeyHistory(validator.id, history);
    }

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_validator_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Unregister Validator

  Receipt TransactionExecutor::executeUnregisterValidator(State::StateAccess &state,
                                                          const Transaction &tx,
                                                          const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    if (validator.is_seed)
      return failure;

    std::vector<Id> active_set = loadActiveSet(state);
    const bool was_active =
        std::find(active_set.begin(), active_set.end(), validator_id) !=
        active_set.end();

    if (was_active)
    {
      std::vector<Id> new_set;
      new_set.reserve(active_set.size());
      for (auto vid : active_set)
      {
        if (vid != validator_id)
          new_set.push_back(vid);
      }

      if (new_set.size() < GlobalConfig::ACTIVE_SET_MIN)
        return failure;

      saveActiveSet(state, new_set);
    }

    if (validator.pending_unbond_height != 0)
      return failure;

    validator.is_active = false;
    validator.last_active_at = ctx.current_height;
    validator.pending_unbond_height = ctx.current_height + UNBONDING_PERIOD;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Update Reward Address

  Receipt TransactionExecutor::executeUpdateRewardAddress(State::StateAccess &state,
                                                          const Transaction &tx,
                                                          const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 32)
      return failure;

    Crypto::Address new_address;
    std::memcpy(new_address.data.data(), tx.payload.data(), 32);

    if (new_address.isNull())
      return failure;

    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    if (new_address != tx.from)
    {
      uint64_t collision = 0;
      if (state.getValidatorByAddress(new_address, collision))
        return failure;
    }

    if (validator.consensus_key.isNull())
      validator.consensus_key = validator.effectiveConsensusKey();

    state.deleteValidatorByAddress(validator.reward_address);
    state.putValidatorByAddress(new_address, validator.id);

    validator.reward_address = new_address;
    validator.owner = new_address;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Rotate Consensus Key

  Receipt TransactionExecutor::executeRotateConsensusKey(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 32)
      return failure;

    Crypto::PublicKey new_key;
    std::memcpy(new_key.data.data(), tx.payload.data(), 32);

    if (new_key.isNull())
      return failure;

    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    //  Only the owner can rotate. In current deployments the owner
    //  and reward_address are the same; the check is written
    //  against owner so the invariant survives a future split.
    if (validator.owner != tx.from)
      return failure;

    //  A no-op rotation is a user error. effectiveConsensusKey()
    //  returns the current signing key whether it's the explicit
    //  consensus_key or the reward_address fallback.
    if (validator.effectiveConsensusKey() == new_key)
      return failure;

    //  A departing validator should not extend its signing window.
    if (validator.pending_unbond_height != 0)
      return failure;

    //  Load the current history. If it doesn't exist (a validator
    //  registered before the feature existed, or a record whose
    //  history was never written), synthesize a single-entry
    //  history covering from registration onward using the
    //  record's current key. This migration path keeps every
    //  pre-feature validator working through the first rotation.
    std::vector<Core::KeyRotation> history;
    if (!state.getValidatorKeyHistory(validator_id, history) ||
        history.empty())
    {
      history.clear();
      Core::KeyRotation initial;
      initial.key = validator.effectiveConsensusKey();
      initial.valid_from_height = validator.registered_at_height;
      initial.valid_until_height = 0;
      history.push_back(initial);
    }

    //  Seal the previous last entry at the rotation height.
    history.back().valid_until_height = ctx.current_height;

    //  Append the new entry.
    Core::KeyRotation entry;
    entry.key = new_key;
    entry.valid_from_height = ctx.current_height;
    entry.valid_until_height = 0;
    history.push_back(entry);

    state.putValidatorKeyHistory(validator_id, history);

    //  Update the record's cached key.
    validator.consensus_key = new_key;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Token

  Receipt TransactionExecutor::executeCreateToken(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 3)
      return failure;

    size_t off = 0;
    uint8_t decimals = tx.payload[off++];
    uint8_t backing = tx.payload[off++];
    uint8_t name_len = tx.payload[off++];

    if (off + name_len + 1 > tx.payload.size())
      return failure;
    std::string name(reinterpret_cast<const char *>(tx.payload.data() + off), name_len);
    off += name_len;

    uint8_t sym_len = tx.payload[off++];
    if (off + sym_len + 8 + 2 + 1 > tx.payload.size())
      return failure;
    std::string symbol(reinterpret_cast<const char *>(tx.payload.data() + off), sym_len);
    off += sym_len;

    uint64_t max_supply = 0;
    for (int i = 0; i < 8; ++i)
      max_supply |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint16_t royalty_bps = uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;

    uint8_t has_fp = tx.payload[off++];
    std::optional<Crypto::Hash> fingerprint;
    if (has_fp)
    {
      if (off + 32 > tx.payload.size())
        return failure;
      Crypto::Hash fp;
      std::memcpy(fp.data.data(), tx.payload.data() + off, 32);
      off += 32;
      fingerprint = fp;
    }

    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_token_id", id_bytes);
    uint64_t next_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_id = 1;

    TokenInfo token;
    token.id = static_cast<Id>(next_id);
    token.name = name;
    token.symbol = symbol;
    token.decimals = decimals;
    token.creator = tx.from;
    token.backing = static_cast<BackingModel>(backing);
    token.maxSupply = max_supply;
    token.royaltyBps = royalty_bps;
    token.fingerprint = fingerprint;

    if (!token.isValid())
      return failure;

    state.putToken(token);
    state.putTokenSupply(token.id, 0);

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_token_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Mint Token

  Receipt TransactionExecutor::executeMintToken(State::StateAccess &state,
                                                const Transaction &tx,
                                                const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.amount == 0)
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    if (token.creator != tx.from)
      return failure;

    uint64_t current_supply = state.getTokenSupply(tx.token_id);

    if (token.maxSupply > 0 && current_supply + tx.amount > token.maxSupply)
      return failure;

    uint64_t recipient_balance = state.getTokenBalance(tx.to, tx.token_id);
    state.putTokenBalance(tx.to, tx.token_id, recipient_balance + tx.amount);

    state.putTokenSupply(tx.token_id, current_supply + tx.amount);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Burn Token

  Receipt TransactionExecutor::executeBurnToken(State::StateAccess &state,
                                                const Transaction &tx,
                                                const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.amount == 0)
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    uint64_t sender_balance = state.getTokenBalance(tx.from, tx.token_id);
    if (sender_balance < tx.amount)
      return failure;

    state.putTokenBalance(tx.from, tx.token_id, sender_balance - tx.amount);

    uint64_t current_supply = state.getTokenSupply(tx.token_id);
    uint64_t new_supply = (current_supply >= tx.amount)
                              ? current_supply - tx.amount
                              : 0;
    state.putTokenSupply(tx.token_id, new_supply);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Update Token Meta

  Receipt TransactionExecutor::executeUpdateTokenMeta(State::StateAccess &state,
                                                      const Transaction &tx,
                                                      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 4)
      return failure;

    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    if (token.creator != tx.from)
      return failure;

    size_t off = 0;
    uint8_t name_len = tx.payload[off++];
    if (off + name_len + 1 > tx.payload.size())
      return failure;

    std::string new_name(reinterpret_cast<const char *>(tx.payload.data() + off),
                         name_len);
    off += name_len;

    uint8_t sym_len = tx.payload[off++];
    if (off + sym_len + 2 > tx.payload.size())
      return failure;

    std::string new_symbol(reinterpret_cast<const char *>(tx.payload.data() + off),
                           sym_len);
    off += sym_len;

    uint16_t new_royalty = uint16_t(tx.payload[off]) |
                           (uint16_t(tx.payload[off + 1]) << 8);

    TokenInfo updated = token;
    if (name_len > 0)
      updated.name = new_name;
    if (sym_len > 0)
      updated.symbol = new_symbol;
    if (new_royalty != 0)
      updated.royaltyBps = new_royalty;

    if (!updated.isValid())
      return failure;

    state.putToken(updated);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Pool

  Receipt TransactionExecutor::executeCreatePool(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 14)
      return failure;

    size_t off = 0;
    uint32_t token_b = uint32_t(tx.payload[off]) | (uint32_t(tx.payload[off + 1]) << 8) | (uint32_t(tx.payload[off + 2]) << 16) | (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t amount_b = 0;
    for (int i = 0; i < 8; ++i)
      amount_b |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint16_t fee_bps = uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);

    uint32_t token_a = tx.token_id;
    uint64_t amount_a = tx.amount;

    if (token_a == token_b)
      return failure;
    if (amount_a == 0 || amount_b == 0)
      return failure;
    if (fee_bps > AMM_MAX_FEE_BPS)
      return failure;

    if (token_a > token_b)
    {
      std::swap(token_a, token_b);
      std::swap(amount_a, amount_b);
    }

    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_pool_id", id_bytes);
    uint64_t next_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_id = 1;

    AmmPool pool;
    pool.id = next_id;
    pool.creator = tx.from;
    pool.token_a = token_a;
    pool.token_b = token_b;
    pool.reserve_a = amount_a;
    pool.reserve_b = amount_b;
    pool.fee_bps = fee_bps;
    pool.created_at_height = ctx.current_height;
    pool.active = true;

    __uint128_t prod = static_cast<__uint128_t>(amount_a) * amount_b;
    uint64_t initial_liq = 1;
    while (initial_liq <= prod / (initial_liq + 1))
      ++initial_liq;
    pool.total_liquidity = initial_liq;

    if (!pool.isValid())
      return failure;

    if (token_a == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_a)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_a);
      if (bal < amount_a)
        return failure;
    }

    if (token_b == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_b)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_b);
      if (bal < amount_b)
        return failure;
    }

    if (token_a == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_a;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_a);
      state.putTokenBalance(tx.from, token_a, bal - amount_a);
    }

    if (token_b == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_b;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_b);
      state.putTokenBalance(tx.from, token_b, bal - amount_b);
    }

    state.putAmmPool(pool);

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_pool_id", new_id_bytes);

    std::vector<uint8_t> pos_id_bytes;
    state.getGlobal("next_position_id", pos_id_bytes);
    uint64_t next_pos_id = 1;
    for (int i = 0; i < 8 && i < (int)pos_id_bytes.size(); ++i)
    {
      next_pos_id |= uint64_t(pos_id_bytes[i]) << (i * 8);
    }
    if (pos_id_bytes.empty())
      next_pos_id = 1;

    AmmPosition pos;
    pos.id = next_pos_id;
    pos.owner = tx.from;
    pos.pool_id = pool.id;
    pos.liquidity = initial_liq;
    pos.created_at_height = ctx.current_height;
    state.putAmmPosition(pos);

    state.putPositionIndex(tx.from, pool.id, next_pos_id);

    uint64_t new_pos_next = next_pos_id + 1;
    std::vector<uint8_t> new_pos_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_pos_id_bytes[i] = uint8_t(new_pos_next >> (i * 8));
    state.putGlobal("next_position_id", new_pos_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Add Liquidity

  Receipt TransactionExecutor::executeAddLiquidity(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 16)
      return failure;

    size_t off = 0;
    uint64_t pool_id = 0;
    for (int i = 0; i < 8; ++i)
      pool_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint64_t amount_b = 0;
    for (int i = 0; i < 8; ++i)
      amount_b |= uint64_t(tx.payload[off + i]) << (i * 8);

    AmmPool pool;
    if (!state.getAmmPool(pool_id, pool))
      return failure;
    if (!pool.active)
      return failure;

    Id token_in = tx.token_id;
    Id token_other = (token_in == pool.token_a) ? pool.token_b : pool.token_a;
    if (token_in != pool.token_a && token_in != pool.token_b)
      return failure;

    uint64_t amount_in = tx.amount;

    if (pool.reserve_a == 0 || pool.reserve_b == 0)
      return failure;

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_in)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      if (bal < amount_in)
        return failure;
    }

    if (token_other == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_b)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_other);
      if (bal < amount_b)
        return failure;
    }

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_in;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      state.putTokenBalance(tx.from, token_in, bal - amount_in);
    }

    if (token_other == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_b;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_other);
      state.putTokenBalance(tx.from, token_other, bal - amount_b);
    }

    uint64_t share_a = (amount_in * pool.total_liquidity) / pool.reserve_a;
    uint64_t share_b = (amount_b * pool.total_liquidity) / pool.reserve_b;
    uint64_t liquidity_minted = std::min(share_a, share_b);

    if (token_in == pool.token_a)
    {
      pool.reserve_a += amount_in;
      pool.reserve_b += amount_b;
    }
    else
    {
      pool.reserve_b += amount_in;
      pool.reserve_a += amount_b;
    }
    pool.total_liquidity += liquidity_minted;
    state.putAmmPool(pool);

    uint64_t existing_pos_id = 0;

    if (state.getPositionIndex(tx.from, pool_id, existing_pos_id))
    {
      AmmPosition pos;
      if (state.getAmmPosition(existing_pos_id, pos))
      {
        pos.liquidity += liquidity_minted;
        state.putAmmPosition(pos);
        return {ReceiptStatus::Success, tx.fee};
      }
    }

    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_position_id", id_bytes);
    uint64_t next_pos_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_pos_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_pos_id = 1;

    AmmPosition pos;
    pos.id = next_pos_id;
    pos.owner = tx.from;
    pos.pool_id = pool_id;
    pos.liquidity = liquidity_minted;
    pos.created_at_height = ctx.current_height;
    state.putAmmPosition(pos);

    state.putPositionIndex(tx.from, pool_id, next_pos_id);

    uint64_t new_next = next_pos_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_position_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Remove Liquidity

  Receipt TransactionExecutor::executeRemoveLiquidity(State::StateAccess &state,
                                                      const Transaction &tx,
                                                      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8)
      return failure;

    uint64_t position_id = 0;
    for (int i = 0; i < 8; ++i)
      position_id |= uint64_t(tx.payload[i]) << (i * 8);

    AmmPosition pos;
    if (!state.getAmmPosition(position_id, pos))
      return failure;
    if (pos.owner != tx.from)
      return failure;
    if (pos.liquidity == 0)
      return failure;

    AmmPool pool;
    if (!state.getAmmPool(pos.pool_id, pool))
      return failure;

    uint64_t share_a = (pos.liquidity * pool.reserve_a) / pool.total_liquidity;
    uint64_t share_b = (pos.liquidity * pool.reserve_b) / pool.total_liquidity;

    pool.reserve_a -= share_a;
    pool.reserve_b -= share_b;
    pool.total_liquidity -= pos.liquidity;
    state.putAmmPool(pool);

    if (pool.token_a == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance += share_a;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, pool.token_a);
      state.putTokenBalance(tx.from, pool.token_a, bal + share_a);
    }

    if (pool.token_b == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance += share_b;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, pool.token_b);
      state.putTokenBalance(tx.from, pool.token_b, bal + share_b);
    }

    pos.liquidity = 0;
    state.putAmmPosition(pos);

    state.deletePositionIndex(pos.owner, pos.pool_id);

    if (pool.isClosed())
    {
      state.deleteAmmPool(pool.id);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Swap

  Receipt TransactionExecutor::executeSwap(State::StateAccess &state,
                                           const Transaction &tx,
                                           const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 16)
      return failure;

    size_t off = 0;
    uint64_t pool_id = 0;
    for (int i = 0; i < 8; ++i)
      pool_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint64_t min_amount_out = 0;
    for (int i = 0; i < 8; ++i)
      min_amount_out |= uint64_t(tx.payload[off + i]) << (i * 8);

    AmmPool pool;
    if (!state.getAmmPool(pool_id, pool))
      return failure;
    if (!pool.active)
      return failure;

    Id token_in = tx.token_id;
    Id token_out;
    uint64_t reserve_in, reserve_out;

    if (token_in == pool.token_a)
    {
      token_out = pool.token_b;
      reserve_in = pool.reserve_a;
      reserve_out = pool.reserve_b;
    }
    else if (token_in == pool.token_b)
    {
      token_out = pool.token_a;
      reserve_in = pool.reserve_b;
      reserve_out = pool.reserve_a;
    }
    else
    {
      return failure;
    }

    uint64_t amount_in = tx.amount;

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < amount_in)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      if (bal < amount_in)
        return failure;
    }

    uint64_t amount_in_with_fee = amount_in * (10'000 - pool.fee_bps) / 10'000;

    __uint128_t numerator = static_cast<__uint128_t>(reserve_out) * amount_in_with_fee;
    uint64_t denominator = reserve_in + amount_in_with_fee;
    uint64_t amount_out = static_cast<uint64_t>(numerator / denominator);

    if (amount_out < min_amount_out)
      return failure;

    if (token_in == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= amount_in;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, token_in);
      state.putTokenBalance(tx.from, token_in, bal - amount_in);
    }

    if (token_out == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.to);
      acct.balance += amount_out;
      state.putAccount(tx.to, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.to, token_out);
      state.putTokenBalance(tx.to, token_out, bal + amount_out);
    }

    uint64_t clrty_volume = 0;

    if (token_in == NATIVE_TOKEN_ID)
    {
      clrty_volume = amount_in;
    }
    else if (pool.token_a == NATIVE_TOKEN_ID && pool.reserve_b > 0)
    {
      clrty_volume = static_cast<uint64_t>(
          static_cast<__uint128_t>(amount_in) *
          pool.reserve_a / pool.reserve_b);
    }
    else if (pool.token_b == NATIVE_TOKEN_ID && pool.reserve_a > 0)
    {
      clrty_volume = static_cast<uint64_t>(
          static_cast<__uint128_t>(amount_in) *
          pool.reserve_b / pool.reserve_a);
    }

    if (pool.volume_window_height == 0)
    {
      pool.volume_window_height = ctx.current_height;
      pool.volume_current = clrty_volume;
      pool.volume_last = 0;
    }
    else if (ctx.current_height >=
             pool.volume_window_height + ROTATION_INTERVAL)
    {
      pool.volume_last = pool.volume_current;
      pool.volume_current = clrty_volume;
      pool.volume_window_height = ctx.current_height;
    }
    else
    {
      pool.volume_current += clrty_volume;
    }

    if (token_in == pool.token_a)
    {
      pool.reserve_a += amount_in;
      pool.reserve_b -= amount_out;
    }
    else
    {
      pool.reserve_b += amount_in;
      pool.reserve_a -= amount_out;
    }
    state.putAmmPool(pool);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Order

  Receipt TransactionExecutor::executeCreateOrder(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Structural validation. This is the same check the mempool
    //  runs on admission, applied again here so a block built from
    //  an unvalidated source cannot smuggle a malformed order into
    //  state.
    if (!validateCreateOrderStructure(tx))
      return failure;

    //  Re-parse the payload now that we know it is well-formed.
    //
    //  Layout:
    //    [4]  buy_token (LE)
    //    [8]  min_buy_amount (LE)
    //    [1]  mode
    //    [4]  pool_id (LE)
    //    [8]  expires_at_height (LE)
    //    [1]  condition_count
    //    [N]  conditions (13 bytes each)
    size_t off = 0;
    uint32_t buy_token = uint32_t(tx.payload[off]) |
                         (uint32_t(tx.payload[off + 1]) << 8) |
                         (uint32_t(tx.payload[off + 2]) << 16) |
                         (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t min_buy_amount = 0;
    for (int i = 0; i < 8; ++i)
      min_buy_amount |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t mode = tx.payload[off++];

    uint32_t pool_id = uint32_t(tx.payload[off]) |
                       (uint32_t(tx.payload[off + 1]) << 8) |
                       (uint32_t(tx.payload[off + 2]) << 16) |
                       (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t expires_at_height = 0;
    for (int i = 0; i < 8; ++i)
      expires_at_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t condition_count = tx.payload[off++];

    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      OrderCondition::deserializeState(
          tx.payload.data(), tx.payload.size(), off, conditions[i]);
    }

    Id sell_token = tx.token_id;
    uint64_t sell_amount = tx.amount;

    //  Allocate the order ID. The counter lives in the SMT under
    //  "next_order_id"; the same key Genesis writes.
    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_order_id", id_bytes);

    uint64_t next_id = 0;
    if (id_bytes.empty())
    {
      next_id = 1;
    }
    else
    {
      for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
      {
        next_id |= uint64_t(id_bytes[i]) << (i * 8);
      }
    }

    //  Build the order record.
    Order order;
    order.id = next_id;
    order.owner = tx.from;
    order.mode = static_cast<OrderExecutionMode>(mode);
    order.pool_id = pool_id;
    order.sell_token = sell_token;
    order.buy_token = buy_token;
    order.sell_amount = sell_amount;
    order.min_buy_amount = min_buy_amount;
    order.created_at_height = ctx.current_height;
    order.order_expires_at_height = expires_at_height;
    order.filled_amount = 0;
    order.condition_count = condition_count;
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      order.conditions[i] = conditions[i];
    }

    if (!order.isValid())
      return failure;

    //  Balance check. All other structural checks have already
    //  passed in validateCreateOrderStructure.
    if (sell_token == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      if (acct.balance < sell_amount)
        return failure;
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, sell_token);
      if (bal < sell_amount)
        return failure;
    }

    //  ---- Pre-route validation for Active orders ----
    //
    //  An Active order with no conditions routes immediately on
    //  creation. If the pool is missing, closed, or does not
    //  contain the order's pair, the order can never fill and must
    //  be rejected. This check has to happen BEFORE the sell-token
    //  lock is taken and BEFORE the order record is written,
    //  because a failure after those points would leave state
    //  modified under a rejected transaction — the executor has no
    //  rollback primitive, so "modify then fail" is a leak.
    //
    //  Active orders WITH conditions do not route on creation; they
    //  wait for the epoch boundary. For them, the pool may not exist
    //  yet, or may be created later, so we do NOT pre-validate.
    if (order.mode == OrderExecutionMode::Active &&
        order.condition_count == 0)
    {
      AmmPool pool;
      if (!state.getAmmPool(order.pool_id, pool))
        return failure;
      if (!pool.active)
        return failure;

      const bool sells_a = (order.sell_token == pool.token_a &&
                            order.buy_token == pool.token_b);
      const bool sells_b = (order.sell_token == pool.token_b &&
                            order.buy_token == pool.token_a);
      if (!sells_a && !sells_b)
        return failure;

      if (pool.reserve_a == 0 || pool.reserve_b == 0)
        return failure;
    }

    //  ---- All checks passed. Apply state changes. ----

    //  Take the sell-token lock. Both the matcher and the router
    //  require the lock to be in place before they run.
    if (sell_token == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(tx.from);
      acct.balance -= sell_amount;
      state.putAccount(tx.from, acct);
    }
    else
    {
      uint64_t bal = state.getTokenBalance(tx.from, sell_token);
      state.putTokenBalance(tx.from, sell_token, bal - sell_amount);
    }

    //  Persist the record. The matcher or the router may overwrite
    //  or delete it.
    state.putOrder(order);

    //  Execute.
    std::vector<Fill> fills;

    if (order.mode == OrderExecutionMode::Passive)
    {
      MatchOutcome outcome = matchPassiveOrder(
          state, order, ctx.current_height, ctx.tx_index_in_block);
      fills = std::move(outcome.fills);
    }
    else // Active
    {
      //  No conditions: route immediately against the order's pool.
      //  The pre-route validation above guarantees the pool is
      //  usable, so executeActiveOrder cannot return Unroutable for
      //  a structural reason. It can still return Rested if the
      //  pool's current price is unfavorable — that's fine, the
      //  order rests.
      //
      //  With conditions: leave the order in state. The condition
      //  evaluator, running at the next epoch boundary, will route
      //  it if the conditions hold or cancel it if they do not.
      if (order.condition_count == 0)
      {
        const auto outcome = BlockProcessor::executeActiveOrder(
            state, order, ctx.current_height, ctx.tx_index_in_block, fills);

        //  Defensive: the pre-route check should have caught any
        //  structural reason for Unroutable, but if the state
        //  changed between the check and here (it can't within a
        //  single tx, but the invariant is worth asserting),
        //  reject rather than leave a partially-applied state.
        if (outcome == ActiveRouteOutcome::Unroutable)
        {
          return failure;
        }

        //  Filled: fills already contains the fill(s).
        //  Rested: the order is in state with a remainder. The
        //  expiry index below will pick it up if it has one.
      }
    }

    //  Expiry index. Only if the order still exists after execution.
    //  A fully filled order was deleted by the matcher or the
    //  router, and indexing a deleted order would leave an expiry
    //  row pointing at nothing.
    Order still_exists;
    if (state.getOrder(order.id, still_exists) &&
        expires_at_height != 0)
    {
      state.addOrderExpiry(expires_at_height, order.id);
    }

    //  Bump the next-order-id counter. The counter is advanced once
    //  per successful CreateOrder, regardless of whether the order
    //  rested or executed.
    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_order_id", new_id_bytes);

    //  Receipt with fills.
    Receipt receipt{ReceiptStatus::Success, tx.fee};
    receipt.fills = std::move(fills);
    return receipt;
  }

  //  Cancel Order

  Receipt TransactionExecutor::executeCancelOrder(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8)
      return failure;

    uint64_t order_id = 0;
    for (int i = 0; i < 8; ++i)
      order_id |= uint64_t(tx.payload[i]) << (i * 8);

    Order order;
    if (!state.getOrder(order_id, order))
      return failure;
    if (order.owner != tx.from)
      return failure;

    uint64_t refund = order.remainingAmount();
    if (refund > 0)
    {
      if (order.sell_token == NATIVE_TOKEN_ID)
      {
        Account acct = state.getAccount(tx.from);
        acct.balance += refund;
        state.putAccount(tx.from, acct);
      }
      else
      {
        uint64_t bal = state.getTokenBalance(tx.from, order.sell_token);
        state.putTokenBalance(tx.from, order.sell_token, bal + refund);
      }
    }

    state.deleteRestingOrder(order);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  System Slash

  Receipt TransactionExecutor::executeSystemSlash(State::StateAccess &state,
                                                  uint64_t validator_id,
                                                  uint64_t slash_height,
                                                  const TxExecutionContext & /*ctx*/)
  {
    const Receipt no_op{ReceiptStatus::Success, 0};

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return no_op;

    if (SEED_SLASH_EXEMPT && validator.is_seed)
      return no_op;

    const uint64_t slash_amount =
        applyBps(validator.stake, SLASH_AMOUNT_BPS);

    if (slash_amount <= validator.stake)
      validator.stake -= slash_amount;

    validator.applyInfractionPenalty(slash_height);

    state.putValidator(validator);

    if (slash_amount > 0)
    {
      GlobalStateReader reader(state);
      GlobalStateWriter writer(state);

      uint64_t pot = reader.pot();
      pot += slash_amount;
      writer.setPot(pot);
    }

    return {ReceiptStatus::Success, 0};
  }

  //  Validate Create Order Structure

  bool TransactionExecutor::validateCreateOrderStructure(const Transaction &tx)
  {
    //  Minimum length: buy_token(4) + min_buy_amount(8) + mode(1)
    //  + pool_id(4) + expires_at_height(8) + condition_count(1) = 26.
    if (tx.payload.size() < 26)
      return false;

    size_t off = 0;
    uint32_t buy_token = uint32_t(tx.payload[off]) |
                         (uint32_t(tx.payload[off + 1]) << 8) |
                         (uint32_t(tx.payload[off + 2]) << 16) |
                         (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t min_buy_amount = 0;
    for (int i = 0; i < 8; ++i)
      min_buy_amount |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t mode = tx.payload[off++];

    uint32_t pool_id = uint32_t(tx.payload[off]) |
                       (uint32_t(tx.payload[off + 1]) << 8) |
                       (uint32_t(tx.payload[off + 2]) << 16) |
                       (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t expires_at_height = 0;
    for (int i = 0; i < 8; ++i)
      expires_at_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t condition_count = tx.payload[off++];

    if (condition_count > ORDER_MAX_CONDITIONS)
      return false;

    if (mode != static_cast<uint8_t>(OrderExecutionMode::Passive) &&
        mode != static_cast<uint8_t>(OrderExecutionMode::Active))
      return false;

    //  pool_id is meaningful only for Active orders.
    if (mode == static_cast<uint8_t>(OrderExecutionMode::Active))
    {
      if (pool_id == 0)
        return false;
    }
    else
    {
      if (pool_id != 0)
        return false;
    }

    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      if (!OrderCondition::deserializeState(
              tx.payload.data(), tx.payload.size(), off, conditions[i]))
      {
        return false;
      }
    }

    //  Cheap structural checks that mirror Order::isValid without
    //  needing a full Order record.
    if (tx.token_id == buy_token)
      return false;
    if (tx.amount == 0)
      return false;
    if (min_buy_amount == 0)
      return false;

    //  Overflow guard for Passive orders: an order whose canonical
    //  price cannot fit in u64 cannot enter the book, so reject it
    //  up front rather than creating a lock the matcher will never
    //  release. Active orders do not go through the book and so do
    //  not need this check.
    if (mode == static_cast<uint8_t>(OrderExecutionMode::Passive))
    {
      Order probe;
      probe.sell_token = tx.token_id;
      probe.buy_token = buy_token;
      probe.sell_amount = tx.amount;
      probe.min_buy_amount = min_buy_amount;
      uint64_t canonical_price = 0;
      if (!OrderBook::canonicalPrice(probe, canonical_price))
        return false;
    }

    return true;
  }
} // namespace Core