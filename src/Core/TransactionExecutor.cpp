// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionExecutor.h"

#include "AmmPool.h"
#include "AmmPosition.h"
#include "Order.h"
#include "TokenTypes.h"
#include "ValidatorTypes.h"

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
    // Compute the signing hash.
    Crypto::Hash hash = tx.signingHash();

    // Verify against tx.from as the public key.
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
      return true; // no expiry
    return ctx.current_height <= tx.valid_until_height;
  }

  bool TransactionExecutor::chargeFee(State::StateAccess &state,
                                      const Transaction &tx)
  {
    // Fee is charged in native CLRTY, regardless of the transaction's token.
    Account sender = state.getAccount(tx.from);

    if (sender.balance < tx.fee)
    {
      return false; // insufficient balance
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

    // Native CLRTY transfer.
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
        // First time we've seen this account. Mark its creation height.
        receiver.created_at_height = ctx.current_height;
      }
      state.putAccount(tx.to, receiver);

      return {ReceiptStatus::Success, tx.fee};
    }

    // Custom token transfer.
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
    // Opt-in to staking simply clears the opt-out flag.
    Account acct = state.getAccount(tx.from);
    acct.staking_opted_out = false;
    acct.recalculateStaked(AUTO_STAKE_THRESHOLD);
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
    acct.recalculateStaked(AUTO_STAKE_THRESHOLD);
    state.putAccount(tx.from, acct);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Claim Rewards

  Receipt TransactionExecutor::executeClaimRewards(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext & /*ctx*/)
  {
    // Claiming moves the account's accrued pending_rewards into its
    // spendable balance. It is a bookkeeping move within the account:
    // the rewards were already issued (and counted in total_supply) at
    // the moment they were credited to pending_rewards, so claiming
    // does not touch total_supply.
    //
    // The account's totalValue() is unchanged by a claim.
    //
    // A claim with zero pending rewards succeeds trivially. The fee
    // discourages spamming empty claims.

    Account acct = state.getAccount(tx.from);

    acct.balance += acct.pending_rewards;
    acct.pending_rewards = 0;

    // The balance grew; recompute the staked amount to reflect the new
    // balance under the auto-stake rule.
    acct.recalculateStaked(AUTO_STAKE_THRESHOLD);

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

    // Must meet minimum stake requirement.
    if (acct.balance < VALIDATOR_MIN_STAKE)
      return failure;

    // The payload contains the node public key (32 bytes).
    if (tx.payload.size() != 32)
      return failure;

    // A reward address can only be registered once.
    uint64_t existing_id = 0;
    if (state.getValidatorByAddress(tx.from, existing_id))
      return failure;

    // Allocate a new validator ID.
    std::vector<uint8_t> id_bytes;
    if (!state.getGlobal("next_validator_id", id_bytes))
    {
      // First validator — start at 1.
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
    validator.stake = acct.balance; // stake = full balance for now
    validator.registered_at_height = ctx.current_height;
    validator.uptime_score = 10'000;
    validator.is_seed = false;
    validator.is_active = false;
    std::memcpy(validator.node_key.data.data(), tx.payload.data(), 32);

    state.putValidator(validator);

    // Write the validator-by-address index so reward distribution and
    // any other address-based lookup can find this validator.
    state.putValidatorByAddress(validator.reward_address, validator.id);

    // Bump next ID.
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
                                                          const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // Look up the validator by the sender's address.
    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    // Seeds cannot unregister. They're the bootstrap set.
    if (validator.is_seed)
      return failure;

    // If the validator is active, removing them must not drop the
    // active set below quorum. Compute what the set would look like.
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

      // The remaining set must still be at least ACTIVE_SET_MIN strong.
      // This is a policy floor, not a safety check: the set can
      // theoretically form quorum at any size >= 4, but the chain's
      // design keeps a floor to bound coordination cost and preserve
      // censorship resistance. A validator that wants to leave when
      // the set is at the floor must wait for rotation to promote
      // replacements first.
      if (new_set.size() < ACTIVE_SET_MIN)
        return failure;

      saveActiveSet(state, new_set);
    }

    // Return the validator's stake to their balance. Under the current
    // registration model, stake == the full balance at registration
    // time, and it has been held out of balance ever since.
    Account acct = state.getAccount(validator.owner);
    acct.balance += validator.stake;
    acct.recalculateStaked(AUTO_STAKE_THRESHOLD);
    state.putAccount(validator.owner, acct);

    // Remove the address index.
    state.deleteValidatorByAddress(validator.reward_address);

    // Remove the validator record itself.
    state.deleteValidator(validator.id);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Update Reward Address

  Receipt TransactionExecutor::executeUpdateRewardAddress(State::StateAccess &state,
                                                          const Transaction &tx,
                                                          const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // The payload is the new reward address (32 bytes).
    if (tx.payload.size() != 32)
      return failure;

    Crypto::Address new_address;
    std::memcpy(new_address.data.data(), tx.payload.data(), 32);

    if (new_address.isNull())
      return failure;

    // Look up the sender's validator.
    uint64_t validator_id = 0;
    if (!state.getValidatorByAddress(tx.from, validator_id))
      return failure;

    ValidatorInfo validator;
    if (!state.getValidator(validator_id, validator))
      return failure;

    // The new address must not already be registered.
    if (new_address != tx.from)
    {
      uint64_t collision = 0;
      if (state.getValidatorByAddress(new_address, collision))
        return failure;
    }

    // Update the index: remove the old, add the new.
    state.deleteValidatorByAddress(validator.reward_address);
    state.putValidatorByAddress(new_address, validator.id);

    // Update the validator record. We keep owner in sync with
    // reward_address because that's the current invariant: registration
    // sets both to tx.from, and nothing else changes them.
    validator.reward_address = new_address;
    validator.owner = new_address;
    state.putValidator(validator);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Create Token

  Receipt TransactionExecutor::executeCreateToken(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // Payload layout:
    //   [1]  decimals
    //   [1]  backing_model
    //   [1]  name_len
    //   [N]  name
    //   [1]  symbol_len
    //   [M]  symbol
    //   [8]  max_supply
    //   [2]  royalty_bps
    //   [1]  has_fingerprint
    //   [32] fingerprint (optional)

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

    // Allocate a new token ID.
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

    // Initialize the cumulative supply counter to zero. The counter is
    // separate from the token's metadata so mint can check the cap
    // without loading the record, and so burn can decrement without
    // touching the metadata. A supply of 0 removes the entry.
    state.putTokenSupply(token.id, 0);

    // Bump next token ID.
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

    // The native token cannot be minted through a transaction. Its
    // supply is controlled by the block reward path, and allowing mint
    // would break the total_supply invariant.
    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    // Only the creator can mint.
    if (token.creator != tx.from)
      return failure;

    // Enforce max supply against the cumulative minted supply, not the
    // minter's current balance. This is the fix for the previous soft
    // cap, which allowed a minter to transfer away their balance and
    // then mint past the cap.
    uint64_t current_supply = state.getTokenSupply(tx.token_id);

    if (token.maxSupply > 0 && current_supply + tx.amount > token.maxSupply)
      return failure;

    // Credit the recipient.
    uint64_t recipient_balance = state.getTokenBalance(tx.to, tx.token_id);
    state.putTokenBalance(tx.to, tx.token_id, recipient_balance + tx.amount);

    // Bump the cumulative supply.
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

    // The native token cannot be burned through a transaction. Burning
    // it would break the total_supply invariant maintained by the
    // reward path.
    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    uint64_t sender_balance = state.getTokenBalance(tx.from, tx.token_id);
    if (sender_balance < tx.amount)
      return failure;

    state.putTokenBalance(tx.from, tx.token_id, sender_balance - tx.amount);

    // Decrement the cumulative supply. If the burn exceeds the tracked
    // supply (which shouldn't happen, since supply >= sum of balances),
    // clamp at zero rather than underflow.
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

    // Payload layout:
    //   [1]  new_name_len
    //   [N]  new_name
    //   [1]  new_symbol_len
    //   [M]  new_symbol
    //   [2]  new_royalty_bps
    //
    // An empty name or symbol (len 0) means "don't change this field".
    // maxSupply and decimals cannot be changed: changing maxSupply
    // would undermine the supply cap guarantee, and changing decimals
    // would change the meaning of every existing balance.

    if (tx.payload.size() < 4)
      return failure;

    // The native token cannot be modified.
    if (tx.token_id == NATIVE_TOKEN_ID)
      return failure;

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    // Only the creator can update.
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

    // Apply updates. Empty string means "leave unchanged". Zero royalty
    // means "leave unchanged" too — a token with royalty 0 is the
    // default, and users can't distinguish "set to 0" from "don't
    // change" otherwise.
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

    // Payload layout:
    //   [4]  token_b
    //   [8]  amount_b
    //   [2]  fee_bps
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

    // tx.token_id is token_a, tx.amount is amount_a.
    uint32_t token_a = tx.token_id;
    uint64_t amount_a = tx.amount;

    if (token_a == token_b)
      return failure;
    if (amount_a == 0 || amount_b == 0)
      return failure;
    if (fee_bps > AMM_MAX_FEE_BPS)
      return failure;

    // Canonical ordering: token_a < token_b.
    if (token_a > token_b)
    {
      std::swap(token_a, token_b);
      std::swap(amount_a, amount_b);
    }

    // Build the pool struct and validate BEFORE deducting anything.
    // Allocate a new pool ID.
    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_pool_id", id_bytes);
    uint64_t next_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_id = 1;

    // Create the pool (in memory).
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

    // Initial liquidity = sqrt(amount_a * amount_b).
    __uint128_t prod = static_cast<__uint128_t>(amount_a) * amount_b;
    uint64_t initial_liq = 1;
    while (initial_liq <= prod / (initial_liq + 1))
      ++initial_liq;
    pool.total_liquidity = initial_liq;

    if (!pool.isValid())
      return failure;

    // Check BOTH balances before deducting either token.
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

    // ---- All checks passed. Apply state changes. ----

    // Deduct both tokens from the creator.
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

    // Bump next pool ID.
    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_pool_id", new_id_bytes);

    // Allocate a position ID (same pattern as executeAddLiquidity).
    std::vector<uint8_t> pos_id_bytes;
    state.getGlobal("next_position_id", pos_id_bytes);
    uint64_t next_pos_id = 1;
    for (int i = 0; i < 8 && i < (int)pos_id_bytes.size(); ++i)
    {
      next_pos_id |= uint64_t(pos_id_bytes[i]) << (i * 8);
    }
    if (pos_id_bytes.empty())
      next_pos_id = 1;

    // Create LP position for the creator.
    AmmPosition pos;
    pos.id = next_pos_id;
    pos.owner = tx.from;
    pos.pool_id = pool.id;
    pos.liquidity = initial_liq;
    pos.created_at_height = ctx.current_height;
    state.putAmmPosition(pos);

    // Write the position index so future AddLiquidity calls can find
    // and merge into this position rather than creating a new one.
    state.putPositionIndex(tx.from, pool.id, next_pos_id);

    // Bump next position ID.
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

    // Payload: [8] pool_id, [8] amount_b
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

    // tx.token_id must be one of the pool's tokens.
    Id token_in = tx.token_id;
    Id token_other = (token_in == pool.token_a) ? pool.token_b : pool.token_a;
    if (token_in != pool.token_a && token_in != pool.token_b)
      return failure;

    uint64_t amount_in = tx.amount;

    // Validate the empty-reserve condition BEFORE deducting anything.
    if (pool.reserve_a == 0 || pool.reserve_b == 0)
    {
      // Empty pool — shouldn't happen for an existing active pool.
      return failure;
    }

    // Check BOTH balances before deducting either token.
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

    // ---- All checks passed. Apply state changes. ----

    // Deduct both tokens from sender.
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

    // Compute LP tokens to mint.
    uint64_t share_a = (amount_in * pool.total_liquidity) / pool.reserve_a;
    uint64_t share_b = (amount_b * pool.total_liquidity) / pool.reserve_b;
    uint64_t liquidity_minted = std::min(share_a, share_b);

    // Update pool reserves.
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

    // ---- Position handling ----
    //
    // One position per (owner, pool). If the owner already has a
    // position for this pool, merge the newly minted liquidity into it
    // and keep the original created_at_height. Otherwise, allocate a
    // fresh position and index it.

    uint64_t existing_pos_id = 0;

    if (state.getPositionIndex(tx.from, pool_id, existing_pos_id))
    {
      AmmPosition pos;
      if (state.getAmmPosition(existing_pos_id, pos))
      {
        pos.liquidity += liquidity_minted;
        // created_at_height is preserved — the position was created
        // when the LP first provided liquidity.
        state.putAmmPosition(pos);
        return {ReceiptStatus::Success, tx.fee};
      }
      // Index points at a missing position — that's an inconsistency.
      // Treat it as "no existing position" and fall through to create
      // a fresh one, overwriting the stale index entry.
    }

    // No existing position: allocate a new one.
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

    // Payload: [8] position_id
    if (tx.payload.size() < 8)
      return failure;

    uint64_t position_id = 0;
    for (int i = 0; i < 8; ++i)
      position_id |= uint64_t(tx.payload[i]) << (i * 8);

    // All lookups and ownership checks happen before any mutation.
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

    // Compute share of each reserve.
    uint64_t share_a = (pos.liquidity * pool.reserve_a) / pool.total_liquidity;
    uint64_t share_b = (pos.liquidity * pool.reserve_b) / pool.total_liquidity;

    // ---- All checks passed. Apply state changes. ----

    // Update pool.
    pool.reserve_a -= share_a;
    pool.reserve_b -= share_b;
    pool.total_liquidity -= pos.liquidity;
    state.putAmmPool(pool);

    // Credit LP.
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

    // Zero the position.
    pos.liquidity = 0;
    state.putAmmPosition(pos);

    // The position is drained. Remove the index entry so a future
    // AddLiquidity creates a fresh position rather than merging into
    // a zeroed one.
    state.deletePositionIndex(pos.owner, pos.pool_id);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Swap

  Receipt TransactionExecutor::executeSwap(State::StateAccess &state,
                                           const Transaction &tx,
                                           const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // Payload: [8] pool_id, [8] min_amount_out
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

    // Determine input/output tokens.
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

    // ---- Precondition checks BEFORE any state mutation ----

    // Sender must have enough input.
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

    // Compute expected output using constant product formula with fee.
    uint64_t amount_in_with_fee = amount_in * (10'000 - pool.fee_bps) / 10'000;

    __uint128_t numerator = static_cast<__uint128_t>(reserve_out) * amount_in_with_fee;
    uint64_t denominator = reserve_in + amount_in_with_fee;
    uint64_t amount_out = static_cast<uint64_t>(numerator / denominator);

    if (amount_out < min_amount_out)
      return failure;

    // ---- All checks passed. Apply state changes. ----

    // Deduct input from sender.
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

    // Credit output to receiver.
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

    // Update pool reserves.
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

    // Payload layout:
    //   [4]  buy_token
    //   [8]  min_buy_amount
    //   [1]  mode
    //   [8]  expires_at_height
    //   [1]  condition_count
    //   [N]  conditions (13 bytes each)
    if (tx.payload.size() < 22)
      return failure;

    size_t off = 0;
    uint32_t buy_token = uint32_t(tx.payload[off]) | (uint32_t(tx.payload[off + 1]) << 8) | (uint32_t(tx.payload[off + 2]) << 16) | (uint32_t(tx.payload[off + 3]) << 24);
    off += 4;

    uint64_t min_buy_amount = 0;
    for (int i = 0; i < 8; ++i)
      min_buy_amount |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t mode = tx.payload[off++];

    uint64_t expires_at_height = 0;
    for (int i = 0; i < 8; ++i)
      expires_at_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    uint8_t condition_count = tx.payload[off++];

    if (condition_count > ORDER_MAX_CONDITIONS)
      return failure;

    // Load conditions.
    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};
    for (uint8_t i = 0; i < condition_count; ++i)
    {
      if (!OrderCondition::deserializeState(
              tx.payload.data(), tx.payload.size(), off, conditions[i]))
      {
        return failure;
      }
    }

    // Lock the sell amount in the order (held by the pool).
    Id sell_token = tx.token_id;
    uint64_t sell_amount = tx.amount;

    // Build the order struct and validate BEFORE locking funds.
    // Allocate a new order ID.
    std::vector<uint8_t> id_bytes;
    state.getGlobal("next_order_id", id_bytes);
    uint64_t next_id = 1;
    for (int i = 0; i < 8 && i < (int)id_bytes.size(); ++i)
    {
      next_id |= uint64_t(id_bytes[i]) << (i * 8);
    }
    if (id_bytes.empty())
      next_id = 1;

    Order order;
    order.id = next_id;
    order.owner = tx.from;
    order.mode = static_cast<OrderExecutionMode>(mode);
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

    // Check the balance BEFORE deducting.
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

    // ---- All checks passed. Apply state changes. ----

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

    state.putOrder(order);

    // Add to the expiry index. An expiry height of zero means "never
    // expires", which is a valid state — such orders are not indexed
    // and are only removed by explicit CancelOrder.
    if (expires_at_height != 0)
    {
      state.addOrderExpiry(expires_at_height, order.id);
    }

    // Bump next order ID.
    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_order_id", new_id_bytes);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  Cancel Order

  Receipt TransactionExecutor::executeCancelOrder(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    // Payload: [8] order_id
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

    // Refund any remaining sell amount.
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

    // Remove from the expiry index. Only indexed orders were added
    // with a non-zero expiry height.
    if (order.order_expires_at_height != 0)
    {
      state.removeOrderExpiry(order.order_expires_at_height, order_id);
    }

    state.deleteOrder(order_id);

    return {ReceiptStatus::Success, tx.fee};
  }

} // namespace Core