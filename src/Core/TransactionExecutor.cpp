// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionExecutor.h"

#include "ActiveRouter.h"
#include "AmmFarmTypes.h"
#include "AmmPool.h"
#include "AmmPosition.h"
#include "BlockProcessor.h"
#include "Order.h"
#include "TokenTypes.h"
#include "ValidatorTypes.h"
#include "GlobalState.h"
#include "RewardTypes.h"
#include "KeyRotation.h"
#include "Bridge/Bitcoin.h"

#include "State/Keys.h"
#include "State/StateAccess.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <iomanip>

namespace Core
{

  namespace
  {
    uint64_t isqrt128(__uint128_t n)
    {
      if (n == 0)
        return 0;

      __uint128_t lo = 0;
      __uint128_t hi = (__uint128_t(1) << 64);

      while (hi - lo > 1)
      {
        __uint128_t mid = lo + (hi - lo) / 2;
        if (mid * mid <= n)
          lo = mid;
        else
          hi = mid;
      }

      return static_cast<uint64_t>(lo);
    }

    uint64_t readU64GlobalInternal(State::StateAccess &state,
                                   const char *name)
    {
      std::vector<uint8_t> bytes;
      if (!state.getGlobal(name, bytes) || bytes.size() != 8)
        return 0;
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(bytes[i]) << (i * 8);
      return v;
    }

    void writeU64GlobalInternal(State::StateAccess &state,
                                const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(v >> (i * 8));
      state.putGlobal(name, bytes);
    }

    struct BridgeSignatureEntry
    {
      uint16_t signer_index{0};
      Crypto::Signature signature{};
    };

    bool parseBridgeSignatureBlock(const uint8_t *data, size_t len,
                                   std::vector<BridgeSignatureEntry> &out)
    {
      out.clear();
      if (len < 2)
        return false;

      const uint16_t count =
          uint16_t(data[0]) | (uint16_t(data[1]) << 8);

      if (count > BRIDGE_MAX_WATCHERS)
        return false;

      const size_t expected = 2 + static_cast<size_t>(count) * 66;
      if (len != expected)
        return false;

      out.reserve(count);
      for (uint16_t i = 0; i < count; ++i)
      {
        const uint8_t *p = data + 2 + i * 66;
        BridgeSignatureEntry e;
        e.signer_index = uint16_t(p[0]) | (uint16_t(p[1]) << 8);
        std::memcpy(e.signature.data.data(), p + 2, 64);
        out.push_back(e);
      }

      return true;
    }

    bool adoptOrCreateWrappedTokenImpl(
        State::StateAccess &state,
        Core::BridgeChainRegistration &reg)
    {
      Core::TokenInfo existing;
      const bool have_existing = state.getToken(reg.wrapped_token_id, existing);

      if (have_existing)
      {
        if (!existing.isBridged())
          return false;
        if (!existing.fingerprint.has_value() ||
            *existing.fingerprint != reg.fingerprint)
          return false;
        if (existing.backing != Core::BackingModel::Backed)
          return false;
        if (!existing.creator.isNull())
          return false;
        if (existing.decimals != reg.clarity_decimals)
        {
          //  Decimals mismatch: an existing token has the right
          //  fingerprint but the wrong decimal count. This happens
          //  when a chain's clarity_decimals constant is changed
          //  after the token has already been created. Refusing to
          //  adopt it is the safe behaviour: the operator must
          //  either accept the old token's decimals or wipe and
          //  re-register.
          return false;
        }

        return true;
      }

      if (reg.source_chain_id != Core::BitcoinBridge::BTC_CHAIN_ID)
        return false;

      const uint64_t alloc_id = reg.wrapped_token_id;

      Core::TokenInfo token;
      token.id = static_cast<Id>(alloc_id);
      token.name = std::string(Core::BitcoinBridge::BTC_WRAPPED_NAME);
      token.symbol = std::string(Core::BitcoinBridge::BTC_WRAPPED_SYMBOL);
      token.decimals = Core::BitcoinBridge::BTC_WRAPPED_DECIMALS;
      token.creator = Crypto::Address{};
      token.backing = Core::BackingModel::Backed;
      token.maxSupply = 0;
      token.royaltyBps = 0;
      token.fingerprint = reg.fingerprint;

      if (!token.isValid())
        return false;

      state.putToken(token);
      state.putTokenSupply(token.id, 0);

      uint64_t current_next = readU64GlobalInternal(state, "next_token_id");
      if (current_next == 0)
        current_next = 1;
      const uint64_t new_next = std::max(current_next, alloc_id + 1);
      writeU64GlobalInternal(state, "next_token_id", new_next);

      return true;
    }

    Crypto::Hash bridgeSigningHash(std::string_view domain,
                                   const uint8_t *message, size_t message_len)
    {
      return Crypto::hashDomain(domain.data(), message, message_len);
    }

    std::vector<uint8_t> encodeBridgeMintMessage(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        const Crypto::Address &destination,
        uint64_t amount)
    {
      std::vector<uint8_t> out;
      out.reserve(8 + 32 + 4 + 32 + 8);

      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(source_chain_id >> (i * 8)));
      out.insert(out.end(), source_tx_hash.data.begin(), source_tx_hash.data.end());
      for (int i = 0; i < 4; ++i)
        out.push_back(uint8_t(source_output_index >> (i * 8)));
      out.insert(out.end(), destination.data.begin(), destination.data.end());
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(amount >> (i * 8)));

      return out;
    }

    std::vector<uint8_t> encodeBridgeAckMessage(uint64_t withdrawal_id)
    {
      std::vector<uint8_t> out;
      out.reserve(8);
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(withdrawal_id >> (i * 8)));
      return out;
    }

    void bumpBridgeStats(State::StateAccess &state,
                         uint64_t source_chain_id,
                         uint64_t current_height,
                         uint64_t minted_delta,
                         uint64_t burned_delta,
                         uint64_t released_delta,
                         bool count_deposit,
                         bool count_withdrawal,
                         bool count_release)
    {
      Core::BridgeStats stats;
      if (!state.getBridgeStats(source_chain_id, stats))
      {
        stats.source_chain_id = source_chain_id;
        stats.registered_at_height = current_height;
      }

      stats.total_minted += minted_delta;
      stats.total_burned += burned_delta;
      stats.total_released += released_delta;

      if (count_deposit)
      {
        stats.deposit_count += 1;
        stats.last_mint_height = current_height;
      }
      if (count_withdrawal)
      {
        stats.withdrawal_count += 1;
        stats.last_burn_height = current_height;
      }
      if (count_release)
      {
        stats.released_withdrawal_count += 1;
        stats.last_release_height = current_height;
      }

      state.putBridgeStats(stats);
    }

    bool debitToken(State::StateAccess &state,
                    const Crypto::Address &addr,
                    Id token_id, uint64_t amount)
    {
      if (token_id == NATIVE_TOKEN_ID)
      {
        Core::Account acct = state.getAccount(addr);
        if (acct.balance < amount)
          return false;
        acct.balance -= amount;
        state.putAccount(addr, acct);
        return true;
      }

      uint64_t bal = state.getTokenBalance(addr, token_id);
      if (bal < amount)
        return false;
      state.putTokenBalance(addr, token_id, bal - amount);
      return true;
    }

    void creditToken(State::StateAccess &state,
                     const Crypto::Address &addr,
                     Id token_id, uint64_t amount)
    {
      if (amount == 0)
        return;

      if (token_id == NATIVE_TOKEN_ID)
      {
        Core::Account acct = state.getAccount(addr);
        acct.balance += amount;
        state.putAccount(addr, acct);
        return;
      }

      uint64_t bal = state.getTokenBalance(addr, token_id);
      state.putTokenBalance(addr, token_id, bal + amount);
    }

    //  Settle a position's farm accrual since its last settle.
    //
    //  Computes (farm.rps_per_share - accrual.last_rps) * pos.liquidity
    //  / FARM_RPS_SCALE, updates the accrual companion's last_rps to
    //  the farm's current rps_per_share, and RETURNS the accrued
    //  amount WITHOUT touching any account. The caller decides how to
    //  credit the beneficiary:
    //
    //    - executeRemoveLiquidity credits tx.from inline (one position,
    //      one account write);
    //    - executeClaimAmmFarmRewards accumulates across every position
    //      the caller holds and does one account write at the end.
    //
    //  Returns 0 if:
    //    - the pool has no farm;
    //    - the position has zero liquidity;
    //    - nothing has accrued since the last settle.
    //
    //  If the accrual companion is absent (a position created before
    //  the farm existed), last_rps is treated as 0 — which is correct,
    //  because the farm's rps_per_share was also 0 when the position
    //  was created. The position earns from the farm's start.
    //
    //  This function writes the accrual companion (updates last_rps)
    //  whenever the position has positive liquidity and a farm exists,
    //  even if the computed accrual is 0. That keeps last_rps in sync
    //  so a subsequent call sees a zero delta rather than a stale one.
    uint64_t settleAmmFarmAccrual(State::StateAccess &state,
                                  const Core::AmmPosition &pos)
    {
      if (pos.liquidity == 0)
        return 0;

      Core::AmmFarmSchedule farm;
      if (!state.getAmmFarm(pos.pool_id, farm))
        return 0;

      Core::AmmPositionAccrual accrual;
      const bool have_accrual =
          state.getAmmPositionAccrual(pos.id, accrual);

      const uint64_t last_rps = have_accrual ? accrual.last_rps : 0;

      uint64_t accrued = 0;
      if (farm.rps_per_share > last_rps)
      {
        const __uint128_t delta =
            static_cast<__uint128_t>(farm.rps_per_share - last_rps);
        const __uint128_t num = delta * pos.liquidity;
        accrued = static_cast<uint64_t>(num / FARM_RPS_SCALE);
      }

      //  Persist the new last_rps. Do this even when accrued == 0 so
      //  a subsequent settle doesn't recompute a delta we've already
      //  accounted for. (The only case where a stale last_rps would
      //  hurt is a farm that bumps rps and a position that reads but
      //  doesn't write; skipping the write would let the next settle
      //  re-credit the same delta.)
      Core::AmmPositionAccrual updated;
      updated.position_id = pos.id;
      updated.last_rps = farm.rps_per_share;
      state.putAmmPositionAccrual(updated);

      return accrued;
    }

    uint32_t readU32At(const std::vector<uint8_t> &p, size_t off)
    {
      return uint32_t(p[off]) | (uint32_t(p[off + 1]) << 8) |
             (uint32_t(p[off + 2]) << 16) | (uint32_t(p[off + 3]) << 24);
    }

    uint64_t readU64At(const std::vector<uint8_t> &p, size_t off)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(p[off + i]) << (i * 8);
      return v;
    }

    void recordBridgeEvent(State::StateAccess &state,
                           Core::BridgeEventKind kind,
                           uint64_t source_chain_id,
                           uint64_t current_height,
                           uint64_t tx_index,
                           const Crypto::Hash &tx_hash,
                           const Crypto::Address &actor,
                           const Crypto::Hash &source_tx_hash,
                           bool has_source,
                           uint32_t source_output_index,
                           uint64_t withdrawal_id,
                           uint64_t amount,
                           uint64_t counterparty)
    {
      Core::BridgeEvent evt;
      evt.kind = kind;
      evt.source_chain_id = source_chain_id;
      evt.block_height = current_height;
      evt.tx_index_in_block = static_cast<uint32_t>(tx_index);
      evt.tx_hash = tx_hash;
      evt.has_source_hash = has_source;
      evt.source_tx_hash = source_tx_hash;
      evt.source_output_index = source_output_index;
      evt.withdrawal_id = withdrawal_id;
      evt.actor = actor;
      evt.amount = amount;
      evt.counterparty = counterparty;
      evt.has_tx_hash = true;
      state.putBridgeEvent(evt);
    }

    //  Shared body of verifyAttestationSignatures and
    //  verifyGovernanceSignatures. Resolves the active validator
    //  set, parses the signature block, and verifies every entry
    //  against the corresponding validator's consensus key at
    //  ctx.current_height.
    //
    //  Returns false on any failure (empty set, below quorum, bad
    //  parse, bad index, unknown key, bad signature).
    bool verifyActiveValidatorSignatures(
        State::StateAccess &state,
        std::string_view domain,
        const uint8_t *message, size_t message_len,
        const uint8_t *signatures, size_t signatures_len,
        const TxExecutionContext &ctx)
    {
      if (domain.size() != 4)
        return false;

      std::vector<Id> active = TransactionExecutor::loadActiveSet(state);
      std::sort(active.begin(), active.end());

      if (active.empty())
        return false;

      const size_t threshold = Core::bftQuorum(active.size());

      std::vector<BridgeSignatureEntry> sigs;
      if (!parseBridgeSignatureBlock(signatures, signatures_len, sigs))
        return false;

      if (sigs.size() < threshold)
        return false;

      std::vector<bool> seen(active.size(), false);
      for (const auto &e : sigs)
      {
        if (e.signer_index >= active.size())
          return false;
        if (seen[e.signer_index])
          return false;
        seen[e.signer_index] = true;
      }

      const Crypto::Hash hash =
          bridgeSigningHash(domain, message, message_len);

      for (const auto &e : sigs)
      {
        const Id validator_id = active[e.signer_index];

        auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
        if (!pk.has_value())
          return false;

        if (!Crypto::verify(hash, *pk, e.signature))
          return false;
      }

      return true;
    }
  } // anonymous namespace

  //  Dispatch

  Receipt TransactionExecutor::execute(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (!tx.isWellFormed())
      return failure;

    if (tx.chain_id != ctx.chain_id)
      return failure;

    if (!checkExpiry(tx, ctx))
      return failure;

    if (!verifySignature(tx))
      return failure;

    if (!verifyNonce(state, tx))
      return failure;

    if (!chargeFee(state, tx))
      return failure;

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

    case TxType::CreateNftCollection:
      receipt = executeCreateNftCollection(state, tx, ctx);
      break;

    case TxType::MintNft:
      receipt = executeMintNft(state, tx, ctx);
      break;

    case TxType::WrapNft:
      receipt = executeWrapNft(state, tx, ctx);
      break;

    case TxType::TransferNft:
      receipt = executeTransferNft(state, tx, ctx);
      break;

    case TxType::BurnNft:
      receipt = executeBurnNft(state, tx, ctx);
      break;

    case TxType::UpdateNftMetadata:
      receipt = executeUpdateNftMetadata(state, tx, ctx);
      break;

    case TxType::TopUpNft:
      receipt = executeTopUpNft(state, tx, ctx);
      break;

    case TxType::ClaimNftReward:
      receipt = executeClaimNftReward(state, tx, ctx);
      break;

    case TxType::RefillCollectionReward:
      receipt = executeRefillCollectionReward(state, tx, ctx);
      break;

    case TxType::CreateAmmFarm:
      receipt = executeCreateAmmFarm(state, tx, ctx);
      break;

    case TxType::UpdateAmmFarm:
      receipt = executeUpdateAmmFarm(state, tx, ctx);
      break;

    case TxType::PauseAmmFarm:
      receipt = executePauseAmmFarm(state, tx, ctx);
      break;

    case TxType::RefillAmmFarm:
      receipt = executeRefillAmmFarm(state, tx, ctx);
      break;

    case TxType::CloseAmmFarm:
      receipt = executeCloseAmmFarm(state, tx, ctx);
      break;

    case TxType::ClaimAmmFarmRewards:
      receipt = executeClaimAmmFarmRewards(state, tx, ctx);
      break;

    case TxType::BridgeMint:
      receipt = executeBridgeMint(state, tx, ctx);
      break;

    case TxType::BridgeBurn:
      receipt = executeBridgeBurn(state, tx, ctx);
      break;

    case TxType::BridgePause:
      receipt = executeBridgePause(state, tx, ctx);
      break;

    case TxType::BridgeUnpause:
      receipt = executeBridgeUnpause(state, tx, ctx);
      break;

    case TxType::BridgeAckWithdrawal:
      receipt = executeBridgeAckWithdrawal(state, tx, ctx);
      break;

    case TxType::BridgeRegisterChain:
      receipt = executeBridgeRegisterChain(state, tx, ctx);
      break;

    case TxType::BridgeAttest:
      receipt = executeBridgeAttest(state, tx, ctx);
      break;

    case TxType::BridgeAckAttest:
      receipt = executeBridgeAckAttest(state, tx, ctx);
      break;

    case TxType::RegisterBridgeWatcher:
    case TxType::UnregisterBridgeWatcher:
      //  Reserved types. Rejected by dispatch. There is no handler:
      //  a validator is a bridge watcher, so there is nothing to
      //  register or unregister separately.
      return failure;

    default:
      return failure;
    }

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

    if (validator.owner != tx.from)
      return failure;

    if (validator.effectiveConsensusKey() == new_key)
      return failure;

    if (validator.pending_unbond_height != 0)
      return failure;

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

    history.back().valid_until_height = ctx.current_height;

    Core::KeyRotation entry;
    entry.key = new_key;
    entry.valid_from_height = ctx.current_height;
    entry.valid_until_height = 0;
    history.push_back(entry);

    state.putValidatorKeyHistory(validator_id, history);

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

    TokenInfo token;
    if (!state.getToken(tx.token_id, token))
      return failure;

    if (token.isBridged())
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

    if (token_a == NATIVE_TOKEN_ID &&
        amount_a < MIN_POOL_LIQUIDITY)
      return failure;
    if (token_b == NATIVE_TOKEN_ID &&
        amount_b < MIN_POOL_LIQUIDITY)
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

    const __uint128_t prod = static_cast<__uint128_t>(amount_a) * amount_b;
    pool.total_liquidity = isqrt128(prod);

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
    pos.liquidity = isqrt128(prod);
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
        //  Settle farm accrual before the position's shares change.
        //  The accrual for the epochs up to this point must be
        //  computed against the *current* liquidity, not the
        //  post-add liquidity. Without this, a mid-epoch add
        //  retroactively over-credits the position for past epochs
        //  at the new, larger share count.
        const uint64_t accrued = settleAmmFarmAccrual(state, pos);
        if (accrued > 0)
        {
          Core::Account acct = state.getAccount(tx.from);
          acct.pending_rewards += accrued;
          state.putAccount(tx.from, acct);
        }

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

    //  If a farm exists on this pool, initialize the accrual
    //  companion with last_rps = the farm's current rps_per_share.
    //  A position that joins a running farm starts earning from the
    //  next boundary, not from the farm's beginning. If the farm
    //  does not exist yet, this is a no-op; the first settle will
    //  see last_rps = 0, which is correct because the farm's
    //  rps_per_share is also 0 at creation.
    Core::AmmFarmSchedule farm;
    if (state.getAmmFarm(pool_id, farm))
    {
      Core::AmmPositionAccrual accrual;
      accrual.position_id = pos.id;
      accrual.last_rps = farm.rps_per_share;
      state.putAmmPositionAccrual(accrual);
    }

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

    if (tx.payload.size() != 16)
      return failure;

    const uint64_t position_id = readU64At(tx.payload, 0);
    const uint64_t requested_amount = readU64At(tx.payload, 8);

    AmmPosition pos;
    if (!state.getAmmPosition(position_id, pos))
      return failure;
    if (pos.owner != tx.from)
      return failure;
    if (pos.liquidity == 0)
      return failure;

    const uint64_t amount =
        (requested_amount == 0) ? pos.liquidity : requested_amount;

    if (amount > pos.liquidity)
      return failure;

    AmmPool pool;
    if (!state.getAmmPool(pos.pool_id, pool))
      return failure;

    //  Settle farm accrual BEFORE the position's shares change.
    //  The accrual is computed against the pre-removal liquidity,
    //  so this must run before `pos.liquidity -= amount` (or the
    //  last-removal zeroing below).
    //
    //  settleAmmFarmAccrual persists the new last_rps and returns
    //  the accrued amount. We credit it to pending_rewards here;
    //  one position, one account write.
    const uint64_t farm_accrued = settleAmmFarmAccrual(state, pos);
    if (farm_accrued > 0)
    {
      Account acct = state.getAccount(tx.from);
      acct.pending_rewards += farm_accrued;
      state.putAccount(tx.from, acct);
    }

    const bool is_last_removal = (amount == pool.total_liquidity);

    uint64_t share_a = 0;
    uint64_t share_b = 0;

    if (is_last_removal)
    {
      share_a = pool.reserve_a;
      share_b = pool.reserve_b;
    }
    else
    {
      share_a = static_cast<uint64_t>(
          static_cast<unsigned __int128>(amount) * pool.reserve_a /
          pool.total_liquidity);
      share_b = static_cast<uint64_t>(
          static_cast<unsigned __int128>(amount) * pool.reserve_b /
          pool.total_liquidity);
    }

    pool.reserve_a -= share_a;
    pool.reserve_b -= share_b;
    pool.total_liquidity -= amount;
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

    if (is_last_removal)
    {
      pos.liquidity = 0;
      state.putAmmPosition(pos);
      state.deletePositionIndex(pos.owner, pos.pool_id);
      //  Delete the farm accrual companion too. The AmmPosition
      //  record lingers (v1 policy), but the accrual record has no
      //  reason to; leaving it would be an orphan key, and it
      //  would cost 16 bytes per position ever created.
      state.deleteAmmPositionAccrual(pos.id);
    }
    else
    {
      pos.liquidity -= amount;
      state.putAmmPosition(pos);
    }

    if (pool.isClosed())
    {
      //  A full drain closes the farm too. Refund any remaining
      //  escrow to the creator, then delete the schedule. The
      //  debit is guaranteed to succeed by the invariant that the
      //  escrow custody balance always equals
      //  farm.reward_escrow_remaining; a failure here means state
      //  corruption and should fail the whole remove so the block
      //  is rejected and the operator investigates.
      Core::AmmFarmSchedule farm;
      if (state.getAmmFarm(pool.id, farm))
      {
        if (farm.reward_escrow_remaining > 0)
        {
          const Crypto::Address custody =
              State::Keys::ammFarmAddress(pool.id);
          if (!debitToken(state, custody, farm.reward_token_id,
                          farm.reward_escrow_remaining))
          {
            return failure;
          }
          creditToken(state, farm.creator, farm.reward_token_id,
                      farm.reward_escrow_remaining);
        }
        state.deleteAmmFarm(pool.id);
      }

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

    const uint64_t amount_in_with_fee = static_cast<uint64_t>(
        static_cast<__uint128_t>(amount_in) * (10'000 - pool.fee_bps) / 10'000);

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

    if (!validateCreateOrderStructure(tx))
      return failure;

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

    std::vector<Fill> fills;

    if (order.mode == OrderExecutionMode::Passive)
    {
      MatchOutcome outcome = matchPassiveOrder(
          state, order, ctx.current_height, ctx.tx_index_in_block);
      fills = std::move(outcome.fills);
    }
    else
    {
      if (order.condition_count == 0)
      {
        const auto outcome = BlockProcessor::executeActiveOrder(
            state, order, ctx.current_height, ctx.tx_index_in_block, fills);

        if (outcome == ActiveRouteOutcome::Unroutable)
        {
          return failure;
        }
      }
    }

    Order still_exists;
    if (state.getOrder(order.id, still_exists) &&
        expires_at_height != 0)
    {
      state.addOrderExpiry(expires_at_height, order.id);
    }

    uint64_t new_next = next_id + 1;
    std::vector<uint8_t> new_id_bytes(8);
    for (int i = 0; i < 8; ++i)
      new_id_bytes[i] = uint8_t(new_next >> (i * 8));
    state.putGlobal("next_order_id", new_id_bytes);

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

  //  ---- NFT handlers (identical to the current version) ----

  Receipt TransactionExecutor::executeCreateNftCollection(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() < 1)
      return failure;

    size_t off = 0;
    const uint8_t name_len = tx.payload[off++];
    if (off + name_len > tx.payload.size())
      return failure;
    std::string name(reinterpret_cast<const char *>(tx.payload.data() + off), name_len);
    off += name_len;

    if (off + 1 > tx.payload.size())
      return failure;
    const uint8_t sym_len = tx.payload[off++];
    if (off + sym_len > tx.payload.size())
      return failure;
    std::string symbol(reinterpret_cast<const char *>(tx.payload.data() + off), sym_len);
    off += sym_len;

    if (off + 2 > tx.payload.size())
      return failure;
    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len > tx.payload.size())
      return failure;
    std::string base_uri(reinterpret_cast<const char *>(tx.payload.data() + off), uri_len);
    off += uri_len;

    if (off + 4 + 8 + 8 > tx.payload.size())
      return failure;
    const Id reward_token_id = readU32At(tx.payload, off);
    off += 4;
    const uint64_t reward_rate_per_epoch = readU64At(tx.payload, off);
    off += 8;
    const uint64_t reward_escrow_amount = readU64At(tx.payload, off);
    off += 8;

    uint64_t next_id = readU64GlobalInternal(state, "next_collection_id");
    if (next_id == 0)
      next_id = 1;

    Core::NftCollection c;
    c.id = next_id;
    c.creator = tx.from;
    c.name = std::move(name);
    c.symbol = std::move(symbol);
    c.base_uri = std::move(base_uri);
    c.reward_token_id = reward_token_id;
    c.reward_rate_per_epoch = reward_rate_per_epoch;
    c.created_at_height = ctx.current_height;

    if (!c.isValid())
      return failure;

    if (reward_escrow_amount > 0)
    {
      if (!debitToken(state, tx.from, reward_token_id, reward_escrow_amount))
        return failure;
      creditToken(state, State::Keys::nftCollectionAddress(c.id),
                  reward_token_id, reward_escrow_amount);
      c.reward_escrow_remaining = reward_escrow_amount;
    }

    state.putNftCollection(c);
    writeU64GlobalInternal(state, "next_collection_id", c.id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeMintNft(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() < 8 + 32 + 1 + 2)
      return failure;

    size_t off = 0;
    const uint64_t collection_id = readU64At(tx.payload, off);
    off += 8;

    Crypto::Hash metadata_hash;
    std::memcpy(metadata_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint8_t has_hash = tx.payload[off++];
    if (has_hash > 1)
      return failure;
    if (has_hash == 0 && !metadata_hash.isNull())
      return failure;
    if (has_hash == 0)
      metadata_hash = Crypto::Hash{};

    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len > tx.payload.size())
      return failure;
    std::string uri(reinterpret_cast<const char *>(tx.payload.data() + off), uri_len);
    off += uri_len;

    if (uri.size() > NFT_URI_MAX)
      return failure;

    Core::NftCollection collection;
    if (collection_id != 0)
    {
      if (!state.getNftCollection(collection_id, collection))
        return failure;
    }

    uint64_t next_token_id = readU64GlobalInternal(state, "next_token_id");
    if (next_token_id == 0)
      next_token_id = 1;
    const uint64_t next_nft_id = next_token_id;

    Core::TokenInfo shadow;
    shadow.id = static_cast<Id>(next_nft_id);
    shadow.decimals = 0;
    shadow.maxSupply = 1;
    shadow.creator = tx.from;
    shadow.backing = Core::BackingModel::Unbacked;

    if (collection_id != 0)
    {
      shadow.name = collection.name + " #" + std::to_string(next_nft_id);
      shadow.symbol = collection.symbol;
    }
    else
    {
      shadow.name = "NFT #" + std::to_string(next_nft_id);
      shadow.symbol = "NFT";
    }

    if (!shadow.isValid())
      return failure;

    state.putToken(shadow);
    state.putTokenSupply(shadow.id, 1);
    state.putTokenBalance(tx.from, shadow.id, 1);

    Core::NftInfo nft;
    nft.id = next_nft_id;
    nft.owner = tx.from;
    nft.creator = tx.from;
    nft.shadow_token_id = shadow.id;
    nft.underlying_token_id = 0;
    nft.wrapped_amount = 0;
    nft.collection_id = collection_id;
    nft.metadata_hash = metadata_hash;
    nft.metadata_uri = std::move(uri);
    nft.last_accrual_height = ctx.current_height;
    nft.created_at_height = ctx.current_height;

    if (!nft.isValid())
      return failure;

    state.putNft(nft);

    if (collection_id != 0)
    {
      collection.minted_count += 1;
      state.putNftCollection(collection);
    }

    writeU64GlobalInternal(state, "next_token_id", nft.id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeWrapNft(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() < 4 + 8 + 8 + 32 + 1 + 2)
      return failure;

    size_t off = 0;
    const Id underlying_token_id = readU32At(tx.payload, off);
    off += 4;
    const uint64_t wrapped_amount = readU64At(tx.payload, off);
    off += 8;
    const uint64_t collection_id = readU64At(tx.payload, off);
    off += 8;

    Crypto::Hash metadata_hash;
    std::memcpy(metadata_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint8_t has_hash = tx.payload[off++];
    if (has_hash > 1)
      return failure;
    if (has_hash == 0 && !metadata_hash.isNull())
      return failure;
    if (has_hash == 0)
      metadata_hash = Crypto::Hash{};

    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len > tx.payload.size())
      return failure;
    std::string uri(reinterpret_cast<const char *>(tx.payload.data() + off), uri_len);

    if (underlying_token_id == 0)
      return failure;
    if (wrapped_amount == 0)
      return failure;
    if (uri.size() > NFT_URI_MAX)
      return failure;

    Core::NftCollection collection;
    if (collection_id != 0)
    {
      if (!state.getNftCollection(collection_id, collection))
        return failure;
    }

    uint64_t next_token_id = readU64GlobalInternal(state, "next_token_id");
    if (next_token_id == 0)
      next_token_id = 1;
    const uint64_t next_nft_id = next_token_id;

    if (underlying_token_id == next_nft_id)
      return failure;

    Core::TokenInfo shadow;
    shadow.id = static_cast<Id>(next_nft_id);
    shadow.decimals = 0;
    shadow.maxSupply = 1;
    shadow.creator = tx.from;
    shadow.backing = Core::BackingModel::Unbacked;

    if (collection_id != 0)
    {
      shadow.name = collection.name + " #" + std::to_string(next_nft_id);
      shadow.symbol = collection.symbol;
    }
    else
    {
      shadow.name = "NFT #" + std::to_string(next_nft_id);
      shadow.symbol = "NFT";
    }

    if (!shadow.isValid())
      return failure;

    if (!debitToken(state, tx.from, underlying_token_id, wrapped_amount))
      return failure;

    const Crypto::Address custody = State::Keys::nftAddress(next_nft_id);
    creditToken(state, custody, underlying_token_id, wrapped_amount);

    state.putToken(shadow);
    state.putTokenSupply(shadow.id, 1);
    state.putTokenBalance(tx.from, shadow.id, 1);

    Core::NftInfo nft;
    nft.id = next_nft_id;
    nft.owner = tx.from;
    nft.creator = tx.from;
    nft.shadow_token_id = shadow.id;
    nft.underlying_token_id = underlying_token_id;
    nft.wrapped_amount = wrapped_amount;
    nft.collection_id = collection_id;
    nft.metadata_hash = metadata_hash;
    nft.metadata_uri = std::move(uri);
    nft.last_accrual_height = ctx.current_height;
    nft.created_at_height = ctx.current_height;

    if (!nft.isValid())
      return failure;

    state.putNft(nft);

    if (collection_id != 0)
    {
      collection.minted_count += 1;
      state.putNftCollection(collection);
    }

    writeU64GlobalInternal(state, "next_token_id", nft.id + 1);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeTransferNft(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() != 8 + 32)
      return failure;

    const uint64_t nft_id = readU64At(tx.payload, 0);
    Crypto::Address new_owner;
    std::memcpy(new_owner.data.data(), tx.payload.data() + 8, 32);

    if (new_owner.isNull())
      return failure;

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.owner != tx.from)
      return failure;

    if (nft.owner == new_owner)
      return failure;

    if (nft.collection_id != 0)
    {
      Core::NftCollection collection;
      if (state.getNftCollection(nft.collection_id, collection) &&
          collection.hasReward())
      {
        const uint64_t accrued =
            (ctx.current_height - nft.last_accrual_height) /
            ROTATION_INTERVAL * collection.reward_rate_per_epoch;
        if (accrued > 0)
        {
          Core::Account acct = state.getAccount(nft.owner);
          acct.pending_rewards += accrued;
          state.putAccount(nft.owner, acct);
        }
      }
    }

    const uint64_t shadow_balance =
        state.getTokenBalance(nft.owner, nft.shadow_token_id);
    if (shadow_balance < 1)
      return failure;

    state.putTokenBalance(nft.owner, nft.shadow_token_id, shadow_balance - 1);

    const uint64_t buyer_balance =
        state.getTokenBalance(new_owner, nft.shadow_token_id);
    state.putTokenBalance(new_owner, nft.shadow_token_id, buyer_balance + 1);

    state.unindexNft(nft);

    nft.owner = new_owner;
    nft.last_accrual_height = ctx.current_height;
    nft.accrued_owed = 0;

    state.putNft(nft);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeBurnNft(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() != 8)
      return failure;

    const uint64_t nft_id = readU64At(tx.payload, 0);

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.owner != tx.from)
      return failure;

    if (nft.collection_id != 0)
    {
      Core::NftCollection collection;
      if (state.getNftCollection(nft.collection_id, collection) &&
          collection.hasReward())
      {
        const uint64_t accrued =
            (ctx.current_height - nft.last_accrual_height) /
            ROTATION_INTERVAL * collection.reward_rate_per_epoch;
        if (accrued > 0)
        {
          Core::Account acct = state.getAccount(nft.owner);
          acct.pending_rewards += accrued;
          state.putAccount(nft.owner, acct);
        }
      }
    }

    const uint64_t shadow_balance =
        state.getTokenBalance(nft.owner, nft.shadow_token_id);
    if (shadow_balance < 1)
      return failure;

    state.putTokenBalance(nft.owner, nft.shadow_token_id, shadow_balance - 1);
    state.putTokenSupply(nft.shadow_token_id, 0);

    if (nft.isWrapped() && nft.wrapped_amount > 0)
    {
      const Crypto::Address custody = State::Keys::nftAddress(nft_id);
      if (!debitToken(state, custody, nft.underlying_token_id, nft.wrapped_amount))
      {
        return failure;
      }
      creditToken(state, nft.owner, nft.underlying_token_id, nft.wrapped_amount);
    }

    state.deleteNft(nft_id);

    if (nft.collection_id != 0)
    {
      Core::NftCollection collection;
      if (state.getNftCollection(nft.collection_id, collection))
      {
        if (collection.minted_count > 0)
          collection.minted_count -= 1;
        state.putNftCollection(collection);
      }
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeUpdateNftMetadata(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() < 8 + 32 + 1 + 2)
      return failure;

    size_t off = 0;
    const uint64_t nft_id = readU64At(tx.payload, off);
    off += 8;

    Crypto::Hash new_hash;
    std::memcpy(new_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint8_t has_hash = tx.payload[off++];
    if (has_hash > 1)
      return failure;
    if (has_hash == 0)
      new_hash = Crypto::Hash{};

    const uint16_t uri_len =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;
    if (off + uri_len + 1 > tx.payload.size())
      return failure;

    std::string new_uri(reinterpret_cast<const char *>(tx.payload.data() + off), uri_len);
    off += uri_len;

    const uint8_t freeze = tx.payload[off];

    if (freeze > 1)
      return failure;
    if (new_uri.size() > NFT_URI_MAX)
      return failure;

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.owner != tx.from)
      return failure;
    if (nft.frozen)
      return failure;

    nft.metadata_hash = new_hash;
    nft.metadata_uri = std::move(new_uri);
    if (freeze == 1)
      nft.frozen = true;

    if (!nft.isValid())
      return failure;

    state.putNft(nft);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeTopUpNft(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() != 8 + 4 + 8)
      return failure;

    const uint64_t nft_id = readU64At(tx.payload, 0);
    const Id token_id = readU32At(tx.payload, 8);
    const uint64_t amount = readU64At(tx.payload, 12);

    if (amount == 0)
      return failure;

    Core::NftInfo nft;
    if (!state.getNft(nft_id, nft))
      return failure;

    if (nft.isWrapped() && token_id != nft.underlying_token_id)
      return failure;

    if (!debitToken(state, tx.from, token_id, amount))
      return failure;

    const Crypto::Address custody = State::Keys::nftAddress(nft_id);
    creditToken(state, custody, token_id, amount);

    if (nft.isWrapped() && token_id == nft.underlying_token_id)
    {
      nft.wrapped_amount += amount;
      state.putNft(nft);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeClaimNftReward(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (!tx.payload.empty())
      return failure;

    Core::Account acct = state.getAccount(tx.from);
    uint64_t total_claimed = 0;

    state.forEachNftForOwner(tx.from,
                             [&](const Core::NftInfo &nft)
                             {
                               if (nft.collection_id == 0)
                                 return;
                               Core::NftCollection collection;
                               if (!state.getNftCollection(nft.collection_id, collection))
                                 return;
                               if (!collection.hasReward())
                                 return;
                               const uint64_t accrued =
                                   (ctx.current_height - nft.last_accrual_height) /
                                   ROTATION_INTERVAL * collection.reward_rate_per_epoch;
                               if (accrued == 0)
                                 return;
                               total_claimed += accrued;
                               Core::NftInfo updated = nft;
                               updated.last_accrual_height = ctx.current_height;
                               updated.accrued_owed = 0;
                               state.putNft(updated);
                             });

    if (total_claimed > 0)
    {
      acct.pending_rewards += total_claimed;
      state.putAccount(tx.from, acct);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeRefillCollectionReward(
      State::StateAccess &state, const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};
    if (tx.payload.size() != 16)
      return failure;

    const uint64_t collection_id = readU64At(tx.payload, 0);
    const uint64_t amount = readU64At(tx.payload, 8);

    if (amount == 0)
      return failure;

    Core::NftCollection collection;
    if (!state.getNftCollection(collection_id, collection))
      return failure;

    if (!collection.hasReward())
      return failure;

    if (collection.creator != tx.from)
      return failure;

    if (!debitToken(state, tx.from, collection.reward_token_id, amount))
      return failure;

    creditToken(state, State::Keys::nftCollectionAddress(collection_id),
                collection.reward_token_id, amount);

    collection.reward_escrow_remaining += amount;
    if (collection.reward_paused && collection.reward_escrow_remaining > 0)
      collection.reward_paused = false;

    state.putNftCollection(collection);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  AMM farming
  //  =========================================================================

  Receipt TransactionExecutor::executeCreateAmmFarm(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload:
    //    [8] pool_id
    //    [4] reward_token_id
    //    [8] reward_rate_per_epoch
    //    [8] reward_escrow_amount
    //  Total: 28 bytes.
    if (tx.payload.size() != 8 + 4 + 8 + 8)
      return failure;

    size_t off = 0;
    const uint64_t pool_id = readU64At(tx.payload, off);
    off += 8;
    const Id reward_token_id = readU32At(tx.payload, off);
    off += 4;
    const uint64_t reward_rate_per_epoch = readU64At(tx.payload, off);
    off += 8;
    const uint64_t reward_escrow_amount = readU64At(tx.payload, off);
    off += 8;

    if (reward_rate_per_epoch == 0)
      return failure;
    if (reward_escrow_amount == 0)
      return failure;

    AmmPool pool;
    if (!state.getAmmPool(pool_id, pool))
      return failure;
    if (!pool.active)
      return failure;

    //  One farm per pool.
    AmmFarmSchedule existing;
    if (state.getAmmFarm(pool_id, existing))
      return failure;

    AmmFarmSchedule farm;
    farm.pool_id = pool_id;
    farm.creator = tx.from;
    farm.reward_token_id = reward_token_id;
    farm.reward_rate_per_epoch = reward_rate_per_epoch;
    farm.reward_escrow_remaining = reward_escrow_amount;
    farm.reward_paused = false;
    farm.rps_per_share = 0;
    farm.created_at_height = ctx.current_height;

    if (!farm.isValid())
      return failure;

    if (!debitToken(state, tx.from, reward_token_id, reward_escrow_amount))
      return failure;

    creditToken(state, State::Keys::ammFarmAddress(pool_id),
                reward_token_id, reward_escrow_amount);

    //  Put the record last, so it only exists after the escrow has
    //  actually moved. If a future change makes creditToken able to
    //  fail, this order leaves no phantom farm with a phantom escrow.
    state.putAmmFarm(farm);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeUpdateAmmFarm(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload:
    //    [8] pool_id
    //    [8] new_rate_per_epoch
    //  Total: 16 bytes.
    if (tx.payload.size() != 8 + 8)
      return failure;

    const uint64_t pool_id = readU64At(tx.payload, 0);
    const uint64_t new_rate = readU64At(tx.payload, 8);

    if (new_rate == 0)
      return failure;

    AmmFarmSchedule farm;
    if (!state.getAmmFarm(pool_id, farm))
      return failure;

    if (farm.creator != tx.from)
      return failure;

    farm.reward_rate_per_epoch = new_rate;
    state.putAmmFarm(farm);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executePauseAmmFarm(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload:
    //    [8] pool_id
    //  Total: 8 bytes.
    if (tx.payload.size() != 8)
      return failure;

    const uint64_t pool_id = readU64At(tx.payload, 0);

    AmmFarmSchedule farm;
    if (!state.getAmmFarm(pool_id, farm))
      return failure;

    if (farm.creator != tx.from)
      return failure;

    farm.reward_paused = true;
    state.putAmmFarm(farm);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeRefillAmmFarm(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload:
    //    [8] pool_id
    //    [8] amount
    //  Total: 16 bytes.
    if (tx.payload.size() != 8 + 8)
      return failure;

    const uint64_t pool_id = readU64At(tx.payload, 0);
    const uint64_t amount = readU64At(tx.payload, 8);

    if (amount == 0)
      return failure;

    AmmFarmSchedule farm;
    if (!state.getAmmFarm(pool_id, farm))
      return failure;

    if (farm.creator != tx.from)
      return failure;

    if (!debitToken(state, tx.from, farm.reward_token_id, amount))
      return failure;

    creditToken(state, State::Keys::ammFarmAddress(pool_id),
                farm.reward_token_id, amount);

    farm.reward_escrow_remaining += amount;
    if (farm.reward_paused && farm.reward_escrow_remaining > 0)
      farm.reward_paused = false;

    state.putAmmFarm(farm);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeCloseAmmFarm(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    //  Payload:
    //    [8] pool_id
    //  Total: 8 bytes.
    if (tx.payload.size() != 8)
      return failure;

    const uint64_t pool_id = readU64At(tx.payload, 0);

    AmmFarmSchedule farm;
    if (!state.getAmmFarm(pool_id, farm))
      return failure;

    if (farm.creator != tx.from)
      return failure;

    //  A live pool cannot have its farm closed. The path to close is:
    //  pause, drain the pool (last LP's remove closes the pool and
    //  the farm together), or close while the pool is already
    //  drained. A pause is required even after the pool is drained,
    //  because closing a running farm forfeits unclaimed accrual and
    //  the pause is the creator's signal to LPs that emissions have
    //  stopped.
    AmmPool pool;
    if (state.getAmmPool(pool_id, pool))
    {
      if (pool.total_liquidity > 0)
        return failure;
    }

    if (!farm.reward_paused)
      return failure;

    if (farm.reward_escrow_remaining > 0)
    {
      const Crypto::Address custody =
          State::Keys::ammFarmAddress(pool_id);
      if (!debitToken(state, custody, farm.reward_token_id,
                      farm.reward_escrow_remaining))
        return failure;
      creditToken(state, farm.creator, farm.reward_token_id,
                  farm.reward_escrow_remaining);
    }

    state.deleteAmmFarm(pool_id);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeClaimAmmFarmRewards(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext & /*ctx*/)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (!tx.payload.empty())
      return failure;

    //  Settle every position the caller holds, accumulating into one
    //  pending_rewards credit. This matches executeClaimNftReward's
    //  shape: one account write for the whole claim, no matter how
    //  many positions were settled.
    //
    //  The actual balance movement is done by the standard
    //  ClaimRewards transaction, exactly as for staking and NFT
    //  rewards. This tx only settles accrual into pending_rewards.
    uint64_t total_accrued = 0;

    state.forEachPositionForOwner(
        tx.from,
        [&](const Core::AmmPosition &pos)
        {
          const uint64_t accrued = settleAmmFarmAccrual(state, pos);
          if (accrued > 0)
            total_accrued += accrued;
        });

    if (total_accrued > 0)
    {
      Account acct = state.getAccount(tx.from);
      acct.pending_rewards += total_accrued;
      state.putAccount(tx.from, acct);
    }

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — verifiers
  //  =========================================================================
  //
  //  Both verifiers resolve the active validator set at
  //  ctx.current_height, parse the [2] count || N*66 signature block,
  //  enforce bftQuorum(active_count), and verify every entry
  //  against the corresponding validator's consensus key at
  //  ctx.current_height.
  //
  //  verifyAttestationSignatures and verifyGovernanceSignatures share
  //  the same body. The two names exist because their call sites
  //  pass different domains ("bmin"/"back" vs "bpau"/"bunp"/"brgr"),
  //  and keeping the names keeps those call sites self-documenting.
  //  The `source_chain_id` parameter on verifyAttestationSignatures is
  //  retained for the same reason: it's not used to resolve a
  //  per-chain set, but it tells a future reader which chain the
  //  attestation is about.

  bool TransactionExecutor::verifyAttestationSignatures(
      State::StateAccess &state,
      uint64_t /*source_chain_id*/,
      std::string_view domain,
      const uint8_t *message, size_t message_len,
      const uint8_t *signatures, size_t signatures_len,
      const TxExecutionContext &ctx)
  {
    return verifyActiveValidatorSignatures(
        state, domain,
        message, message_len,
        signatures, signatures_len,
        ctx);
  }

  bool TransactionExecutor::verifyGovernanceSignatures(
      State::StateAccess &state,
      std::string_view domain,
      const uint8_t *message, size_t message_len,
      const uint8_t *signatures, size_t signatures_len,
      const TxExecutionContext &ctx)
  {
    return verifyActiveValidatorSignatures(
        state, domain,
        message, message_len,
        signatures, signatures_len,
        ctx);
  }

  //  =========================================================================
  //  Bridge — BridgeMint
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgeMint(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 32 + 4 + 32 + 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    Crypto::Hash source_tx_hash;
    std::memcpy(source_tx_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint32_t source_output_index = readU32At(tx.payload, off);
    off += 4;

    Crypto::Address destination;
    std::memcpy(destination.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint64_t amount = readU64At(tx.payload, off);
    off += 8;

    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    if (amount == 0)
      return failure;
    if (destination.isNull())
      return failure;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    Core::TokenInfo token;
    if (!state.getToken(reg.wrapped_token_id, token))
      return failure;
    if (!token.isBridged() ||
        !token.fingerprint.has_value() ||
        *token.fingerprint != reg.fingerprint)
      return failure;

    uint64_t existing_mint_height = 0;
    if (state.getBridgeConsumed(source_chain_id, source_tx_hash,
                                source_output_index, existing_mint_height))
      return failure;

    const std::vector<uint8_t> message = encodeBridgeMintMessage(
        source_chain_id, source_tx_hash, source_output_index,
        destination, amount);

    if (!verifyAttestationSignatures(
            state, source_chain_id, "bmin",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    const uint64_t existing_balance =
        state.getTokenBalance(destination, reg.wrapped_token_id);
    state.putTokenBalance(destination, reg.wrapped_token_id,
                          existing_balance + amount);

    const uint64_t supply = state.getTokenSupply(reg.wrapped_token_id);
    state.putTokenSupply(reg.wrapped_token_id, supply + amount);

    state.putBridgeConsumed(source_chain_id, source_tx_hash,
                            source_output_index, ctx.current_height);

    GlobalStateWriter writer(state);
    writer.setBridgeConsumedCount(reader.bridgeConsumedCount() + 1);

    bumpBridgeStats(state, source_chain_id, ctx.current_height,
                    /*minted*/ amount, /*burned*/ 0, /*released*/ 0,
                    /*count_deposit*/ true,
                    /*count_withdrawal*/ false,
                    /*count_release*/ false);

    recordBridgeEvent(state, Core::BridgeEventKind::Mint,
                      source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/source_tx_hash,
                      /*has_source=*/true,
                      /*source_output_index=*/source_output_index,
                      /*withdrawal_id=*/0,
                      /*amount=*/amount,
                      /*counterparty=*/0);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — BridgeBurn
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgeBurn(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 1 + 8)
      return failure;

    size_t off = 0;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    const uint8_t blob_len = tx.payload[off];
    off += 1;

    if (tx.payload.size() < off + blob_len + 1 + 8)
      return failure;

    std::vector<uint8_t> destination_blob(blob_len);
    if (blob_len > 0)
    {
      std::memcpy(destination_blob.data(), tx.payload.data() + off, blob_len);
      off += blob_len;
    }

    const uint8_t addr_len = tx.payload[off];
    off += 1;

    if (tx.payload.size() != off + addr_len + 8)
      return failure;

    std::string destination_address;
    if (addr_len > 0)
    {
      destination_address.assign(
          reinterpret_cast<const char *>(tx.payload.data() + off), addr_len);
      off += addr_len;
    }

    const uint64_t amount = readU64At(tx.payload, off);

    if (amount == 0)
      return failure;
    if (destination_address.empty())
      return failure;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    if (tx.token_id != reg.wrapped_token_id)
      return failure;

    if (blob_len < reg.destination_blob_min_len ||
        blob_len > reg.destination_blob_max_len)
      return failure;

    const uint64_t balance = state.getTokenBalance(tx.from, tx.token_id);
    if (balance < amount)
      return failure;

    state.putTokenBalance(tx.from, tx.token_id, balance - amount);

    const uint64_t supply = state.getTokenSupply(tx.token_id);
    state.putTokenSupply(tx.token_id,
                         supply >= amount ? supply - amount : 0);

    uint64_t next_id = reader.bridgeNextWithdrawalId();
    if (next_id == 0)
      next_id = 1;

    Core::BridgeWithdrawal w;
    w.id = next_id;
    w.source_chain_id = source_chain_id;
    w.wrapped_token_id = tx.token_id;
    w.burner = tx.from;
    w.amount = amount;
    w.destination_blob = std::move(destination_blob);
    w.destination_address = std::move(destination_address);
    w.created_at_height = ctx.current_height;

    if (!w.isWellFormed())
      return failure;

    state.putBridgeWithdrawal(w);

    GlobalStateWriter writer(state);
    writer.setBridgeNextWithdrawalId(next_id + 1);
    writer.setBridgeWithdrawalsPending(reader.bridgeWithdrawalsPending() + 1);

    bumpBridgeStats(state, source_chain_id, ctx.current_height,
                    /*minted*/ 0, /*burned*/ amount, /*released*/ 0,
                    /*count_deposit*/ false,
                    /*count_withdrawal*/ true,
                    /*count_release*/ false);

    recordBridgeEvent(state, Core::BridgeEventKind::Burn,
                      source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/Crypto::Hash{},
                      /*has_source=*/false,
                      /*source_output_index=*/0,
                      /*withdrawal_id=*/w.id,
                      /*amount=*/amount,
                      /*counterparty=*/0);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — Pause / Unpause (governance)
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgePause(State::StateAccess &state,
                                                  const Transaction &tx,
                                                  const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t bound_height = 0;
    for (int i = 0; i < 8; ++i)
      bound_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    std::vector<uint8_t> message;
    message.reserve(8);
    for (int i = 0; i < 8; ++i)
      message.push_back(uint8_t(bound_height >> (i * 8)));

    if (!verifyGovernanceSignatures(
            state, "bpau",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    GlobalStateWriter writer(state);
    writer.setBridgePaused(true);

    return {ReceiptStatus::Success, tx.fee};
  }

  Receipt TransactionExecutor::executeBridgeUnpause(State::StateAccess &state,
                                                    const Transaction &tx,
                                                    const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t bound_height = 0;
    for (int i = 0; i < 8; ++i)
      bound_height |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    std::vector<uint8_t> message;
    message.reserve(8);
    for (int i = 0; i < 8; ++i)
      message.push_back(uint8_t(bound_height >> (i * 8)));

    if (!verifyGovernanceSignatures(
            state, "bunp",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    GlobalStateWriter writer(state);
    writer.setBridgePaused(false);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — AckWithdrawal
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgeAckWithdrawal(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 8 + 32 + 8 + 2)
      return failure;

    size_t off = 0;

    uint64_t withdrawal_id = 0;
    for (int i = 0; i < 8; ++i)
      withdrawal_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    Crypto::Hash release_tx_hash;
    std::memcpy(release_tx_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint64_t release_height = readU64At(tx.payload, off);
    off += 8;

    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    if (release_tx_hash.isNull())
      return failure;
    if (release_height == 0)
      return failure;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeWithdrawal w;
    if (!state.getBridgeWithdrawal(withdrawal_id, w))
      return failure;
    if (!w.isWellFormed())
      return failure;

    if (w.isReleased())
    {
      if (w.release_tx_hash == release_tx_hash &&
          w.release_height == release_height)
      {
        return {ReceiptStatus::Success, tx.fee};
      }
      return failure;
    }

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(w.source_chain_id, reg))
      return failure;

    const std::vector<uint8_t> message = encodeBridgeAckMessage(withdrawal_id);

    if (!verifyAttestationSignatures(
            state, w.source_chain_id, "back",
            message.data(), message.size(),
            sigs_ptr, sigs_len, ctx))
      return failure;

    w.release_tx_hash = release_tx_hash;
    w.release_height = release_height;
    w.released_at_height = ctx.current_height;
    state.putBridgeWithdrawal(w);

    //  Attribute the release to the submitting validator, if the
    //  sender maps to a registered validator. Under the
    //  validator-is-watcher model there is no per-chain watcher
    //  lookup; the address either maps to a validator or it doesn't,
    //  and the validator's presence on-chain is the attribution.
    {
      uint64_t validator_id = 0;
      if (state.getValidatorByAddress(tx.from, validator_id))
      {
        w.released_by_validator_id = validator_id;
      }
    }

    if (!w.isWellFormed())
      return failure;

    state.putBridgeWithdrawal(w);

    GlobalStateWriter writer(state);
    const uint64_t pending = reader.bridgeWithdrawalsPending();
    writer.setBridgeWithdrawalsPending(pending > 0 ? pending - 1 : 0);

    bumpBridgeStats(state, w.source_chain_id, ctx.current_height,
                    /*minted*/ 0, /*burned*/ 0, /*released*/ w.amount,
                    /*count_deposit*/ false,
                    /*count_withdrawal*/ false,
                    /*count_release*/ true);

    recordBridgeEvent(state, Core::BridgeEventKind::AckWithdrawal,
                      w.source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/Crypto::Hash{},
                      /*has_source=*/false,
                      /*source_output_index=*/0,
                      /*withdrawal_id=*/withdrawal_id,
                      /*amount=*/w.amount,
                      /*counterparty=*/release_height);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — RegisterChain (governance)
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgeRegisterChain(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() < 1 + 2)
      return failure;

    size_t off = 0;

    const uint8_t reg_len = tx.payload[off];
    off += 1;

    if (off + reg_len + 2 > tx.payload.size())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!Core::BridgeChainRegistration::deserializeState(
            tx.payload.data() + off, reg_len, reg))
      return failure;
    off += reg_len;

    const size_t sig_block_off = off;
    const size_t sig_block_len = tx.payload.size() - sig_block_off;

    if (sig_block_len < 2)
      return failure;
    const uint16_t signer_count =
        uint16_t(tx.payload[sig_block_off]) |
        (uint16_t(tx.payload[sig_block_off + 1]) << 8);
    if (sig_block_len != 2 + static_cast<size_t>(signer_count) * 66)
      return failure;

    const uint8_t *sigs_ptr = tx.payload.data() + sig_block_off;
    const size_t sigs_len = sig_block_len;

    const uint8_t *msg_ptr = tx.payload.data() + 1;
    const size_t msg_len = reg_len;

    if (!verifyGovernanceSignatures(
            state, "brgr",
            msg_ptr, msg_len,
            sigs_ptr, sigs_len, ctx))
      return failure;

    Core::BridgeChainRegistration existing;
    if (state.getBridgeChainRegistration(reg.source_chain_id, existing))
      return failure;

    if (!adoptOrCreateWrappedTokenImpl(state, reg))
      return failure;

    if (!reg.isWellFormed())
      return failure;

    state.putBridgeChainRegistration(reg);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — BridgeAttest
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgeAttest(State::StateAccess &state,
                                                   const Transaction &tx,
                                                   const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 8 + 32 + 4 + 32 + 8 + 2 + 64)
      return failure;

    size_t off = 0;

    uint64_t source_chain_id = 0;
    for (int i = 0; i < 8; ++i)
      source_chain_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    Crypto::Hash source_tx_hash;
    std::memcpy(source_tx_hash.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint32_t source_output_index = readU32At(tx.payload, off);
    off += 4;

    Crypto::Address destination;
    std::memcpy(destination.data.data(), tx.payload.data() + off, 32);
    off += 32;

    const uint64_t amount = readU64At(tx.payload, off);
    off += 8;

    const uint16_t signer_index =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;

    Crypto::Signature signature;
    std::memcpy(signature.data.data(), tx.payload.data() + off, 64);
    off += 64;

    if (amount == 0)
      return failure;
    if (destination.isNull())
      return failure;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    uint64_t existing_mint_height = 0;
    if (state.getBridgeConsumed(source_chain_id, source_tx_hash,
                                source_output_index, existing_mint_height))
      return failure;

    std::vector<Core::ValidatorInfo> active;
    state.forEachActiveValidator(
        [&](const Core::ValidatorInfo &v)
        { active.push_back(v); });

    std::sort(active.begin(), active.end(),
              [](const Core::ValidatorInfo &a, const Core::ValidatorInfo &b)
              { return a.id < b.id; });

    if (active.size() < reg.active_validator_min)
      return failure;

    if (signer_index >= active.size())
      return failure;

    const Id validator_id = active[signer_index].id;

    auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
    if (!pk.has_value())
      return failure;

    const std::vector<uint8_t> message = encodeBridgeMintMessage(
        source_chain_id, source_tx_hash, source_output_index,
        destination, amount);

    const Crypto::Hash hash =
        bridgeSigningHash("bmin", message.data(), message.size());

    const bool ok = Crypto::verify(hash, *pk, signature);
    if (!ok)
      return failure;

    {
      Core::BridgeAttestation existing;
      if (state.getBridgeAttestation(
              source_chain_id, source_tx_hash, source_output_index,
              validator_id, existing))
        return failure;
    }

    bool has_conflict = false;
    state.forEachBridgeAttestationForDeposit(
        source_chain_id, source_tx_hash, source_output_index,
        [&](uint64_t /*other_vid*/, const Core::BridgeAttestation &other) -> bool
        {
          if (other.destination != destination || other.amount != amount)
          {
            has_conflict = true;
            return false;
          }
          return true;
        });

    if (has_conflict)
      return failure;

    Core::BridgeAttestation attestation;
    attestation.signer_index = signer_index;
    attestation.signature = signature;
    attestation.destination = destination;
    attestation.amount = amount;
    attestation.attested_at_height = ctx.current_height;

    if (!attestation.isWellFormed())
      return failure;

    state.putBridgeAttestation(source_chain_id, source_tx_hash,
                               source_output_index, validator_id,
                               attestation);

    return {ReceiptStatus::Success, tx.fee};
  }

  //  =========================================================================
  //  Bridge — BridgeAckAttest
  //  =========================================================================

  Receipt TransactionExecutor::executeBridgeAckAttest(
      State::StateAccess &state,
      const Transaction &tx,
      const TxExecutionContext &ctx)
  {
    Receipt failure{ReceiptStatus::Failure, tx.fee};

    if (tx.payload.size() != 8 + 2 + 64)
      return failure;

    size_t off = 0;

    uint64_t withdrawal_id = 0;
    for (int i = 0; i < 8; ++i)
      withdrawal_id |= uint64_t(tx.payload[off + i]) << (i * 8);
    off += 8;

    const uint16_t signer_index =
        uint16_t(tx.payload[off]) | (uint16_t(tx.payload[off + 1]) << 8);
    off += 2;

    Crypto::Signature signature;
    std::memcpy(signature.data.data(), tx.payload.data() + off, 64);
    off += 64;

    GlobalStateReader reader(state);
    if (reader.bridgePaused())
      return failure;

    Core::BridgeWithdrawal w;
    if (!state.getBridgeWithdrawal(withdrawal_id, w))
      return failure;
    if (!w.isWellFormed())
      return failure;
    if (w.isReleased())
      return failure;

    Core::BridgeChainRegistration reg;
    if (!state.getBridgeChainRegistration(w.source_chain_id, reg))
      return failure;
    if (!reg.isWellFormed() || !reg.enabled)
      return failure;

    std::vector<Core::ValidatorInfo> active;
    state.forEachActiveValidator(
        [&](const Core::ValidatorInfo &v)
        { active.push_back(v); });

    std::sort(active.begin(), active.end(),
              [](const Core::ValidatorInfo &a, const Core::ValidatorInfo &b)
              { return a.id < b.id; });

    if (active.size() < reg.active_validator_min)
      return failure;

    if (signer_index >= active.size())
      return failure;

    const Id validator_id = active[signer_index].id;

    auto pk = state.validatorKeyAtHeight(validator_id, ctx.current_height);
    if (!pk.has_value())
      return failure;

    const std::vector<uint8_t> message = encodeBridgeAckMessage(withdrawal_id);
    const Crypto::Hash hash =
        bridgeSigningHash("back", message.data(), message.size());

    if (!Crypto::verify(hash, *pk, signature))
      return failure;

    std::cerr << "[executeBridgeAckAttest] verify="
              << (Crypto::verify(hash, *pk, signature) ? "OK" : "FAIL")
              << "\n";

    {
      Core::BridgeAckAttestation existing;
      if (state.getBridgeAckAttestation(withdrawal_id, validator_id, existing))
        return failure;
    }

    Core::BridgeAckAttestation attestation;
    attestation.signer_index = signer_index;
    attestation.signature = signature;
    attestation.attested_at_height = ctx.current_height;

    if (!attestation.isWellFormed())
      return failure;

    state.putBridgeAckAttestation(withdrawal_id, validator_id, attestation);

    recordBridgeEvent(state, Core::BridgeEventKind::AckAttest,
                      w.source_chain_id, ctx.current_height,
                      ctx.tx_index_in_block, tx.txid(),
                      /*actor=*/tx.from,
                      /*source_tx_hash=*/Crypto::Hash{},
                      /*has_source=*/false,
                      /*source_output_index=*/0,
                      /*withdrawal_id=*/withdrawal_id,
                      /*amount=*/0,
                      /*counterparty=*/validator_id);

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

    if (tx.token_id == buy_token)
      return false;
    if (tx.amount == 0)
      return false;
    if (min_buy_amount == 0)
      return false;

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

  //  adoptOrCreateWrappedToken (public wrapper)

  bool TransactionExecutor::adoptOrCreateWrappedToken(
      State::StateAccess &state,
      Core::BridgeChainRegistration &reg)
  {
    return adoptOrCreateWrappedTokenImpl(state, reg);
  }

} // namespace Core