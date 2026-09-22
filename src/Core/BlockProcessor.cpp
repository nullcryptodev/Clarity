// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BlockProcessor.h"

#include "Account.h"
#include "Block.h"
#include "RewardCalculator.h"
#include "RewardTypes.h"
#include "TransactionExecutor.h"
#include "TransactionTypes.h"
#include "ValidatorRotation.h"
#include "ValidatorTypes.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "State/StateAccess.h"
#include "Consensus/Message.h"

#include <algorithm>
#include <cstring>

namespace Core
{
  namespace
  {
    uint64_t readU64Global(State::StateAccess &state, const char *name)
    {
      std::vector<uint8_t> bytes;
      if (!state.getGlobal(name, bytes) || bytes.size() != 8)
        return 0;

      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(bytes[i]) << (i * 8);
      return v;
    }

    void writeU64Global(State::StateAccess &state, const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(v >> (i * 8));
      state.putGlobal(name, bytes);
    }

    // How many blocks of the epoch [epoch_start, epoch_end] was this
    // account staked for? Returns a value in [0, epoch_blocks].
    uint64_t blocksStakedIn(const Core::Account &acct,
                            uint64_t epoch_start,
                            uint64_t epoch_end,
                            uint64_t epoch_blocks)
    {
      if (acct.staked == 0)
        return 0;
      if (acct.staker_since_height == 0)
        return 0;

      uint64_t effective_start = std::max(acct.staker_since_height, epoch_start);
      if (effective_start > epoch_end)
        return 0;

      uint64_t blocks = epoch_end + 1 - effective_start;
      if (blocks > epoch_blocks)
        blocks = epoch_blocks;
      return blocks;
    }
  } // anonymous namespace

  //  Public entry points

  BlockResult BlockProcessor::applyBlock(State::StateAccess &state,
                                         const Block &block,
                                         const BlockContext &ctx)
  {
    BlockResult result;
    result.block_hash = block.hash();

    std::string error;
    if (!checkHeader(block, ctx, error))
    {
      result.error = error;
      return result;
    }

    if (!checkTxRoot(block, error))
    {
      result.error = error;
      return result;
    }

    std::vector<Id> active_set = loadActiveSet(state);

    if (active_set.size() != block.header.active_validator_count)
    {
      result.error = "active validator count mismatch";
      return result;
    }

    // Quorum signatures are added after the round's prevote quorum
    // forms, so a block being simulated by the proposer has no
    // signatures yet. The check is a validation of the finalized
    // block, not part of the state transition it produces. Skip it
    // during dry-run.
    if (!ctx.dry_run && !checkQuorum(state, block, active_set, error))
    {
      result.error = error;
      return result;
    }

    if (!checkValidatorSetRoot(block, active_set, error))
    {
      result.error = error;
      return result;
    }

    std::vector<Receipt> receipts;
    std::vector<Crypto::Hash> tx_hashes;

    if (!applyTransactions(state, block, ctx, receipts, tx_hashes, error))
    {
      result.error = error;
      return result;
    }

    for (auto vid : block.participants)
    {
      ValidatorInfo v;
      if (!state.getValidator(vid, v))
        continue;
      v.last_seen_height = ctx.current_height;
      state.putValidator(v);
    }

    if ((ctx.current_height + 1) % OFFLINE_CHECK_INTERVAL == 0)
    {
      runOfflineCheck(state, ctx);
    }

    processOrderExpiries(state, ctx.current_height);

    distributeRewards(state, block, ctx);

    updateGlobalState(state, block, ctx);

    if ((ctx.current_height + 1) % ROTATION_INTERVAL == 0)
    {
      processEpochBoundary(state, block, ctx);
    }

    if ((ctx.current_height + 1) % ROTATION_INTERVAL == 0)
    {
      processRotation(state, block, ctx);
    }

    result.new_state_root = state.stateRoot();

    const bool skip_state_root_check =
        ctx.dry_run || block.header.state_root.isNull();

    if (!skip_state_root_check &&
        block.header.state_root != result.new_state_root)
    {
      result.error = "state root mismatch: expected " +
                     block.header.state_root.toString() +
                     ", got " + result.new_state_root.toString();
      return result;
    }

    if (!block.header.receipts_root.isNull())
    {
      if (!verifyReceiptsRoot(state, tx_hashes, receipts,
                              block.header.receipts_root, error))
      {
        result.error = error;
        return result;
      }
    }

    result.valid = true;
    result.receipts = std::move(receipts);
    result.tx_hashes = std::move(tx_hashes);

    return result;
  }

  BlockResult BlockProcessor::validateBlock(State::StateAccess &state,
                                            const Block &block,
                                            const BlockContext &ctx)
  {
    return applyBlock(state, block, ctx);
  }

  //  Header checks

  bool BlockProcessor::checkHeader(const Block &block,
                                   const BlockContext &ctx,
                                   std::string &error)
  {
    if (!block.header.isWellFormed())
    {
      error = "block header not well-formed";
      return false;
    }

    if (block.header.chain_id != ctx.chain_id)
    {
      error = "chain_id mismatch";
      return false;
    }

    if (block.header.height != ctx.current_height)
    {
      error = "height mismatch";
      return false;
    }

    if (ctx.current_height > 0 && block.header.parent_hash.isNull())
    {
      error = "parent hash is null";
      return false;
    }

    uint64_t now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    if (block.header.timestamp_ms > now_ms + 2000)
    {
      error = "timestamp is too far in the future";
      return false;
    }

    return true;
  }

  bool BlockProcessor::checkTxRoot(const Block &block, std::string &error)
  {
    Crypto::Hash computed = computeTxRoot(block.transactions);
    if (computed != block.header.tx_root)
    {
      error = "tx_root mismatch";
      return false;
    }
    return true;
  }

  bool BlockProcessor::checkQuorum(State::StateAccess &state,
                                   const Block &block,
                                   const std::vector<Id> &active_set,
                                   std::string &error)
  {
    const size_t threshold = bftQuorum(active_set.size());
    if (block.quorum_signatures.size() < threshold)
    {
      error = "insufficient quorum signatures";
      return false;
    }

    std::vector<bool> seen(active_set.size(), false);

    for (const auto &vs : block.quorum_signatures)
    {
      if (vs.signer_index == INVALID_INDEX)
      {
        error = "invalid signer index";
        return false;
      }
      if (vs.signer_index >= active_set.size())
      {
        error = "signer index out of range";
        return false;
      }
      if (seen[vs.signer_index])
      {
        error = "duplicate signature from same signer";
        return false;
      }
      seen[vs.signer_index] = true;
    }

    Crypto::Hash signing_hash = Consensus::voteSigningHash(
        block.header.height,
        block.header.commit_round,
        /*is_nil=*/false,
        block.hash());

    for (const auto &vs : block.quorum_signatures)
    {
      // Resolve validator id from active_set[signer_index].
      Id vid = active_set[vs.signer_index];

      ValidatorInfo v;
      if (!state.getValidator(vid, v))
      {
        error = "quorum signature from unknown validator";
        return false;
      }

      // The codebase convention: a validator's signing key is its
      // reward_address. Same convention as Node::getSignerPublicKey.
      Crypto::PublicKey pk = v.reward_address;

      if (!Crypto::verify(signing_hash, pk, vs.signature))
      {
        error = "invalid quorum signature";
        return false;
      }
    }

    return true;
  }

  bool BlockProcessor::checkValidatorSetRoot(
      const Block &block,
      const std::vector<Id> &active_set,
      std::string &error)
  {
    Crypto::Hash computed = computeValidatorSetRoot(active_set);
    if (computed != block.header.validator_set_root)
    {
      error = "validator_set_root mismatch";
      return false;
    }
    return true;
  }

  //  Transaction application

  bool BlockProcessor::applyTransactions(State::StateAccess &state,
                                         const Block &block,
                                         const BlockContext &ctx,
                                         std::vector<Receipt> &receipts,
                                         std::vector<Crypto::Hash> &tx_hashes,
                                         std::string &error)
  {
    receipts.reserve(block.transactions.size());
    tx_hashes.reserve(block.transactions.size());

    for (size_t i = 0; i < block.transactions.size(); ++i)
    {
      const Transaction &tx = block.transactions[i];

      if (isSystemTx(tx.tx_type))
      {
        Receipt r{ReceiptStatus::Success, 0};
        receipts.push_back(r);
        tx_hashes.push_back(tx.txid());
        continue;
      }

      if (!tx.isWellFormed())
      {
        error = "malformed transaction at index " + std::to_string(i);
        return false;
      }

      TxExecutionContext exec_ctx;
      exec_ctx.current_height = ctx.current_height;
      exec_ctx.chain_id = ctx.chain_id;
      exec_ctx.tx_index_in_block = i;

      Receipt r = TransactionExecutor::execute(state, tx, exec_ctx);

      if (r.status != ReceiptStatus::Success)
      {
        error = "transaction failed at index " + std::to_string(i) + " (type=" + std::string(txTypeName(tx.tx_type)) + ")";
        return false;
      }

      receipts.push_back(r);
      tx_hashes.push_back(tx.txid());
    }

    return true;
  }

  //  Order expiries

  void BlockProcessor::processOrderExpiries(State::StateAccess &state,
                                            uint64_t current_height)
  {
    std::vector<uint64_t> expiring =
        state.getOrdersExpiringAt(current_height);

    if (expiring.empty())
      return;

    for (uint64_t order_id : expiring)
    {
      Order order;
      if (!state.getOrder(order_id, order))
        continue;

      uint64_t refund = order.remainingAmount();
      if (refund > 0)
      {
        if (order.sell_token == NATIVE_TOKEN_ID)
        {
          Account acct = state.getAccount(order.owner);
          acct.balance += refund;
          state.putAccount(order.owner, acct);
        }
        else
        {
          uint64_t bal = state.getTokenBalance(order.owner, order.sell_token);
          state.putTokenBalance(order.owner, order.sell_token, bal + refund);
        }
      }

      state.deleteOrder(order_id);
    }

    state.clearOrderExpiry(current_height);
  }

  //  Reward distribution

  void BlockProcessor::distributeRewards(State::StateAccess &state,
                                         const Block &block,
                                         const BlockContext &ctx)
  {
    RewardContext reward_ctx;
    reward_ctx.height = ctx.current_height;
    reward_ctx.epoch_number = epochOf(ctx.current_height);
    reward_ctx.active_set_size = block.header.active_validator_count;
    reward_ctx.block_reward_atomic = GlobalConfig::BLOCK_REWARD;

    reward_ctx.total_staked = readU64Global(state, "total_staked");

    std::vector<Id> active_set = loadActiveSet(state);

    ValidatorRegistry registry;
    registry.active_set = active_set;
    registry.validators.reserve(active_set.size() + 1);
    registry.validators.push_back(ValidatorInfo{});

    for (auto vid : active_set)
    {
      ValidatorInfo v;
      if (!state.getValidator(vid, v))
      {
        ValidatorInfo placeholder;
        placeholder.id = vid;
        registry.validators.push_back(placeholder);
        continue;
      }
      registry.validators.push_back(v);
    }

    BlockRewardResult rewards = computeBlockReward(reward_ctx, registry);

    uint64_t total_redistributed = 0;

    if (rewards.producer_amount > 0 && !active_set.empty())
    {
      Id producer_id = active_set[0];

      uint64_t indexed_id = 0;
      if (state.getValidatorByAddress(block.header.proposer, indexed_id))
      {
        producer_id = indexed_id;
      }

      ValidatorInfo producer;
      if (state.getValidator(producer_id, producer))
      {
        uint64_t adjusted =
            rewards.producer_amount * producer.reward_multiplier / 10'000;
        uint64_t difference = rewards.producer_amount - adjusted;

        if (adjusted > 0)
        {
          Account acct = state.getAccount(producer.reward_address);
          acct.balance += adjusted;
          state.putAccount(producer.reward_address, acct);
        }

        producer.total_rewards_earned += adjusted;
        state.putValidator(producer);

        total_redistributed += difference;
      }
      else
      {
        total_redistributed += rewards.producer_amount;
      }
    }

    for (const auto &r : rewards.validator_rewards)
    {
      ValidatorInfo v;
      if (!state.getValidator(r.validator_id, v))
      {
        total_redistributed += r.amount;
        continue;
      }

      uint64_t adjusted = r.amount * v.reward_multiplier / 10'000;
      uint64_t difference = r.amount - adjusted;

      if (adjusted > 0)
      {
        Account acct = state.getAccount(v.reward_address);
        acct.balance += adjusted;
        state.putAccount(v.reward_address, acct);
      }

      v.total_rewards_earned += adjusted;
      state.putValidator(v);

      total_redistributed += difference;
    }

    uint64_t pot = readU64Global(state, "pot");
    pot += total_redistributed;

    uint64_t staker_pool = applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);
    pot += staker_pool;

    writeU64Global(state, "pot", pot);
  }

  //  Global state updates

  void BlockProcessor::updateGlobalState(State::StateAccess &state,
                                         const Block &block,
                                         const BlockContext &ctx)
  {
    uint64_t total_fees = 0;
    for (const auto &tx : block.transactions)
    {
      total_fees += tx.fee;
    }

    uint64_t supply = readU64Global(state, "total_supply");
    supply += GlobalConfig::BLOCK_REWARD;
    writeU64Global(state, "total_supply", supply);

    uint64_t epoch = epochOf(ctx.current_height);
    writeU64Global(state, "epoch_number", epoch);
  }

  //  Epoch boundary processing

  void BlockProcessor::processEpochBoundary(State::StateAccess &state,
                                            const Block &block,
                                            const BlockContext &ctx)
  {
    // ========================================================================
    //  Epoch boundary
    //
    //  Runs at the last block of each epoch. Reads the pot, computes the
    //  target staker payout, credits each staker their proportional
    //  share, and adjusts the pot.
    //
    //  The epoch's staker pool has already been added to the pot on a
    //  per-block basis by distributeRewards. Here we distribute from the
    //  pot, not from a fresh pool.
    //
    //  Stakers who joined mid-epoch receive a partial share proportional
    //  to the number of blocks in the epoch for which they were staked
    //  (tracked via Account::staker_since_height).
    // ========================================================================

    const uint64_t pot = readU64Global(state, "pot");
    const uint64_t total_staked = readU64Global(state, "total_staked");
    const uint64_t staker_count = readU64Global(state, "staker_count");

    const uint64_t epoch_end_height = ctx.current_height;
    const uint64_t epoch_start_height =
        (epoch_end_height + 1 >= ROTATION_INTERVAL)
            ? epoch_end_height + 1 - ROTATION_INTERVAL
            : 0;

    const uint64_t staker_pool_per_block =
        applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);
    const uint64_t epoch_pool = staker_pool_per_block * ROTATION_INTERVAL;

    const uint64_t pool_baseline = epoch_pool;

    const uint64_t avg_tx_per_block = block.transactions.size();
    const uint16_t apy_activity_bps = computeActivityBps(avg_tx_per_block);

    const uint16_t apy_pot_bonus_bps = computePotBonusBps(pot, pool_baseline);

    RewardContext rctx;
    rctx.height = ctx.current_height;
    rctx.epoch_number = epochOf(ctx.current_height);
    rctx.active_set_size = block.header.active_validator_count;
    rctx.total_staked = total_staked;
    rctx.pot = pot;
    rctx.fees_this_block = 0;
    rctx.block_reward_atomic = GlobalConfig::BLOCK_REWARD;
    rctx.apy_base_bps = APY_BASE_BPS;
    rctx.apy_activity_bps = apy_activity_bps;
    rctx.apy_pot_bonus_bps = apy_pot_bonus_bps;

    const uint16_t effective_apy =
        computeEffectiveApy(rctx, SECONDS_PER_EPOCH);

    const uint64_t target_payout =
        computeTargetStakerPayout(rctx, effective_apy, SECONDS_PER_EPOCH);

    PotAdjustment adj = applyPotMechanics(
        epoch_pool,
        target_payout,
        pot,
        pool_baseline);

    int64_t pot_delta = static_cast<int64_t>(adj.added_to_pot) -
                        static_cast<int64_t>(adj.drained_from_pot);
    int64_t new_pot = static_cast<int64_t>(pot) + pot_delta;
    if (new_pot < 0)
      new_pot = 0;

    uint64_t pot_max = pool_baseline * POT_MAX_EPOCHS;
    if (static_cast<uint64_t>(new_pot) > pot_max)
    {
      adj.burned = static_cast<uint64_t>(new_pot) - pot_max;
      new_pot = static_cast<int64_t>(pot_max);
    }

    writeU64Global(state, "pot", static_cast<uint64_t>(new_pot));

    if (adj.distributed == 0 || total_staked == 0 || staker_count == 0)
      return;

    __uint128_t total_time_weight = 0;

    state.forEachStaker([&](const Crypto::Address &addr)
                        {
      Account acct = state.getAccount(addr);
      uint64_t blocks_staked = blocksStakedIn(
          acct, epoch_start_height, epoch_end_height, ROTATION_INTERVAL);
      if (blocks_staked == 0)
        return;

      uint64_t weight = acct.staked;
      if (acct.staked >= BALANCE_BONUS_THRESHOLD)
      {
        __uint128_t w = static_cast<__uint128_t>(weight) *
                        (10'000 + BALANCE_BONUS_BPS);
        weight = static_cast<uint64_t>(w / 10'000);
      }

      total_time_weight += static_cast<__uint128_t>(weight) * blocks_staked; });

    if (total_time_weight == 0)
      return;

    state.forEachStaker([&](const Crypto::Address &addr)
                        {
      Account acct = state.getAccount(addr);
      uint64_t blocks_staked = blocksStakedIn(
          acct, epoch_start_height, epoch_end_height, ROTATION_INTERVAL);
      if (blocks_staked == 0)
        return;

      uint64_t weight = acct.staked;
      if (acct.staked >= BALANCE_BONUS_THRESHOLD)
      {
        __uint128_t w = static_cast<__uint128_t>(weight) *
                        (10'000 + BALANCE_BONUS_BPS);
        weight = static_cast<uint64_t>(w / 10'000);
      }

      __uint128_t time_weight =
          static_cast<__uint128_t>(weight) * blocks_staked;

      __uint128_t share_128 =
          static_cast<__uint128_t>(adj.distributed) * time_weight /
          total_time_weight;
      uint64_t share = static_cast<uint64_t>(share_128);

      acct.pending_rewards += share;
      acct.last_reward_epoch = rctx.epoch_number;

      state.putAccount(addr, acct); });
  }

  //  Validator rotation

  void BlockProcessor::processRotation(State::StateAccess &state,
                                       const Block &block,
                                       const BlockContext &ctx)
  {
    std::vector<Id> active_set = loadActiveSet(state);
    if (active_set.empty())
      return;

    ValidatorRegistry registry;
    registry.active_set = active_set;

    registry.validators.push_back(ValidatorInfo{});

    uint64_t next_validator_id = 1;
    {
      std::vector<uint8_t> bytes;
      if (state.getGlobal("next_validator_id", bytes) && bytes.size() == 8)
      {
        next_validator_id = 0;
        for (int i = 0; i < 8; ++i)
          next_validator_id |= uint64_t(bytes[i]) << (i * 8);
      }
    }

    for (uint64_t id = 1; id < next_validator_id; ++id)
    {
      ValidatorInfo v;
      if (!state.getValidator(id, v))
        continue;

      while (registry.validators.size() <= id)
        registry.validators.push_back(ValidatorInfo{});
      registry.validators[id] = v;
    }

    {
      std::vector<uint8_t> bytes;
      if (state.getGlobal("active_set_size", bytes) && bytes.size() == 8)
      {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
          v |= uint64_t(bytes[i]) << (i * 8);
        registry.target_size = v;
      }

      bytes.clear();
      if (state.getGlobal("last_rotation_height", bytes) && bytes.size() == 8)
      {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
          v |= uint64_t(bytes[i]) << (i * 8);
        registry.last_rotation_height = v;
      }
    }

    const uint64_t avg_tx_per_block = block.transactions.size();

    RotationPlan plan = planRotation(registry, avg_tx_per_block);

    if (plan.to_remove.empty() && plan.to_add.empty() &&
        plan.new_target_size == registry.target_size)
    {
      return;
    }

    applyRotation(registry, plan, ctx.current_height);

    for (const auto &v : registry.validators)
    {
      if (v.id == INVALID_ID)
        continue;
      state.putValidator(v);
    }

    std::vector<uint8_t> set_bytes;
    set_bytes.reserve(registry.active_set.size() * 8);
    for (auto vid : registry.active_set)
    {
      for (int i = 0; i < 8; ++i)
        set_bytes.push_back(uint8_t(vid >> (i * 8)));
    }
    state.putGlobal("active_set", set_bytes);

    writeU64Global(state, "active_set_size", plan.new_target_size);
    writeU64Global(state, "last_rotation_height", ctx.current_height);
  }

  //  Verification helpers

  bool BlockProcessor::verifyStateRoot(const Crypto::Hash &computed,
                                       const Crypto::Hash &expected,
                                       std::string &error)
  {
    if (computed != expected)
    {
      error = "state root mismatch";
      return false;
    }
    return true;
  }

  bool BlockProcessor::verifyReceiptsRoot(State::StateAccess & /*state*/,
                                          const std::vector<Crypto::Hash> &tx_hashes,
                                          const std::vector<Receipt> &receipts,
                                          const Crypto::Hash &expected,
                                          std::string &error)
  {
    if (tx_hashes.size() != receipts.size())
    {
      error = "tx_hash / receipt count mismatch";
      return false;
    }

    std::vector<Crypto::Hash> leaves;
    leaves.reserve(receipts.size());

    for (size_t i = 0; i < receipts.size(); ++i)
    {
      std::vector<uint8_t> buf;
      buf.reserve(4 + 32 + 1 + 8);
      buf.push_back('r');
      buf.push_back('c');
      buf.push_back('p');
      buf.push_back('t');

      const auto &th = tx_hashes[i];
      buf.insert(buf.end(), th.data.begin(), th.data.end());

      buf.push_back(static_cast<uint8_t>(receipts[i].status));

      uint64_t fee = receipts[i].fee_paid;
      for (int j = 0; j < 8; ++j)
        buf.push_back(uint8_t(fee >> (j * 8)));

      Crypto::Hash h;
      Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
      leaves.push_back(h);
    }

    Crypto::Hash computed = computeMerkleRoot(leaves);

    if (computed != expected)
    {
      error = "receipts_root mismatch";
      return false;
    }
    return true;
  }

  //  Helpers

  std::vector<Id> BlockProcessor::loadActiveSet(State::StateAccess &state)
  {
    std::vector<Id> result;

    std::vector<uint8_t> set_bytes;
    if (!state.getGlobal("active_set", set_bytes))
    {
      return result;
    }

    size_t count = set_bytes.size() / 8;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t id = 0;
      for (int j = 0; j < 8; ++j)
      {
        id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
      }
      result.push_back(id);
    }

    return result;
  }

  uint64_t BlockProcessor::epochOf(uint64_t height) noexcept
  {
    return height / ROTATION_INTERVAL;
  }

  uint64_t BlockProcessor::rotationIndexOf(uint64_t height) noexcept
  {
    return height / ROTATION_INTERVAL;
  }

  void BlockProcessor::runOfflineCheck(State::StateAccess &state,
                                       const BlockContext &ctx)
  {
    std::vector<Id> active_set = loadActiveSet(state);

    if (active_set.empty())
      return;

    ValidatorRegistry registry;
    registry.active_set = active_set;
    registry.validators.reserve(active_set.size() + 1);
    registry.validators.push_back(ValidatorInfo{});

    for (auto vid : active_set)
    {
      ValidatorInfo v;
      if (!state.getValidator(vid, v))
      {
        continue;
      }
      registry.validators.push_back(v);
    }

    auto plan = planOfflineRemoval(registry, ctx.current_height);

    if (plan.removed.empty() && plan.promoted.empty())
    {
      return;
    }

    applyOfflineRemoval(registry, plan, ctx.current_height);

    for (const auto &v : registry.validators)
    {
      if (v.id == INVALID_ID)
        continue;
      state.putValidator(v);
    }

    std::vector<uint8_t> set_bytes;
    set_bytes.reserve(registry.active_set.size() * 8);
    for (auto vid : registry.active_set)
    {
      for (int i = 0; i < 8; ++i)
      {
        set_bytes.push_back(uint8_t(vid >> (i * 8)));
      }
    }
    state.putGlobal("active_set", set_bytes);
  }
} // namespace Core