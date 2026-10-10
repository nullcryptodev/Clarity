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
#include "EquivocationProof.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "State/StateAccess.h"
#include "Consensus/Message.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>
#include <iostream>

namespace Core
{
  namespace
  {
    //  Read a uint64 from the meta table (MDBX, not the SMT). Used
    //  for aggregation counters that don't participate in the state
    //  root: tx_counter, total_fees_lifetime, total_to_pot,
    //  total_pot_distributed, last_effective_apy_bps.
    uint64_t readU64Meta(State::StateAccess &state, const char *name)
    {
      return state.getMetaU64(name);
    }

    uint64_t nowMs() noexcept
    {
      using namespace std::chrono;
      return duration_cast<milliseconds>(
                 system_clock::now().time_since_epoch())
          .count();
    }

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

    //  Increment the running lifetime counters by this block's
    //  contribution. Called from applyBlock after transactions and
    //  rewards have run, so tx_counter reflects only successfully
    //  applied transactions (a block whose transactions all failed
    //  would have been rejected before this point).
    //
    //  total_fees_lifetime counts the fees paid by transactions in
    //  this block. Every fee goes to the pot eventually, but the
    //  pot itself also accumulates from other sources (validator
    //  penalties, slash proceeds, seed-only set shares). The two
    //  numbers are related but not equal — total_fees_lifetime is
    //  "fees ever paid", pot is "rewards currently unclaimed".
    void bumpLifetimeCounters(State::StateAccess &state, const Block &block)
    {
      //  tx_counter and total_fees_lifetime are aggregation counters:
      //  they are read by the RPC to display explorer statistics, and
      //  nothing in the block-apply path branches on them. Keeping
      //  them in the SMT would make the state root depend on values
      //  that no verifier needs to reproduce, and it would invalidate
      //  every previously-committed block whose state_root was
      //  computed before these counters existed.
      //
      //  They belong in the meta table alongside total_to_pot,
      //  total_pot_distributed, and last_effective_apy_bps, which are
      //  the same category of value.

      uint64_t tx_counter = state.getMetaU64("tx_counter");
      tx_counter += block.transactions.size();
      state.putMetaU64("tx_counter", tx_counter);

      uint64_t fees = state.getMetaU64("total_fees_lifetime");
      fees += block.header.total_fees;
      state.putMetaU64("total_fees_lifetime", fees);
    }
  } // anonymous namespace

  //  Public entry points

  std::vector<Id> BlockProcessor::resolveActiveSet(
      State::StateAccess &state,
      const std::vector<Id> &committed_set,
      uint64_t current_height,
      bool force_rotation)
  {
    return Core::resolveActiveSet(state, committed_set,
                                  current_height, force_rotation);
  }

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

    std::vector<Id> committed_set = loadActiveSet(state);
    const bool is_emergency = (block.header.emergency_rotation > 0);

    if (is_emergency)
    {
      if (!checkTimeoutCertificate(state, block, committed_set,
                                   ctx.current_height, error))
      {
        result.error = error;
        return result;
      }
    }

    std::vector<Id> active_set = is_emergency
                                     ? resolveActiveSet(state, committed_set, ctx.current_height, true)
                                     : committed_set;

    if (active_set.size() != block.header.active_validator_count)
    {
      result.error = "active validator count mismatch";
      return result;
    }

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

    if (!applyTransactions(state, block, ctx, active_set,
                           receipts, tx_hashes, error))
    {
      result.error = error;
      return result;
    }

    if (is_emergency && active_set != committed_set)
    {
      std::unordered_set<Id> was_active(
          committed_set.begin(), committed_set.end());
      std::unordered_set<Id> now_active(
          active_set.begin(), active_set.end());

      for (Id vid : committed_set)
      {
        if (now_active.count(vid) > 0)
          continue;

        ValidatorInfo v;
        if (!state.getValidator(vid, v))
          continue;
        v.is_active = false;
        v.last_active_at = ctx.current_height;
        state.putValidator(v);
      }

      for (Id vid : active_set)
      {
        if (was_active.count(vid) > 0)
          continue;

        ValidatorInfo v;
        if (!state.getValidator(vid, v))
          continue;
        v.is_active = true;
        v.became_active_at = ctx.current_height;
        state.putValidator(v);
      }

      std::vector<uint8_t> set_bytes;
      set_bytes.reserve(active_set.size() * 8);
      for (auto vid : active_set)
      {
        for (int i = 0; i < 8; ++i)
          set_bytes.push_back(uint8_t(vid >> (i * 8)));
      }
      state.putGlobal("active_set", set_bytes);
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
    processUnbondExpiries(state, ctx.current_height);

    distributeRewards(state, block, ctx);

    //  Increment the producer's own counter. This is a state change:
    //  total_blocks_produced lives in the validator record, which is
    //  in the SMT, so it must happen on BOTH the simulate and the
    //  apply path. If it were gated on !ctx.dry_run, the two paths
    //  would produce different state roots — which is exactly the
    //  bug that caused block 1 and block 2 to be rejected.
    //
    //  The simulate path aborts its txn, so the increment does not
    //  persist there. The apply path commits it. Both compute the
    //  same new state root.
    //
    //  Block height 0 has no producer (genesis), so skip it.
    if (block.header.height > 0)
    {
      uint64_t producer_id = 0;
      if (state.getValidatorByAddress(block.header.proposer, producer_id))
      {
        ValidatorInfo producer;
        if (state.getValidator(producer_id, producer))
        {
          producer.total_blocks_produced += 1;
          state.putValidator(producer);
        }
      }
    }

    updateGlobalState(state, block, ctx);

    if (!ctx.dry_run)
    {
      bumpLifetimeCounters(state, block);
      indexBlockProducer(state, block);
      indexTransactions(state, block, ctx);
    }

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

  //  Certificate checks
  //
  //  Two functions, one job each:
  //
  //    checkTimeoutCertificateHash
  //      Wire integrity. Recomputes H(certificate) and compares it to
  //      the value the header committed to. Catches a relaying peer
  //      swapping or stripping the certificate, and catches a
  //      proposer whose header claims a certificate they didn't carry.
  //
  //    checkTimeoutCertificate
  //      Consensus. Verifies the certificate's signatures against the
  //      committed set. Catches an arbitrary emergency flag.
  //
  //  Both must pass for an emergency block to be accepted.

  bool BlockProcessor::checkTimeoutCertificateHash(const Block &block,
                                                   std::string &error)
  {
    //  Recompute the certificate hash from the certificate bytes that
    //  were transmitted alongside the block. Compare against the value
    //  the header committed to. A mismatch means either the header's
    //  hash is wrong (a Byzantine proposer claiming a certificate
    //  they didn't carry) or the certificate bytes were altered in
    //  transit (a MITM on the plaintext P2P channel). Either way, the
    //  block is not the block the proposer signed.
    //
    //  This is a wire-integrity check, separate from the consensus
    //  check that verifies the certificate's signatures. Both must
    //  pass. See checkTimeoutCertificate.
    const Crypto::Hash computed =
        computeTimeoutCertificateHash(block.header.timeout_certificate);

    if (computed != block.header.timeout_certificate_hash)
    {
      error = "timeout certificate hash mismatch: header commits to " +
              block.header.timeout_certificate_hash.toString() +
              ", certificate hashes to " + computed.toString();
      return false;
    }

    return true;
  }

  bool BlockProcessor::checkTimeoutCertificate(
      State::StateAccess &state,
      const Block &block,
      const std::vector<Id> &committed_set,
      uint64_t current_height,
      std::string &error)
  {
    //  Signature verification for the certificate. The wire-integrity
    //  check (certificate bytes match the header's hash) is done
    //  separately in checkTimeoutCertificateHash; that function must
    //  have been called first (checkHeader does it).
    auto lookup = [&state](Id vid, ValidatorInfo &out) -> bool
    {
      return state.getValidator(vid, out);
    };

    return Consensus::verifyTimeoutCertificate(
        block.header.timeout_certificate,
        committed_set,
        /*cert_height=*/current_height,
        /*cert_round=*/block.header.emergency_rotation,
        lookup,
        error);
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
    if (!ctx.dry_run && !block.header.isWellFormed())
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

    //  Certificate hash binding. When emergency_rotation > 0, the
    //  header's timeout_certificate_hash must match H(certificate).
    //  Checked here, before anything more expensive, so a bad hash
    //  rejects the block early.
    //
    //  Non-emergency blocks carry an empty certificate and a null
    //  hash; isWellFormed enforces that they agree.
    if (!ctx.dry_run && block.header.emergency_rotation > 0)
    {
      if (!checkTimeoutCertificateHash(block, error))
        return false;
    }

    uint64_t now_ms = nowMs();
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

      Crypto::PublicKey pk = v.effectiveConsensusKey();

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
                                         const std::vector<Id> &active_set,
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
        //  Slash is the only system tx that carries semantic content
        //  today. It must be verified and applied. Every other system
        //  type (BlockReward, OrderExpired) is a marker: their effects
        //  are computed by the block processor itself, not carried in
        //  the tx. Those fall through to the no-op receipt.
        if (tx.tx_type == TxType::Slash)
        {
          std::string slash_err;
          if (!applySlash(state, tx, active_set, ctx, slash_err))
          {
            error = "slash failed at index " + std::to_string(i) +
                    ": " + slash_err;
            return false;
          }
        }

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
        error = "transaction failed at index " + std::to_string(i) +
                " (type=" + std::string(txTypeName(tx.tx_type)) + ")";
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

  void BlockProcessor::processUnbondExpiries(State::StateAccess &state,
                                             uint64_t current_height)
  {
    // Collect expired unbondings first, then mutate. Mutating while
    // iterating is not safe, and forEachValidator explicitly
    // documents that the visitor should not modify state.
    std::vector<Id> expired;

    state.forEachValidator([&](const ValidatorInfo &v)
                           {
      if (v.isUnbondExpired(current_height))
        expired.push_back(v.id); });

    for (Id vid : expired)
    {
      ValidatorInfo v;
      if (!state.getValidator(vid, v))
        continue;

      // Return the stake to the owner. The account may have been
      // touched since the request; recalculateStaked brings the
      // cached staked value in line with the new balance.
      Account acct = state.getAccount(v.owner);
      acct.balance += v.stake;
      acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
      state.putAccount(v.owner, acct);

      // Remove the address index and the record, in that order.
      // If the process crashes between the two, the index entry
      // points at a missing record; getValidatorByAddress will
      // return the id, and the subsequent getValidator will fail,
      // and the caller treats that as "not registered". The
      // alternative (deleting the record first) would leave a
      // dangling address index that resolves to a non-existent
      // validator — the same failure mode, but harder to diagnose.
      state.deleteValidatorByAddress(v.reward_address);
      state.deleteValidator(v.id);
    }
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

    //  Rewards are paid to the set that actually produced this block.
    //  For an emergency block, that's the derived set written to state
    //  above. Re-reading here gives us the same value, since the write
    //  happened earlier in applyBlock.
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

    //  ---- Seed-only special case ----
    //
    //  When every validator in the active set is a seed, the normal
    //  reward split is replaced by a "seed stipend" model:
    //
    //    - The producer bonus (20% of the validator pool) is split
    //      evenly across all seeds, regardless of which seed proposed
    //      the block. Seeds are operated as a single entity, so the
    //      distinction between producing and signing is bookkeeping
    //      noise.
    //
    //    - The set share (80% of the validator pool) is routed to the
    //      pot rather than paid to the seeds. Paying a seed the full
    //      validator pool on a chain with no other validators would
    //      concentrate wealth and provide no incentive for new
    //      validators to register.
    //
    //  When the active set contains even one non-seed, the normal
    //  distribution resumes. This preserves the incentive to register:
    //  a validator that joins a seed-heavy chain starts earning
    //  immediately.
    //
    //  Degenerate case: with one seed, the seed earns the full
    //  producer bonus and the set share goes to the pot.
    const bool seed_only = !active_set.empty() &&
                           std::all_of(active_set.begin(), active_set.end(),
                                       [&](Id vid)
                                       {
                                         ValidatorInfo v;
                                         return state.getValidator(vid, v) && v.is_seed;
                                       });

    if (seed_only)
    {
      const uint64_t seed_pool = rewards.producer_amount;
      const uint64_t seed_count = active_set.size();
      const uint64_t per_seed = seed_pool / seed_count;
      uint64_t remainder = seed_pool % seed_count;

      for (Id vid : active_set)
      {
        uint64_t amount = per_seed;
        if (remainder > 0)
        {
          amount += 1;
          --remainder;
        }

        ValidatorInfo v;
        if (!state.getValidator(vid, v))
        {
          //  Should not happen — the caller loaded the set from state.
          //  If it does, the amount is routed to the pot.
          total_redistributed += amount;
          continue;
        }

        //  Apply the reward multiplier, matching the normal path.
        //  In practice a seed's multiplier is always START, so this
        //  is a no-op, but keeping it makes the code consistent and
        //  handles any future policy that penalizes a seed.
        const uint64_t adjusted = amount * v.reward_multiplier / 10'000;
        const uint64_t difference = amount - adjusted;

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

      //  Route the entire set share to the pot.
      total_redistributed += rewards.set_amount;

      //  Credit the pot and return. The normal producer loop and
      //  per-validator set-share loop are skipped — the seed stipend
      //  above replaces both.
      uint64_t pot = readU64Global(state, "pot");
      pot += total_redistributed;

      const uint64_t staker_pool =
          applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);
      pot += staker_pool;

      //  Track the lifetime total credited to the pot. Slashing
      //  proceeds also route here via executeSystemSlash; those are
      //  written by the executor, not by this path.
      //
      //  total_to_pot is aggregation, not consensus — it lives in
      //  meta, not the SMT. pot is consensus state and stays on the
      //  SMT.
      uint64_t total_to_pot = state.getMetaU64("total_to_pot");
      total_to_pot += total_redistributed + staker_pool;
      state.putMetaU64("total_to_pot", total_to_pot);

      writeU64Global(state, "pot", pot);
      return;
    }

    //  ---- Normal (non-seed-only) distribution ----

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

    uint64_t total_to_pot = state.getMetaU64("total_to_pot");
    total_to_pot += total_redistributed + staker_pool;
    state.putMetaU64("total_to_pot", total_to_pot);

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

    //  Activity metric. The epoch's total transaction count divided
    //  by the number of blocks in the epoch. The counters are the
    //  chain-lifetime tx_counter and a snapshot of it taken at the
    //  previous epoch boundary — the delta is this epoch's
    //  contribution.
    const uint64_t tx_counter_now = readU64Meta(state, "tx_counter");
    const uint64_t tx_counter_at_start = readU64Meta(state, "tx_counter_at_epoch_start");
    const uint64_t txs_this_epoch =
        tx_counter_now >= tx_counter_at_start
            ? tx_counter_now - tx_counter_at_start
            : 0;

    const uint64_t avg_tx_per_block =
        ROTATION_INTERVAL > 0 ? txs_this_epoch / ROTATION_INTERVAL : 0;

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
    rctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
    rctx.apy_activity_bps = apy_activity_bps;
    rctx.apy_pot_bonus_bps = apy_pot_bonus_bps;

    const uint16_t effective_apy = computeEffectiveApy(rctx, SECONDS_PER_EPOCH);

    //  Record the APY this epoch actually used. The RPC reads this
    //  to answer "what is the current APY" without recomputing it —
    //  the inputs (pot, activity) change between epoch boundaries,
    //  but the value that governs staker payouts is the one computed
    //  here, once per epoch.
    //
    //  This is display-only aggregation, so it lives in meta, not
    //  the SMT. Writing it to the SMT would make the epoch-boundary
    //  state root depend on a value that no verifier needs to
    //  reproduce.
    state.putMetaU64("last_effective_apy_bps",
                     static_cast<uint64_t>(effective_apy));

    //  Snapshot the tx counter so the next epoch can compute its own
    //  activity delta. Written unconditionally, before any of the
    //  early-return paths below, so the next epoch's reading is
    //  always correct regardless of whether this epoch distributed
    //  any rewards.
    state.putMetaU64("tx_counter_at_epoch_start", tx_counter_now);

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

    //  Track the lifetime total actually paid to stakers from the
    //  pot. Not the same as total_to_pot: the pot can also be burned
    //  when it exceeds the cap, and can accumulate without being
    //  distributed if there are no stakers.
    //
    //  Aggregation, so it lives in meta, not the SMT.
    uint64_t total_pot_distributed = state.getMetaU64("total_pot_distributed");
    total_pot_distributed += adj.distributed;
    state.putMetaU64("total_pot_distributed", total_pot_distributed);

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
      if (acct.staked >= GlobalConfig::BALANCE_BONUS_THRESHOLD)
      {
        __uint128_t w = static_cast<__uint128_t>(weight) *
                        (10'000 + GlobalConfig::BALANCE_BONUS_BPS);
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
      if (acct.staked >= GlobalConfig::BALANCE_BONUS_THRESHOLD)
      {
        __uint128_t w = static_cast<__uint128_t>(weight) *
                        (10'000 + GlobalConfig::BALANCE_BONUS_BPS);
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

  bool BlockProcessor::applySlash(State::StateAccess &state,
                                  const Transaction &tx,
                                  const std::vector<Id> &active_set,
                                  const BlockContext &ctx,
                                  std::string &error)
  {
    //  The proof resolves the signer by id, and the policy check
    //  ("is this signer still slashable?") is enforced by
    //  executeSystemSlash against the validator record: it rejects
    //  seeds, rejects a validator that has been fully removed, and
    //  succeeds for one that is merely rotated out or pending
    //  unbond. Passing an empty active_set disables the verifier's
    //  set-membership check, which would otherwise reject a proof
    //  against a validator that rotated out between the vote and
    //  the block — a legitimate slash that must not be lost.
    //
    //  The set-membership check in verifyEquivocationProof remains
    //  useful for callers that want it (tests, migration tooling);
    //  the on-chain path does not need it.
    auto decoded = verifyEquivocationProof(tx.payload,
                                           /*active_set=*/{},
                                           state);
    if (!decoded.has_value())
    {
      error = "invalid equivocation proof";
      return false;
    }

    TxExecutionContext exec_ctx;
    exec_ctx.current_height = ctx.current_height;
    exec_ctx.chain_id = ctx.chain_id;
    exec_ctx.tx_index_in_block = 0;

    Receipt r = TransactionExecutor::executeSystemSlash(
        state, *decoded, ctx.current_height, exec_ctx);

    if (r.status != ReceiptStatus::Success)
    {
      error = "executeSystemSlash returned failure";
      return false;
    }

    return true;
  }

  void BlockProcessor::indexBlockProducer(State::StateAccess &state,
                                          const Block &block)
  {
    state.indexBlockProducer(
        block.header.proposer,
        block.header.height,
        block.hash());
  }

  void BlockProcessor::indexTransactions(State::StateAccess &state,
                                         const Block &block,
                                         const BlockContext &ctx)
  {
    for (size_t i = 0; i < block.transactions.size(); ++i)
    {
      const Transaction &tx = block.transactions[i];

      const bool sys = isSystemTx(tx.tx_type);

      if (sys)
      {
        continue;
      }

      std::vector<Crypto::Address> addresses;
      std::vector<Id> tokens;

      addresses.push_back(tx.from);

      if (!tx.to.isNull())
        addresses.push_back(tx.to);

      switch (tx.tx_type)
      {
      case TxType::Transfer:
        tokens.push_back(tx.token_id);
        break;

      case TxType::CreateToken:
      case TxType::MintToken:
      case TxType::BurnToken:
      case TxType::UpdateTokenMeta:
        tokens.push_back(tx.token_id);
        break;

      case TxType::Swap:
      case TxType::AddLiquidity:
      case TxType::RemoveLiquidity:
        tokens.push_back(tx.token_id);
        break;

      case TxType::CreatePool:
        tokens.push_back(tx.token_id);
        break;

      case TxType::CreateOrder:
      case TxType::CancelOrder:
        tokens.push_back(tx.token_id);
        break;

      case TxType::OptInStaking:
      case TxType::OptOutStaking:
      case TxType::ClaimRewards:
      case TxType::RegisterValidator:
      case TxType::UnregisterValidator:
      case TxType::UpdateRewardAddress:
        tokens.push_back(NATIVE_TOKEN_ID);
        break;

      default:
        break;
      }

      state.indexTransaction(
          tx.txid(),
          ctx.current_height,
          static_cast<uint32_t>(i),
          addresses,
          tokens,
          static_cast<uint8_t>(tx.tx_type));
    }
  }
} // namespace Core