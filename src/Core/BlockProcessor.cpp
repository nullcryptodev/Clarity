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
#include "ActiveRouter.h"

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

    //  ---- Rolling 24h fee window ----
    //
    //  A fixed-size ring of per-block fee totals, plus a running
    //  sum. The ring is sized for 24 h at the nominal block interval.
    //  Reading the window is O(1): the sum is maintained
    //  incrementally as blocks are appended and evicted.
    //
    //  Storage is the meta table; see the comment on
    //  BlockProcessor::updateFeeWindow in the header.

    constexpr uint64_t FEE_WINDOW_BLOCKS =
        24ULL * 60 * 60 / NOMINAL_BLOCK_SECONDS;

    void updateFeeWindowImpl(State::StateAccess &state, uint64_t block_fees)
    {
      //  Read the current ring state. On a fresh chain all three
      //  keys are absent, which the getters report as 0; the ring
      //  vector is also empty, which we grow to FEE_WINDOW_BLOCKS.
      std::vector<uint8_t> ring_bytes;
      state.getMeta("fees_window_ring", ring_bytes);

      const size_t expected_bytes = FEE_WINDOW_BLOCKS * sizeof(uint64_t);
      if (ring_bytes.size() != expected_bytes)
      {
        //  Fresh chain, or an upgrade from a build before the
        //  window existed. Start a new ring. Preserving the old
        //  window across an upgrade would require a migration; a
        //  fresh start is acceptable for an aggregation counter
        //  that the next 24 h will refill anyway.
        ring_bytes.assign(expected_bytes, 0);
        state.putMeta("fees_window_ring", ring_bytes);
        state.putMetaU64("fees_window_sum", 0);
        state.putMetaU64("fees_window_ring_head", 0);
        state.putMetaU64("fees_window_block_count", 0);
      }

      const uint64_t head = state.getMetaU64("fees_window_ring_head");
      const uint64_t count = state.getMetaU64("fees_window_block_count");
      const uint64_t sum = state.getMetaU64("fees_window_sum");

      //  The slot we are about to overwrite holds the value that
      //  falls out of the window when we write the new one.
      uint64_t evicted = 0;
      std::memcpy(&evicted, ring_bytes.data() + head * sizeof(uint64_t),
                  sizeof(uint64_t));

      //  Write the new value into that slot.
      std::memcpy(ring_bytes.data() + head * sizeof(uint64_t),
                  &block_fees, sizeof(uint64_t));

      const uint64_t new_sum = sum - evicted + block_fees;
      const uint64_t new_head = (head + 1) % FEE_WINDOW_BLOCKS;
      const uint64_t new_count =
          (count < FEE_WINDOW_BLOCKS) ? count + 1 : FEE_WINDOW_BLOCKS;

      state.putMeta("fees_window_ring", ring_bytes);
      state.putMetaU64("fees_window_sum", new_sum);
      state.putMetaU64("fees_window_ring_head", new_head);
      state.putMetaU64("fees_window_block_count", new_count);
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

      //  Rolling 24 h window. Same category as the lifetime
      //  counters, so same table.
      updateFeeWindowImpl(state, block.header.total_fees);
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

  Crypto::Hash BlockProcessor::computeEpochFillsRoot(
      const std::vector<Fill> &fills)
  {
    if (fills.empty())
      return Crypto::Hash{};

    std::vector<Crypto::Hash> leaves;
    leaves.reserve(fills.size());

    for (const auto &f : fills)
    {
      //  Leaf layout matches verifyEpochFillsRoot:
      //    "efil" || Fill::serializeState()
      //
      //  The "efil" tag distinguishes this leaf domain from the
      //  receipts_root's "rcpt" tag, so a fill and a receipt with
      //  identical bytes cannot collide across the two trees.
      const auto fill_bytes = f.serializeState();

      std::vector<uint8_t> buf;
      buf.reserve(4 + fill_bytes.size());
      buf.push_back('e');
      buf.push_back('f');
      buf.push_back('i');
      buf.push_back('l');
      buf.insert(buf.end(), fill_bytes.begin(), fill_bytes.end());

      Crypto::Hash h;
      Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
      leaves.push_back(h);
    }

    return computeMerkleRoot(leaves);
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

    //  Condition evaluation runs once per epoch, at the same
    //  boundary as processEpochBoundary and processRotation. It is
    //  placed after transactions and expiries (so it sees the
    //  post-transaction state of this block), and before rewards
    //  (so cancelled orders don't participate in this block's
    //  reward distribution).
    //
    //  Every state mutation performed here — the refund, the fee,
    //  the order deletion, and the Active-order fills — runs on
    //  BOTH the dry-run and apply paths. The rule is unchanged:
    //  SMT writes happen unconditionally, only the meta-table and
    //  non-SMT index writes may be gated on !ctx.dry_run.
    //
    //  Active-order fills produced at the epoch boundary are not
    //  attached to any transaction; they are collected here and
    //  committed to the header via epoch_fills_root below.
    std::vector<Fill> epoch_fills;
    if ((ctx.current_height + 1) % ROTATION_INTERVAL == 0)
    {
      evaluateOrderConditions(state, ctx, epoch_fills);
    }

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

    //  Epoch-fills commitment.
    //
    //  Skipped entirely on the dry-run path. The block builder uses
    //  a placeholder non-null value in the header while computing
    //  the real root, and only knows the real root after this call
    //  returns. Checking the placeholder against the computed value
    //  would reject every dry-run that produced no epoch fills.
    //
    //  On the apply path, both directions are checked:
    //    - non-null root  →  must match the computed root
    //    - null root      →  must have produced no epoch fills
    //
    //  The second direction is the important one: a proposer that
    //  produced epoch fills without committing to them is a
    //  consensus hazard and is rejected.
    if (!ctx.dry_run)
    {
      if (!block.header.epoch_fills_root.isNull())
      {
        if (!verifyEpochFillsRoot(epoch_fills,
                                  block.header.epoch_fills_root, error))
        {
          result.error = error;
          return result;
        }
      }
      else if (!epoch_fills.empty())
      {
        result.error = "epoch fills present but epoch_fills_root is null";
        return result;
      }
    }

    result.valid = true;
    result.receipts = std::move(receipts);
    result.tx_hashes = std::move(tx_hashes);
    result.epoch_fills = std::move(epoch_fills);

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
    auto lookup = [&state, cert_height = current_height](Id vid,
                                                         ValidatorInfo &out) -> bool
    {
      if (!state.getValidator(vid, out))
        return false;

      //  Overwrite the record's current key with the key that
      //  was authoritative at the certificate's height. The
      //  caller (Consensus::verifyTimeoutCertificate) reads
      //  effectiveConsensusKey() from the returned record; by
      //  setting consensus_key here, the verification uses the
      //  height-appropriate key without changing the callback's
      //  signature.
      auto historic = state.validatorKeyAtHeight(vid, cert_height);
      if (!historic.has_value())
        return false;
      out.consensus_key = *historic;
      return true;
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
      Id vid = active_set[vs.signer_index];

      ValidatorInfo v;
      if (!state.getValidator(vid, v))
      {
        error = "quorum signature from unknown validator";
        return false;
      }

      //  Resolve the signing key at this block's height, not the
      //  validator's current key. A validator that has rotated
      //  since the vote was cast must still verify against the key
      //  that was authoritative when they voted.
      auto pk = state.validatorKeyAtHeight(vid, block.header.height);
      if (!pk.has_value())
      {
        error = "no consensus key for signer at this height";
        return false;
      }

      if (!Crypto::verify(signing_hash, *pk, vs.signature))
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

      //  deleteRestingOrder removes the book row, the companion
      //  sequence key, the expiry entry, the SMT record, and every
      //  index row. Previously this call was state.deleteOrder(id),
      //  which left the book index row dangling — harmless for the
      //  matcher (it skips stale rows) but a slow leak.
      state.deleteRestingOrder(order);
    }

    state.clearOrderExpiry(current_height);
  }

  //  Order condition evaluation

  std::optional<uint64_t> BlockProcessor::poolSpotPrice(
      State::StateAccess &state,
      uint32_t pool_id,
      uint32_t sell_token,
      uint32_t buy_token)
  {
    Core::AmmPool pool;
    if (!state.getAmmPool(pool_id, pool))
      return std::nullopt;

    bool sell_is_a = false;
    bool sell_is_b = false;

    if (pool.token_a == sell_token && pool.token_b == buy_token)
    {
      sell_is_a = true;
    }
    else if (pool.token_b == sell_token && pool.token_a == buy_token)
    {
      sell_is_b = true;
    }
    else
    {
      return std::nullopt;
    }

    if (pool.reserve_a == 0 || pool.reserve_b == 0)
      return std::nullopt;

    //  Note: this uses PRICE_SCALE, not BOOK_PRICE_SCALE. The two
    //  constants have the same numeric value today but are
    //  conceptually distinct (see the comment in OrderBook.h).
    //  This comparison is a condition evaluation, so it uses the
    //  condition scale.
    __uint128_t num = 0;
    uint64_t den = 0;

    if (sell_is_a)
    {
      num = static_cast<__uint128_t>(pool.reserve_b) * Core::PRICE_SCALE;
      den = pool.reserve_a;
    }
    else
    {
      num = static_cast<__uint128_t>(pool.reserve_a) * Core::PRICE_SCALE;
      den = pool.reserve_b;
    }

    if (den == 0)
      return std::nullopt;

    return static_cast<uint64_t>(num / den);
  }

  bool BlockProcessor::conditionsAllHold(State::StateAccess &state,
                                         const Core::Order &order,
                                         uint64_t current_height)
  {
    for (uint8_t i = 0; i < order.condition_count; ++i)
    {
      const auto &c = order.conditions[i];

      switch (c.type)
      {
      case OrderConditionType::Invalid:
        return false;

      case OrderConditionType::ExpiresAtHeight:
      {
        if (current_height >= c.param1)
          return false;
        break;
      }

      case OrderConditionType::PriceAbove:
      {
        auto price = poolSpotPrice(state, c.param2,
                                   order.sell_token, order.buy_token);
        if (!price.has_value())
          break;
        if (*price > c.param1)
          return false;
        break;
      }

      case OrderConditionType::PriceBelow:
      {
        auto price = poolSpotPrice(state, c.param2,
                                   order.sell_token, order.buy_token);
        if (!price.has_value())
          break;
        if (*price < c.param1)
          return false;
        break;
      }

      case OrderConditionType::VolumeBelow:
      {
        Core::AmmPool pool;
        if (!state.getAmmPool(c.param2, pool))
          break;
        const uint64_t vol = pool.reportedVolume(current_height);
        if (vol < c.param1)
          return false;
        break;
      }

      case OrderConditionType::BalanceBelow:
      {
        const Core::Account acct = state.getAccount(order.owner);
        if (acct.balance < c.param1)
          return false;
        break;
      }
      }
    }

    return true;
  }

  void BlockProcessor::cancelOrderByCondition(State::StateAccess &state,
                                              Id order_id,
                                              uint64_t /*current_height*/)
  {
    Core::Order order;
    if (!state.getOrder(order_id, order))
      return;

    const uint64_t remaining = order.remainingAmount();
    const uint64_t fee =
        std::min(remaining, Core::ORDER_CANCEL_FEE_ATOMIC);
    const uint64_t refund = remaining - fee;

    if (refund > 0)
    {
      if (order.sell_token == NATIVE_TOKEN_ID)
      {
        Core::Account acct = state.getAccount(order.owner);
        acct.balance += refund;
        state.putAccount(order.owner, acct);
      }
      else
      {
        const uint64_t bal =
            state.getTokenBalance(order.owner, order.sell_token);
        state.putTokenBalance(order.owner, order.sell_token,
                              bal + refund);
      }
    }

    //  Single call does the book row, companion sequence key,
    //  expiry entry, SMT record, and every index. Replaces the
    //  previous two-step (removeOrderExpiry + deleteOrder) which
    //  missed the book index.
    state.deleteRestingOrder(order);
  }

  ActiveRouteOutcome BlockProcessor::executeActiveOrder(
      State::StateAccess &state,
      Order &order,
      uint64_t height,
      uint32_t tx_index_in_block,
      std::vector<Fill> &fills_out)
  {
    if (order.mode != OrderExecutionMode::Active)
      return ActiveRouteOutcome::Unroutable;
    if (order.pool_id == 0)
      return ActiveRouteOutcome::Unroutable;
    if (order.owner.isNull())
      return ActiveRouteOutcome::Unroutable;

    //  Fully filled is a caller bug: the evaluator only routes
    //  orders with a remainder. Report Unroutable so the caller
    //  cleans up.
    if (order.isFullyFilled())
      return ActiveRouteOutcome::Unroutable;

    AmmPool pool;
    if (!state.getAmmPool(order.pool_id, pool))
      return ActiveRouteOutcome::Unroutable; // pool gone
    if (!pool.active)
      return ActiveRouteOutcome::Unroutable; // pool closed

    //  Determine swap direction. The pool's reserves are in
    //  canonical token order (token_a < token_b). The order sells
    //  `order.sell_token`. Either the sell token is token_a (sell
    //  into reserve_a, receive reserve_b) or token_b (the reverse).
    //  Anything else is a pool/order mismatch.
    uint64_t reserve_in = 0;
    uint64_t reserve_out = 0;

    if (order.sell_token == pool.token_a && order.buy_token == pool.token_b)
    {
      reserve_in = pool.reserve_a;
      reserve_out = pool.reserve_b;
    }
    else if (order.sell_token == pool.token_b && order.buy_token == pool.token_a)
    {
      reserve_in = pool.reserve_b;
      reserve_out = pool.reserve_a;
    }
    else
    {
      return ActiveRouteOutcome::Unroutable; // pair mismatch
    }

    if (reserve_in == 0 || reserve_out == 0)
      return ActiveRouteOutcome::Unroutable; // empty pool

    //  Canonical limit price in quote-per-base, scaled.
    //
    //  The order's limit is `min_buy_amount / sell_amount` in
    //  buy-token per sell-token. Convert to the canonical frame
    //  (quote per base) by inverting if the order sells quote.
    //
    //  Canonical:
    //    base  = min(sell, buy)
    //    quote = max(sell, buy)
    //
    //  If the order sells base, its limit price is already
    //  min_buy_amount / sell_amount in quote per base.
    //  If the order sells quote, its limit is
    //  min_buy_amount / sell_amount in base per quote, which
    //  inverts to sell_amount / min_buy_amount in quote per base.
    //
    //  Computed with the same rounding policy OrderBook uses, so
    //  an Active order and a Passive order at the same limit
    //  compare identically against the AMM.
    uint64_t canonical_limit = 0;
    if (!OrderBook::canonicalPrice(order, canonical_limit))
      return ActiveRouteOutcome::Unroutable; // overflow

    //  Compute the max input that respects the limit.
    //
    //  Note on partial fills: an Active order that partially fills
    //  moves the pool's price. The next epoch's max-input
    //  computation runs against the post-fill pool, and if the
    //  pool has moved past the order's limit, the order rests
    //  rather than fills further. That's the correct behavior: the
    //  order's limit is a price floor, not a quantity guarantee,
    //  and a pool that no longer clears the limit cannot be used
    //  to fill the remainder.
    //
    //  No positive input satisfies the limit. The pool is real,
    //  the pair is real, but the current price is unfavorable.
    //  Rest and retry next epoch.
    const auto max_in = ActiveRouter::maxInputWithinLimit(
        reserve_in, reserve_out, pool.fee_bps, canonical_limit);

    if (!max_in.has_value() || *max_in == 0)
      return ActiveRouteOutcome::Rested;

    const uint64_t amount_in = std::min(*max_in, order.remainingAmount());
    if (amount_in == 0)
      return ActiveRouteOutcome::Rested;

    const uint64_t amount_out = ActiveRouter::computeOutput(
        reserve_in, reserve_out, pool.fee_bps, amount_in);
    if (amount_out == 0)
      return ActiveRouteOutcome::Rested;

    const uint64_t effective_price = ActiveRouter::computeEffectivePrice(
        reserve_in, reserve_out, pool.fee_bps, amount_in);

    //  Compute the CLRTY-equivalent volume before the reserve
    //  update, using the pool's pre-swap price. Matches what
    //  AmmPool::executeSwap does for a user Swap transaction.
    //
    //  The tracker stores CLRTY-denominated volume so that a
    //  VolumeBelow condition's threshold is comparable across
    //  pools regardless of which two tokens the pool actually
    //  trades. If the pool has CLRTY on neither side, the volume
    //  is zero — this is the same behavior executeSwap has, and
    //  a pool with no CLRTY side will not have a meaningful
    //  CLRTY volume anyway.
    uint64_t clrty_volume = 0;

    if (order.sell_token == NATIVE_TOKEN_ID)
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

    //  Update the pool reserves. Mirror AmmPool::executeSwap's
    //  reserve update so a subsequent swap sees a consistent
    //  state.
    if (order.sell_token == pool.token_a)
    {
      pool.reserve_a += amount_in;
      pool.reserve_b -= amount_out;
    }
    else
    {
      pool.reserve_b += amount_in;
      pool.reserve_a -= amount_out;
    }

    //  Update the rolling volume window, same as AmmPool::executeSwap
    //  does for a user Swap transaction. A routed order is a trade
    //  through the pool; a VolumeBelow condition on this pool
    //  should see it.
    //
    //  The window mechanics match executeSwap exactly:
    //    - first write initializes the window at this height
    //    - a write at or after window_height + ROTATION_INTERVAL
    //      rolls the current window into "last" and starts fresh
    //    - a write within the window adds to the running total
    //
    //  This runs before putAmmPool so the reserve and volume
    //  updates commit together in the same SMT write.
    if (pool.volume_window_height == 0)
    {
      pool.volume_window_height = height;
      pool.volume_current = clrty_volume;
      pool.volume_last = 0;
    }
    else if (height >= pool.volume_window_height + ROTATION_INTERVAL)
    {
      pool.volume_last = pool.volume_current;
      pool.volume_current = clrty_volume;
      pool.volume_window_height = height;
    }
    else
    {
      pool.volume_current += clrty_volume;
    }

    state.putAmmPool(pool);

    //  Credit the counterparty. The order's sell-token lock was
    //  taken at creation, so the only balance movement here is the
    //  incoming token.
    if (order.buy_token == NATIVE_TOKEN_ID)
    {
      Account acct = state.getAccount(order.owner);
      acct.balance += amount_out;
      state.putAccount(order.owner, acct);
    }
    else
    {
      const uint64_t cur = state.getTokenBalance(order.owner, order.buy_token);
      state.putTokenBalance(order.owner, order.buy_token, cur + amount_out);
    }

    //  Record the fill in the order's sell token.
    order.filled_amount += amount_in;

    //  Build the Fill. qty_base and qty_quote are in the canonical
    //  frame: base is min(sell, buy), quote is max(sell, buy).
    const bool sells_base = (order.sell_token < order.buy_token);
    const uint32_t base_token =
        sells_base ? order.sell_token : order.buy_token;
    const uint32_t quote_token =
        sells_base ? order.buy_token : order.sell_token;

    Fill fill;
    fill.source = FillSource::Amm;
    fill.maker_order_id = 0;
    fill.taker_order_id = order.id;
    fill.pool_id = order.pool_id;
    fill.qty_base = sells_base ? amount_in : amount_out;
    fill.qty_quote = sells_base ? amount_out : amount_in;
    fill.price = effective_price;
    fill.base_token = base_token;
    fill.quote_token = quote_token;

    //  Persist the order.
    if (order.isFullyFilled())
    {
      state.deleteOrder(order.id);
    }
    else
    {
      state.putOrder(order);
    }

    //  Write the fill history. The fill index is the position of
    //  this fill within the caller's accumulating vector, so a
    //  caller that routes several orders in one epoch gets
    //  distinct fill indexes.
    state.indexFill(fill, height, tx_index_in_block,
                    static_cast<uint16_t>(fills_out.size()));

    fills_out.push_back(fill);
    return ActiveRouteOutcome::Filled;
  }

  void BlockProcessor::evaluateOrderConditions(
      State::StateAccess &state,
      const BlockContext &ctx,
      std::vector<Fill> &epoch_fills_out)
  {
    std::vector<Id> to_cancel;
    std::vector<Id> to_route;

    state.forEachOrder([&](const Core::Order &order)
                       {
      if (order.condition_count == 0 &&
          order.mode != OrderExecutionMode::Active)
        return;

      const bool holds = conditionsAllHold(state, order, ctx.current_height);

      if (order.mode == OrderExecutionMode::Active)
      {
        //  Conditions decide whether to route now or cancel. A
        //  condition-failure cancels; a condition-pass routes, and
        //  a partial or zero fill leaves the order in state for the
        //  next epoch.
        if (!holds)
          to_cancel.push_back(order.id);
        else
          to_route.push_back(order.id);
        return;
      }

      //  Passive: unchanged behaviour.
      if (order.condition_count == 0)
        return;
      if (holds)
        return;
      to_cancel.push_back(order.id); });

    //  Cancellations first. An order whose conditions failed is
    //  not routed even if it would have filled; the condition is
    //  the gate, and a failed condition cancels.
    for (Id order_id : to_cancel)
    {
      cancelOrderByCondition(state, order_id, ctx.current_height);
    }

    //  Then routing. Each routed order appends its fills to
    //  epoch_fills_out. A partial fill leaves the order in state;
    //  a full fill deletes it; an unroutable order is cancelled
    //  here.
    for (Id order_id : to_route)
    {
      Core::Order order;
      if (!state.getOrder(order_id, order))
        continue;

      //  The pseudo-index for an epoch-boundary fill. There is no
      //  transaction, so the caller has no tx_index_in_block to
      //  pass. We use the order's own id, which is unique within a
      //  block and therefore yields a unique fill-history key. Any
      //  reader correlating a fill back to a transaction must first
      //  check whether the block height falls on a rotation
      //  boundary; if so, the "tx_index" is an order id, not a
      //  transaction index.
      const auto outcome = executeActiveOrder(
          state, order, ctx.current_height,
          static_cast<uint32_t>(order_id),
          epoch_fills_out);

      if (outcome == ActiveRouteOutcome::Unroutable)
      {
        //  Pool gone, pair mismatch, empty reserves, or overflow.
        //  Cancel with the standard fee, matching the condition-
        //  failure policy.
        cancelOrderByCondition(state, order_id, ctx.current_height);
      }
      //  Filled: executeActiveOrder already wrote everything.
      //  Rested: nothing to do; retry next epoch.
    }
  }

  void BlockProcessor::processUnbondExpiries(State::StateAccess &state,
                                             uint64_t current_height)
  {
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

      Account acct = state.getAccount(v.owner);
      acct.balance += v.stake;
      acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
      state.putAccount(v.owner, acct);

      state.deleteValidatorByAddress(v.reward_address);
      state.deleteValidator(v.id);

      //  Drop the key history with the record. No reason to keep
      //  it once the validator is gone; an equivocation proof
      //  against a deleted validator is not actionable anyway
      //  (executeSystemSlash looks up the record and no-ops on
      //  absence).
      state.putValidatorKeyHistory(v.id, {});
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
          total_redistributed += amount;
          continue;
        }

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

      total_redistributed += rewards.set_amount;

      uint64_t pot = readU64Global(state, "pot");
      pot += total_redistributed;

      const uint64_t staker_pool =
          applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);
      pot += staker_pool;

      uint64_t total_to_pot = state.getMetaU64("total_to_pot");
      total_to_pot += total_redistributed + staker_pool;
      state.putMetaU64("total_to_pot", total_to_pot);

      writeU64Global(state, "pot", pot);
      return;
    }

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

    state.putMetaU64("last_effective_apy_bps",
                     static_cast<uint64_t>(effective_apy));

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

    uint64_t total_pot_distributed = state.getMetaU64("total_pot_distributed");
    total_pot_distributed += adj.distributed;
    state.putMetaU64("total_pot_distributed", total_pot_distributed);

    //  NFT collection reward accrual.
    //
    //  Runs before the staker early-return below: the escrow
    //  decrement is independent of whether stakers were paid this
    //  epoch. If it ran after the return, a chain with an empty pot
    //  or no stakers would never decrement any collection's escrow,
    //  and NFT reward schedules would silently stall.
    //
    //  For each collection with an active reward schedule, the
    //  per-epoch obligation is:
    //
    //    minted_count * reward_rate_per_epoch
    //
    //  Decrement the escrow by that amount. If the escrow cannot
    //  cover it, pay what's left, mark the collection paused, and
    //  stop. The actual credit to a holder happens lazily at claim
    //  time; this pass only moves the escrow.
    //
    //  This is the only place the escrow changes other than a
    //  RefillCollectionReward transaction. That single-writer
    //  invariant is what makes the accrual accounting sound: the
    //  sum of all pending claims is always <= the total the escrow
    //  has decremented for.
    //
    //  The pass is O(collections), not O(NFTs). A chain with
    //  1,000,000 NFTs across 100 collections pays 100 writes here,
    //  not a million.
    state.forEachNftCollection(
        [&](const Core::NftCollection &collection)
        {
          std::cerr << "[NFT] forEachNftCollection: id=" << collection.id
                    << " minted=" << collection.minted_count
                    << " rate=" << collection.reward_rate_per_epoch
                    << " escrow=" << collection.reward_escrow_remaining
                    << " paused=" << collection.reward_paused << "\n";
          if (!collection.hasReward())
            return;
          if (collection.reward_paused)
            return;
          if (collection.minted_count == 0)
            return;

          const uint64_t per_epoch =
              collection.minted_count * collection.reward_rate_per_epoch;

          Core::NftCollection updated = collection;

          if (updated.reward_escrow_remaining >= per_epoch)
          {
            updated.reward_escrow_remaining -= per_epoch;
          }
          else
          {
            //  Partial payout: drain what's left and pause. The
            //  remaining claims for this epoch settle to whatever
            //  the escrow could cover, and the schedule stops until
            //  the creator refills.
            updated.reward_escrow_remaining = 0;
            updated.reward_paused = true;
          }

          state.putNftCollection(updated);
        });

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
      //  Receipt leaf = Blake2b("rcpt" || txid || status || fee ||
      //                          fill_count || fills_bytes)
      //
      //  The fills section is part of the leaf, so a block whose
      //  receipts commit to a different set of fills than the
      //  verifier computes produces a different receipts_root and
      //  is rejected. This is what binds fills into consensus
      //  without adding a new header field.
      const auto receipt_bytes = receipts[i].serializeState();

      std::vector<uint8_t> buf;
      buf.reserve(4 + 32 + receipt_bytes.size());
      buf.push_back('r');
      buf.push_back('c');
      buf.push_back('p');
      buf.push_back('t');

      const auto &th = tx_hashes[i];
      buf.insert(buf.end(), th.data.begin(), th.data.end());

      buf.insert(buf.end(), receipt_bytes.begin(), receipt_bytes.end());

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

  bool BlockProcessor::verifyEpochFillsRoot(
      const std::vector<Fill> &epoch_fills,
      const Crypto::Hash &expected,
      std::string &error)
  {
    const Crypto::Hash computed = computeEpochFillsRoot(epoch_fills);

    if (computed != expected)
    {
      error = "epoch_fills_root mismatch: expected " +
              expected.toString() + ", got " + computed.toString();
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

  //  Public wrapper for the fee-window updater. The header declares
  //  updateFeeWindow as a private static member for symmetry with
  //  the rest of the class; the actual work is done by
  //  updateFeeWindowImpl in the anonymous namespace, which is what
  //  bumpLifetimeCounters calls directly. This definition exists so
  //  the symbol is present if some future caller wants to invoke it
  //  through the class interface.
  void BlockProcessor::updateFeeWindow(State::StateAccess &state,
                                       uint64_t block_fees)
  {
    updateFeeWindowImpl(state, block_fees);
  }
} // namespace Core