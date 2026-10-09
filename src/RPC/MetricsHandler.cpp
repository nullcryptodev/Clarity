// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "MetricsHandler.h"

#include "Node/Node.h"

#include "Core/Mempool.h"
#include "Core/RewardTypes.h"
#include "Core/ValidatorTypes.h"
#include "State/StateAccess.h"

#include <chrono>
#include <filesystem>
#include <system_error>

namespace Rpc
{
  namespace
  {
    //  Sum the sizes of all regular files under `path`, recursively.
    //
    //  Returns 0 if the path does not exist or cannot be read.
    //  Best-effort: a transient read error on any entry terminates
    //  the walk and returns the sum gathered so far, rather than
    //  throwing. The metric is diagnostic; reporting a partial
    //  number is better than failing the whole scrape.
    //
    //  This is deliberately NOT a stat() on the directory itself —
    //  stat on a directory returns the directory inode size, not
    //  the size of the files inside it. MDBX writes its data to a
    //  small number of files directly under the DB directory, so a
    //  single-level walk is sufficient in practice; the recursive
    //  form handles the case where a future MDBX version shards
    //  data into subdirectories without requiring a code change.
    std::uintmax_t dirBytes(const std::string &path) noexcept
    {
      std::error_code ec;
      if (!std::filesystem::exists(path, ec) || ec)
        return 0;

      std::uintmax_t total = 0;
      std::filesystem::recursive_directory_iterator it(
          path,
          std::filesystem::directory_options::skip_permission_denied,
          ec);
      if (ec)
        return 0;

      const std::filesystem::recursive_directory_iterator end;
      while (it != end)
      {
        std::error_code entry_ec;
        if (it->is_regular_file(entry_ec) && !entry_ec)
        {
          const auto size = it->file_size(entry_ec);
          if (!entry_ec)
            total += size;
        }

        it.increment(ec);
        if (ec)
          break;
      }

      return total;
    }

    //  Read a uint64 from the SMT global state. Returns 0 if the
    //  global is not present or is not exactly 8 bytes. Duplicated
    //  from Methods.cpp so the metrics handler doesn't depend on
    //  the RPC method file; the two are small and stable enough
    //  that duplication is cheaper than a shared helper header.
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

    //  Read the active validator set from the "active_set" global and
    //  return the IDs. The global stores a packed vector of
    //  little-endian uint64 validator IDs — the same encoding the
    //  RPC's getActiveSet method decodes.
    //
    //  Shared by the consensus block (which uses .size() and derives
    //  quorum from it) and the per-validator block (which iterates
    //  the IDs). One decoder, two callers.
    //
    //  This is one state read per scrape. It costs a single SMT leaf
    //  lookup, and the returned vector is at most ACTIVE_SET_MAX
    //  (100) elements.
    std::vector<uint64_t> readActiveSet(State::StateAccess &state)
    {
      std::vector<uint8_t> bytes;
      if (!state.getGlobal("active_set", bytes))
        return {};

      const size_t n = bytes.size() / 8;
      std::vector<uint64_t> out;
      out.reserve(n);
      for (size_t i = 0; i < n; ++i)
      {
        uint64_t id = 0;
        for (int j = 0; j < 8; ++j)
          id |= uint64_t(bytes[i * 8 + j]) << (j * 8);
        out.push_back(id);
      }
      return out;
    }
  } // anonymous namespace

  MetricsHandler::MetricsHandler(Node::Node &node, const MetricsConfig &config)
      : node_(node),
        config_(config),
        started_at_(std::chrono::steady_clock::now())
  {
  }

  //  Exposition helpers

  void MetricsHandler::beginMetric(std::string &out,
                                   const std::string &name,
                                   const std::string &type,
                                   const std::string &help)
  {
    out += "# HELP ";
    out += name;
    out += " ";
    out += help;
    out += "\n";

    out += "# TYPE ";
    out += name;
    out += " ";
    out += type;
    out += "\n";
  }

  void MetricsHandler::emitGauge(std::string &out,
                                 const std::string &name,
                                 uint64_t value)
  {
    out += name;
    out += " ";
    out += std::to_string(value);
    out += "\n";
  }

  void MetricsHandler::emitGauge(std::string &out,
                                 const std::string &name,
                                 int64_t value)
  {
    out += name;
    out += " ";
    out += std::to_string(value);
    out += "\n";
  }

  void MetricsHandler::emitGauge(std::string &out,
                                 const std::string &name,
                                 const std::string &label,
                                 const std::string &label_value,
                                 uint64_t value)
  {
    out += name;
    out += "{";
    out += label;
    out += "=\"";
    // Label values must escape backslash, double-quote, and
    // newline per the Prometheus exposition format spec. The
    // values we emit are all internal identifiers (numeric
    // strings, validator IDs, rejection reasons), so none of
    // them currently contain these characters — but the escape
    // is here so a future label carrying an address or an agent
    // string doesn't silently produce malformed output.
    for (char c : label_value)
    {
      switch (c)
      {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      default:
        out += c;
        break;
      }
    }
    out += "\"} ";
    out += std::to_string(value);
    out += "\n";
  }

  //  Rendering

  std::string MetricsHandler::render()
  {
    // Reserve enough for the full metric set plus headroom. The
    // string grows as more blocks are added; a reserve of a few
    // KB avoids repeated reallocations on a scrape.
    std::string out;
    out.reserve(16384);

    Node::Node::Status s = node_.status();

    // ---- Node ----

    beginMetric(out, "clrty_height", "gauge",
                "Current chain height");

    beginMetric(out, "clrty_running", "gauge",
                "1 if the node is running, 0 otherwise");

    beginMetric(out, "clrty_chain_id", "gauge",
                "Chain ID this node is configured for");

    beginMetric(out, "clrty_uptime_seconds", "counter",
                "Seconds since the metrics endpoint started");

    emitGauge(out, "clrty_height", s.height);
    emitGauge(out, "clrty_running", s.running ? uint64_t(1) : uint64_t(0));
    emitGauge(out, "clrty_chain_id", s.chain_id);

    const auto now = std::chrono::steady_clock::now();
    const auto uptime =
        std::chrono::duration_cast<std::chrono::seconds>(now - started_at_)
            .count();
    emitGauge(out, "clrty_uptime_seconds",
              static_cast<uint64_t>(uptime > 0 ? uptime : 0));

    // ---- P2P ----

    beginMetric(out, "clrty_p2p_peers", "gauge",
                "Total known peers (all states)");

    beginMetric(out, "clrty_p2p_peers_inbound", "gauge",
                "Inbound peers currently connected");

    beginMetric(out, "clrty_p2p_peers_outbound", "gauge",
                "Outbound peers currently connected");

    beginMetric(out, "clrty_p2p_peers_established", "gauge",
                "Peers that have completed the handshake and are Established");

    beginMetric(out, "clrty_p2p_peers_banned", "gauge",
                "Entries in the ban list");

    beginMetric(out, "clrty_p2p_addresses_known", "gauge",
                "Addresses in the address book");

    beginMetric(out, "clrty_p2p_aggregate_burst", "gauge",
                "Aggregate rate limiter burst (tokens)");

    beginMetric(out, "clrty_p2p_aggregate_per_second", "gauge",
                "Aggregate rate limiter refill rate (tokens per second)");

    beginMetric(out, "clrty_p2p_aggregate_enabled", "gauge",
                "1 if the aggregate rate limiter is enabled, 0 otherwise");

    emitGauge(out, "clrty_p2p_peers", s.peers_total);
    emitGauge(out, "clrty_p2p_peers_inbound", s.peers_inbound);
    emitGauge(out, "clrty_p2p_peers_outbound", s.peers_outbound);
    emitGauge(out, "clrty_p2p_peers_established", s.peers_established);
    emitGauge(out, "clrty_p2p_peers_banned", s.peers_banned);
    emitGauge(out, "clrty_p2p_addresses_known", s.addresses_known);
    emitGauge(out, "clrty_p2p_aggregate_burst",
              static_cast<uint64_t>(s.aggregate_rate_limit_burst));
    emitGauge(out, "clrty_p2p_aggregate_per_second",
              static_cast<uint64_t>(s.aggregate_rate_limit_per_second));
    emitGauge(out, "clrty_p2p_aggregate_enabled",
              s.aggregate_rate_limit_enabled ? uint64_t(1) : uint64_t(0));

    // ---- Mempool ----

    const Core::Mempool::Stats mstats = node_.mempool().stats();

    beginMetric(out, "clrty_mempool_txs", "gauge",
                "Transactions currently in the mempool");

    beginMetric(out, "clrty_mempool_bytes", "gauge",
                "Total serialized size of mempool transactions, in bytes");

    beginMetric(out, "clrty_mempool_priority_txs", "gauge",
                "Mempool transactions at the priority fee tier");

    beginMetric(out, "clrty_mempool_standard_txs", "gauge",
                "Mempool transactions at the standard fee tier");

    beginMetric(out, "clrty_mempool_min_fee_rate", "gauge",
                "Minimum fee rate across mempool transactions (atomic per byte)");

    beginMetric(out, "clrty_mempool_max_fee_rate", "gauge",
                "Maximum fee rate across mempool transactions (atomic per byte)");

    beginMetric(out, "clrty_mempool_avg_fee_rate", "gauge",
                "Mean fee rate across mempool transactions (atomic per byte)");

    emitGauge(out, "clrty_mempool_txs",
              static_cast<uint64_t>(mstats.total_txs));
    emitGauge(out, "clrty_mempool_bytes",
              static_cast<uint64_t>(mstats.total_bytes));
    emitGauge(out, "clrty_mempool_priority_txs",
              static_cast<uint64_t>(mstats.priority_txs));
    emitGauge(out, "clrty_mempool_standard_txs",
              static_cast<uint64_t>(mstats.standard_txs));
    emitGauge(out, "clrty_mempool_min_fee_rate", mstats.min_fee_rate);
    emitGauge(out, "clrty_mempool_max_fee_rate", mstats.max_fee_rate);
    emitGauge(out, "clrty_mempool_avg_fee_rate", mstats.avg_fee_rate);

    // ---- Mempool add/reject counters ----

    {
      const auto counts = node_.mempool().addResultCounts();

      beginMetric(out, "clrty_mempool_added_total", "counter",
                  "Transactions accepted into the mempool since process start");

      beginMetric(out, "clrty_mempool_rejected_total", "counter",
                  "Transactions rejected by the mempool since process start, by reason");

      emitGauge(out, "clrty_mempool_added_total",
                counts[static_cast<size_t>(Core::MempoolAddResult::Accepted)]);

      for (size_t i = 0; i < counts.size(); ++i)
      {
        const auto result = static_cast<Core::MempoolAddResult>(i);
        if (result == Core::MempoolAddResult::Accepted)
          continue;

        emitGauge(out, "clrty_mempool_rejected_total",
                  "reason",
                  Core::mempoolAddResultName(result),
                  counts[i]);
      }
    }

    // ---- Storage ----

    //  All of the node's persistent data lives in a single MDBX
    //  database, at <data_dir>/state. ChainDB is constructed on top
    //  of the same StateDB instance, so block indices, receipts, and
    //  the transaction index share the one file with the SMT and the
    //  account tables. There is no separate "chain" directory.
    //
    //  The metric reports the logical size of the MDBX file, which
    //  MDBX pre-allocates to the configured map size. On a fresh
    //  node the file's logical size may be much larger than the
    //  amount of data written so far — this is expected and the
    //  number is still the right one for "will this fill my disk",
    //  because a sparse file eventually consumes its logical size.
    const std::string &data_dir = node_.dataDir();
    const std::uintmax_t db_bytes = dirBytes(data_dir + "/state");

    const size_t block_count = node_.chainDB().blockCount();
    const size_t smt_nodes =
        node_.stateDB().entryCount(State::StateDB::TBL_SMT_NODES);
    const size_t smt_leaves =
        node_.stateDB().entryCount(State::StateDB::TBL_SMT_LEAVES);

    beginMetric(out, "clrty_storage_db_bytes", "gauge",
                "On-disk size of the node's MDBX database, in bytes");

    beginMetric(out, "clrty_storage_block_count", "gauge",
                "Number of blocks stored in the chain database");

    beginMetric(out, "clrty_storage_smt_nodes", "gauge",
                "Number of SMT nodes stored");

    beginMetric(out, "clrty_storage_smt_leaves", "gauge",
                "Number of SMT leaves stored");

    emitGauge(out, "clrty_storage_db_bytes",
              static_cast<uint64_t>(db_bytes));
    emitGauge(out, "clrty_storage_block_count",
              static_cast<uint64_t>(block_count));
    emitGauge(out, "clrty_storage_smt_nodes",
              static_cast<uint64_t>(smt_nodes));
    emitGauge(out, "clrty_storage_smt_leaves",
              static_cast<uint64_t>(smt_leaves));

    // ---- Rewards and economics ----

    {
      const uint64_t height = s.height;
      State::StateAccess state(node_.stateDB(), height);

      const uint64_t pot = readU64Global(state, "pot");
      const uint64_t total_supply = readU64Global(state, "total_supply");
      const uint64_t total_staked = readU64Global(state, "total_staked");
      const uint64_t staker_count = readU64Global(state, "staker_count");
      const uint64_t last_apy_bps =
          readU64Global(state, "last_effective_apy_bps");

      const uint64_t epoch = height / Core::ROTATION_INTERVAL;
      const uint64_t epoch_start = epoch * Core::ROTATION_INTERVAL;
      const uint64_t next_epoch = epoch_start + Core::ROTATION_INTERVAL;
      const uint64_t blocks_until_next =
          next_epoch > height ? next_epoch - height : 0;

      beginMetric(out, "clrty_pot", "gauge",
                  "Current staker reward pot balance (atomic CLRTY)");

      beginMetric(out, "clrty_total_supply", "gauge",
                  "Total CLRTY in circulation (atomic)");

      beginMetric(out, "clrty_total_staked", "gauge",
                  "Total staked CLRTY (atomic)");

      beginMetric(out, "clrty_staker_count", "gauge",
                  "Number of accounts with a staked balance");

      beginMetric(out, "clrty_last_effective_apy_bps", "gauge",
                  "APY applied at the last epoch boundary, in basis points");

      beginMetric(out, "clrty_current_epoch", "gauge",
                  "Current epoch number (height / ROTATION_INTERVAL)");

      beginMetric(out, "clrty_blocks_until_epoch", "gauge",
                  "Blocks remaining until the next epoch boundary");

      emitGauge(out, "clrty_pot", pot);
      emitGauge(out, "clrty_total_supply", total_supply);
      emitGauge(out, "clrty_total_staked", total_staked);
      emitGauge(out, "clrty_staker_count", staker_count);
      emitGauge(out, "clrty_last_effective_apy_bps", last_apy_bps);
      emitGauge(out, "clrty_current_epoch", epoch);
      emitGauge(out, "clrty_blocks_until_epoch", blocks_until_next);
    }

    // ---- Consensus ----

    beginMetric(out, "clrty_consensus_height", "gauge",
                "Height the consensus engine is working on (0 if not a validator)");

    beginMetric(out, "clrty_consensus_round", "gauge",
                "Current round within the consensus height");

    beginMetric(out, "clrty_consensus_step", "gauge",
                "Consensus step ordinal: 0=NewHeight 1=Propose 2=Prevote 3=Precommit 4=Commit");

    beginMetric(out, "clrty_consensus_is_proposer", "gauge",
                "1 if this node is the proposer for the current round, 0 otherwise");

    beginMetric(out, "clrty_consensus_prevotes", "gauge",
                "Prevotes recorded for the current round");

    beginMetric(out, "clrty_consensus_precommits", "gauge",
                "Precommits recorded for the current round");

    beginMetric(out, "clrty_consensus_consecutive_timeouts", "gauge",
                "Consecutive rounds at the current height that ended without a commit");

    beginMetric(out, "clrty_consensus_emergency_rotation", "gauge",
                "1 if the engine is in emergency rotation mode, 0 otherwise");

    beginMetric(out, "clrty_active_set_size", "gauge",
                "Number of validators in the active set");

    beginMetric(out, "clrty_consensus_quorum", "gauge",
                "Precommit quorum threshold for the current active set");

    emitGauge(out, "clrty_consensus_height", s.consensus_height);
    emitGauge(out, "clrty_consensus_round",
              static_cast<uint64_t>(s.consensus_round));

    emitGauge(out, "clrty_consensus_step",
              static_cast<uint64_t>(s.consensus_step_ordinal));

    emitGauge(out, "clrty_consensus_is_proposer",
              s.consensus_is_proposer ? uint64_t(1) : uint64_t(0));

    emitGauge(out, "clrty_consensus_prevotes",
              static_cast<uint64_t>(s.consensus_prevotes));

    emitGauge(out, "clrty_consensus_precommits",
              static_cast<uint64_t>(s.consensus_precommits));

    emitGauge(out, "clrty_consensus_consecutive_timeouts",
              static_cast<uint64_t>(s.consensus_consecutive_timeouts));

    emitGauge(out, "clrty_consensus_emergency_rotation",
              s.consensus_emergency_rotation ? uint64_t(1) : uint64_t(0));

    {
      const uint64_t height = s.height;
      State::StateAccess state(node_.stateDB(), height);
      const std::vector<uint64_t> active = readActiveSet(state);
      const size_t quorum = Core::bftQuorum(active.size());

      emitGauge(out, "clrty_active_set_size",
                static_cast<uint64_t>(active.size()));
      emitGauge(out, "clrty_consensus_quorum",
                static_cast<uint64_t>(quorum));
    }

    // ---- Per-validator metrics (opt-in) ----
    //
    //  Gated on config_.include_validator_metrics, which defaults to
    //  false. On a 100-validator chain this block adds roughly 600
    //  time series; an operator who wants to alert on their own
    //  validator can enable it, and one who doesn't pays nothing.
    //
    //  The active set is read once, then each ID is looked up in
    //  state. Each lookup is one SMT read; the total is bounded by
    //  ACTIVE_SET_MAX (100) per scrape. On an idle chain this block
    //  is the largest single cost in render(), and it's still well
    //  under a millisecond.

    if (config_.include_validator_metrics)
    {
      const uint64_t height = s.height;
      State::StateAccess state(node_.stateDB(), height);
      const std::vector<uint64_t> active = readActiveSet(state);

      beginMetric(out, "clrty_validator_stake", "gauge",
                  "Staked amount for the validator, in atomic CLRTY");

      beginMetric(out, "clrty_validator_uptime_bps", "gauge",
                  "Validator uptime EMA, in basis points (10000 = fully online)");

      beginMetric(out, "clrty_validator_reward_multiplier", "gauge",
                  "Validator reward multiplier, in basis points (10000 = unpenalized)");

      beginMetric(out, "clrty_validator_total_rewards_earned", "gauge",
                  "Cumulative rewards earned by the validator, in atomic CLRTY");

      beginMetric(out, "clrty_validator_blocks_produced", "gauge",
                  "Cumulative blocks produced by the validator");

      beginMetric(out, "clrty_validator_pending_unbond_height", "gauge",
                  "Height at which the validator's unbonding completes (0 if not unbonding)");

      for (uint64_t vid : active)
      {
        Core::ValidatorInfo v;
        if (!state.getValidator(vid, v))
          continue;

        const std::string id_str = std::to_string(vid);

        emitGauge(out, "clrty_validator_stake",
                  "validator_id", id_str, v.stake);
        emitGauge(out, "clrty_validator_uptime_bps",
                  "validator_id", id_str,
                  static_cast<uint64_t>(v.uptime_score));
        emitGauge(out, "clrty_validator_reward_multiplier",
                  "validator_id", id_str,
                  static_cast<uint64_t>(v.reward_multiplier));
        emitGauge(out, "clrty_validator_total_rewards_earned",
                  "validator_id", id_str, v.total_rewards_earned);
        emitGauge(out, "clrty_validator_blocks_produced",
                  "validator_id", id_str, v.total_blocks_produced);
        emitGauge(out, "clrty_validator_pending_unbond_height",
                  "validator_id", id_str, v.pending_unbond_height);
      }
    }

    return out;
  }

  //  HTTP

  HttpResponse MetricsHandler::handle(const HttpRequest &request)
  {
    HttpResponse out;
    out.content_type = "text/plain; version=0.0.4; charset=utf-8";

    if (request.path != "/metrics")
    {
      out.status = 404;
      out.content_type = "text/plain";
      out.body = "path must be /metrics\n";
      return out;
    }

    if (request.method != "GET")
    {
      out.status = 405;
      out.content_type = "text/plain";
      out.body = "use GET for metrics\n";
      return out;
    }

    try
    {
      out.status = 200;
      out.body = render();
    }
    catch (const std::exception &)
    {
      out.status = 500;
      out.content_type = "text/plain";
      out.body = "internal error while rendering metrics\n";
    }
    catch (...)
    {
      out.status = 500;
      out.content_type = "text/plain";
      out.body = "internal error while rendering metrics\n";
    }

    return out;
  }

} // namespace Rpc