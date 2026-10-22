// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <set>

#include "Crypto/Types.h"

namespace Bridge
{
  class ChainRuntime;
  class ReleaseTracker;
  class WatcherSession;
  struct ObservedDeposit;

  namespace Scan
  {
    //  How long the scan loop sleeps between polls when there is
    //  no work to do. The loop checks its stop flag every 200 ms
    //  within this window so a stop request is honoured promptly
    //  even during the idle interval.
    constexpr auto SCAN_POLL_INTERVAL = std::chrono::seconds(30);

    //  Fallback burn-finality depth when a ChainRuntime's
    //  config.burn_finality_depth is zero. A per-chain value
    //  always wins; this constant only exists for the "config
    //  did not set it" case.
    constexpr uint16_t kDefaultBurnFinalityDepth = 3;

    //  Withdrawal state machine. Each pending withdrawal the scan
    //  loop has discovered lives in exactly one of these states.
    //  Transitions are driven by the corresponding scan phase
    //  functions below.
    //
    //    Observed     — seen on Clarity, no ack submitted yet
    //    Acking       — ack attestation submitted, waiting for peers
    //    Acked        — quorum reached, waiting for burn finality
    //    Releasable   — finality reached, ready to launch release
    //    Releasing    — release handed to ReleaseTracker, waiting
    //                   for the background wallet RPC call to return
    //    Released     — release confirmed on CCX, waiting to record
    //                   the ack-withdrawal on Clarity
    //    Done         — ack-withdrawal recorded, withdrawal complete
    enum class WithdrawalPhase
    {
      Observed,
      Acking,
      Acked,
      Releasable,
      Releasing,
      Released,
      Done,
    };

    struct TrackedWithdrawal
    {
      uint64_t withdrawal_id{0};
      uint64_t source_chain_id{0};
      uint64_t amount{0}; // Clarity atomic units
      uint64_t created_at_height{0};
      uint64_t ack_quorum{0};
      std::vector<uint8_t> ack_block;
      Crypto::Hash release_tx_hash{};
      uint64_t release_height{0};
      WithdrawalPhase phase{WithdrawalPhase::Observed};
      std::chrono::steady_clock::time_point phase_since;
    };

    //  Convenience aliases for the two maps the scan thread owns.
    //  They are keyed differently because deposits are identified
    //  by (tx_hash, output_index) — encoded as a string key — and
    //  withdrawals by their Clarity-side id.
    using DepositMap = std::map<std::string, ObservedDeposit>;
    using WithdrawalMap = std::map<uint64_t, TrackedWithdrawal>;

    //  ---- The three scan phases ----
    //
    //  runDepositScanPhase and runWithdrawalScanPhase run once per
    //  poll, in that order. drainCompletedReleases runs at the top
    //  of the withdrawal phase and is exposed separately so a
    //  future caller (an RPC endpoint, a test harness) can force a
    //  drain without running a full scan.
    //
    //  All three take the stop flag by shared_ptr so the thread
    //  can check it during long loops without the scan registry
    //  needing to hold a lock while the thread is running.

    void runDepositScanPhase(WatcherSession *session,
                             ChainRuntime &rt,
                             const std::string &chain_name,
                             DepositMap &watched,
                             std::set<std::string> &warned_unregistered_chains,
                             const std::shared_ptr<std::atomic<bool>> &stop);

    void drainCompletedReleases(const std::string &chain_name,
                                ChainRuntime &rt,
                                ReleaseTracker &tracker,
                                WithdrawalMap &tracked);

    void runWithdrawalScanPhase(WatcherSession *session,
                                ChainRuntime &rt,
                                const std::string &chain_name,
                                WithdrawalMap &tracked,
                                ReleaseTracker &release_tracker,
                                const std::shared_ptr<std::atomic<bool>> &stop);

    //  ---- The loop entry point ----
    //
    //  Owns the per-chain maps and the ReleaseTracker for the
    //  lifetime of the thread. Called from ScanRegistry's startScan
    //  via std::thread. Returns when *stop becomes true.
    void runScanLoop(WatcherSession *session,
                     std::string chain_name,
                     std::shared_ptr<std::atomic<bool>> stop);
  } // namespace Scan
} // namespace Bridge