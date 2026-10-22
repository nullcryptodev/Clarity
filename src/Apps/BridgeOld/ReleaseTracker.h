// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ChainAdapter.h"
#include "Session.h"

#include "Crypto/Types.h"

#include "Wallet/RpcClient.h"

namespace Bridge
{
  //  ReleaseTracker
  //
  //  Runs CCX releases on background threads so the scan loop isn't
  //  stalled by the wallet RPC's blocking `transfer` call.
  //
  //  The problem
  //  -----------
  //
  //  CcxAdapter::submit_release calls the CCX wallet RPC's `transfer`
  //  method. The wallet RPC blocks until the release transaction is
  //  confirmed in a block — that's the wallet's contract, not the
  //  bridge's. On CCX (a PoW chain with a 120-second target block
  //  time), the happy case is ~2 minutes. Under poor network
  //  conditions it can be 10+ minutes.
  //
  //  A scan loop that called submit_release inline would stall for
  //  that long, during which no deposits would be scanned and no
  //  ack attestations would be submitted. On a busy bridge that's
  //  unacceptable.
  //
  //  The solution
  //  ------------
  //
  //  ReleaseTracker launches each release on its own thread. The
  //  scan loop calls launch() (non-blocking, returns immediately),
  //  continues its normal work, and periodically calls
  //  drain_completed() to collect finished releases. Each finished
  //  release is either Succeeded (with a CCX tx hash) or Failed
  //  (with a reason string); the scan loop advances each
  //  withdrawal's phase accordingly.
  //
  //  Lifecycle
  //  ---------
  //
  //  - One ReleaseTracker per ChainRuntime. Owned by the runtime,
  //    created alongside the scan worker and destroyed when the
  //    scan worker stops. Different chains can't interfere with
  //    each other's releases.
  //
  //  - launch() with an already-tracked withdrawal is a no-op
  //    (returns false). The scan loop doesn't need to guard against
  //    double-launching the same withdrawal.
  //
  //  - shutdown() sets a stop flag, joins all worker threads, and
  //    waits for each in-flight submit_release to finish its current
  //    blocking wallet RPC call. A release that's mid-flight when
  //    shutdown is called completes normally and its result is
  //    discarded — the withdrawal will be rediscovered on restart
  //    via getPendingWithdrawals.
  //
  //  Thread safety
  //  -------------
  //
  //  All public methods are safe to call from the scan loop thread.
  //  launch() and drain_completed() must be called from the same
  //  thread (the scan loop); they are not mutually exclusive with
  //  each other, but the tracker assumes a single drainer. Worker
  //  threads only ever touch their own entry's result fields under
  //  the tracker's internal mutex.
  class ReleaseTracker
  {
  public:
    //  The state of one in-flight release. Populated by the worker
    //  thread as it runs; drained by the scan loop.
    struct CompletedRelease
    {
      uint64_t withdrawal_id{0};
      bool succeeded{false};
      Crypto::Hash tx_hash{}; // valid iff succeeded
      std::string reason;     // valid iff !succeeded
    };

    ReleaseTracker() = default;
    ~ReleaseTracker();

    ReleaseTracker(const ReleaseTracker &) = delete;
    ReleaseTracker &operator=(const ReleaseTracker &) = delete;

    //  Launch a release for the given withdrawal on a background
    //  thread. `rt` must outlive the tracker (it's owned by the
    //  ChainRuntime, and the tracker is too). `request` and
    //  `ack_block` are copied into the worker; the caller can
    //  destroy them after launch() returns.
    //
    //  Returns false if the withdrawal is already in flight. Returns
    //  true if a thread was started; the caller will see the result
    //  via drain_completed() on a later poll.
    //
    //  Not blocking. Does not throw on the normal path (thread
    //  creation failure throws std::system_error, which the caller
    //  should treat as a fatal error and shut the bridge down).
    bool launch(ChainRuntime &rt,
                const ReleaseRequest &request,
                uint64_t amount_source_atomic,
                const std::vector<uint8_t> &ack_block);

    //  Collect all finished releases since the last call. Removes
    //  them from the tracker's in-flight set.
    //
    //  Returns an empty vector if nothing has completed since the
    //  last drain. Never blocks (except for the internal mutex, which
    //  is held only briefly).
    std::vector<CompletedRelease> drain_completed();

    //  Stop accepting new launches and join all worker threads. Any
    //  threads currently in a blocking wallet RPC call will finish
    //  that call; the tracker waits for them. Results from
    //  in-flight releases are discarded — they'll be rediscovered
    //  on restart.
    //
    //  Idempotent: safe to call multiple times.
    void shutdown();

    //  True if the tracker has any threads running (either actively
    //  releasing or waiting to be joined). Diagnostic only.
    bool in_flight() const;

  private:
    struct InFlight
    {
      uint64_t withdrawal_id{0};
      std::thread thread;
      std::atomic<bool> done{false};
      bool succeeded{false};
      Crypto::Hash tx_hash{};
      std::string reason;
    };

    void runRelease(std::shared_ptr<InFlight> entry,
                    ChainRuntime *rt,
                    ReleaseRequest request,
                    uint64_t amount_source_atomic,
                    std::vector<uint8_t> ack_block);

    mutable std::mutex mutex_;
    std::map<uint64_t, std::shared_ptr<InFlight>> in_flight_;
    std::atomic<bool> stop_{false};
    bool shutdown_called_{false};
  };

} // namespace Bridge