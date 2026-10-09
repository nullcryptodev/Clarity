// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

#include "MessageTypes.h"
#include "Common/RateLimiter.h"

namespace P2P
{
  // Cost of a message type against the aggregate budget. Separate from
  // `messageCost` on purpose — see the class comment on
  // AggregateLimiter. The ratio is compressed relative to the per-peer
  // table: a control message is 1, a proof request is 10 (not 50), a
  // block is 5 (not 10). The intent is "expensive work is shed first"
  // without letting a single legitimate request dominate the budget.
  //
  // Returns 1 for unknown types. Consensus types are charged here even
  // though they are not charged to the per-peer general bucket.
  uint32_t aggregateCost(MessageType t) noexcept;

  // Node-wide rate limiter for inbound message work.
  //
  // The per-peer bucket in `Peer` bounds what any one peer can do. It
  // does not bound the sum: 100 peers each staying under their own cap
  // can still saturate the io_context thread's serving capacity. This
  // limiter is the second line of defense — an aggregate work budget,
  // charged by message type, checked at the same point the per-peer
  // bucket is checked.
  //
  // Differences from the per-peer bucket:
  //
  //   * Cost table is separate (`aggregateCost`), not `messageCost`.
  //     The per-peer table assigns GetProof a cost of 50 because
  //     serving one proof is ~50x a control message. At the aggregate
  //     level that ratio is wrong: a single legitimate proof request
  //     would consume an eighth of a modest budget and starve header
  //     sync. The aggregate table compresses the ratio — expensive
  //     types still cost more, but not proportionally so.
  //
  //   * Consensus types are charged here. They are not charged to the
  //     per-peer general bucket (they have their own), but at the
  //     aggregate level they must count: a crowd of non-validators
  //     sending junk proposals is a real flood vector, and the
  //     per-peer cap on each of them doesn't help if there are enough
  //     of them.
  //
  //   * A trip does NOT imply a ban. The per-peer bucket reports
  //     misbehavior on trip; this one does not. A peer behind a shared
  //     NAT can trip the aggregate budget through no fault of its own,
  //     and banning its IP would punish every peer behind the same NAT.
  //     The correct response is to shed the message and close the
  //     connection, not to blacklist.
  //
  // Threading: NOT thread-safe. Owned by P2PManager, touched only from
  // the io_context thread (all Peer read handlers run there). If the
  // io_context is ever run on more than one thread, or if the limiter
  // is shared across io_contexts, this must gain a mutex.
  //
  // Disabled when burst == 0 or refillPerSecond == 0, matching the
  // per-peer and RPC conventions.
  class AggregateLimiter
  {
  public:
    AggregateLimiter() = default;

    AggregateLimiter(uint32_t burst, uint32_t refillPerSecond)
        : bucket_(burst, refillPerSecond)
    {
    }

    // Returns true if the message may proceed. On false, the caller
    // must close the connection without reporting misbehavior.
    bool allow(MessageType type)
    {
      return bucket_.tryConsume(aggregateCost(type));
    }

    bool enabled() const noexcept { return bucket_.enabled(); }
    uint32_t burst() const noexcept { return bucket_.burst(); }
    uint32_t refillPerSecond() const noexcept { return bucket_.refillPerSecond(); }

    // Tokens available right now, post-refill. For tests and metrics.
    uint32_t available() { return bucket_.available(); }

  private:
    Common::RateLimiter bucket_;
  };

} // namespace P2P