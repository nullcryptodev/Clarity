// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <vector>

#include "Message.h"
#include "Peer.h"
#include "SyncMessages.h"

#include "Core/Block.h"
#include "Crypto/Types.h"

namespace P2P
{
  // SyncManager drives one peer through the header/block download
  // protocol. One instance per peer, owned by Node, keyed by PeerId.
  //
  // Lifecycle:
  //   - Constructed when the peer reaches Established.
  //   - tick() called periodically from Node's sync tick loop.
  //   - onHeaders() / onBlocks() called when the peer sends those.
  //   - Destroyed when the peer disconnects.
  //
  // The manager never touches the chain or the state. Everything it
  // needs from Node comes through four callbacks:
  //
  //   our_height        — how far along our chain is. Read fresh on
  //                       every state transition; sync picks up where
  //                       the chain currently is, not where it was
  //                       when the manager was created.
  //
  //   send              — deliver a message to the peer.
  //
  //   apply_blocks      — hand a vector of blocks to the node for
  //                       application. Returns the number successfully
  //                       applied (typically all of them or none).
  //                       If it returns less than blocks.size(), the
  //                       manager treats the peer as malicious and
  //                       signals a disconnect.
  //
  //   on_misbehavior    — record a score and (optionally) request
  //                       disconnect. Node translates this into
  //                       Peer::reportMisbehavior and Peer::forceClose.
  //
  // The manager is not thread-safe. Callers must ensure all methods
  // run on one thread. In production, that's the P2P io_context thread;
  // Node's onP2PMessage and onP2PPeerEstablished handlers both run
  // there.

  class SyncManager
  {
  public:
    // ---- Callbacks (set by Node before the first tick) ----

    std::function<uint64_t()> our_height;

    std::function<void(const Message &)> send;

    // Apply a batch of blocks. Returns how many were successfully
    // applied. A return value less than blocks.size() is treated as
    // a protocol violation by the peer that sent them.
    std::function<size_t(const std::vector<Core::Block> &)> apply_blocks;

    // Record a score for the peer, with a human-readable reason.
    // Node translates this into Peer::reportMisbehavior and, if the
    // score crosses the ban threshold, disconnects. The manager does
    // not disconnect on its own — it just reports.
    std::function<void(uint32_t score, const char *reason)> on_misbehavior;

    // ---- Construction ----

    // SyncManager no longer takes the peer's advertised best height.
    // That value is a snapshot from the Version handshake and goes
    // stale the moment the peer commits a block. Instead, sync is
    // driven by asking the peer: GetHeaders on start, GetHeaders on
    // every refresh tick. The response is the truth; the advertised
    // height was only ever a hint.
    SyncManager(PeerId id, uint64_t max_block_bytes);

    // ---- Entry points ----

    // Called once when the peer reaches Established. Sends the first
    // GetHeaders. If the peer is caught up with us, the response will
    // be empty and we'll go Idle on the first tick.
    void start();

    // Called periodically from Node's sync tick loop. Handles two
    // things:
    //   - Active state: fires onRequestTimeout() if a request has
    //     been outstanding longer than its budget.
    //   - Idle state: fires GetHeaders if refresh_interval_ has
    //     elapsed, so we discover blocks the peer committed since
    //     we last asked.
    void tick();

    // Called when the peer sends Headers.
    void onHeaders(const HeadersMessage &m);

    // Called when the peer sends Blocks.
    void onBlocks(const BlocksMessage &m);

    // ---- Configuration ----

    // How often, when Idle, to re-issue GetHeaders to see whether the
    // peer has advanced. This is what makes a node self-heal: without
    // it, a SyncManager that reaches Idle stays Idle forever, and a
    // node whose peer commits new blocks never learns about them.
    //
    // Default 30s. Tests that need to observe a refresh can set it
    // shorter.
    void setRefreshInterval(std::chrono::milliseconds interval)
    {
      refresh_interval_ = interval;
    }

    // ---- Introspection (for tests and RPC) ----

    enum class State
    {
      Idle, // waiting for the next refresh tick
      AwaitingHeaders,
      AwaitingBlocks,
    };

    State state() const noexcept { return state_; }
    size_t pendingHeaderCount() const noexcept { return pending_headers_.size(); }
    size_t pendingBlockCount() const noexcept { return pending_blocks_.size(); }

  private:
    // ---- State machine transitions ----

    void requestHeaders();
    void requestNextBlocks();

    // ---- Timeout handling ----

    void onRequestTimeout();

    PeerId id_;
    uint64_t max_block_bytes_;
    uint32_t max_blocks_per_request_;

    State state_ = State::Idle;

    // Headers received from the peer but not yet converted into
    // block requests. Popped from the front as blocks are applied.
    std::deque<HeadersEntry> pending_headers_;

    // Hashes we've requested blocks for, in request order. Used to
    // verify the Blocks response matches what we asked for.
    std::deque<Crypto::Hash> pending_blocks_;

    // Wall-clock time the current request was sent. Zero when no
    // request is outstanding. Used to detect timeouts.
    std::chrono::steady_clock::time_point request_sent_at_{};

    // Refresh interval for Idle re-checks. See setRefreshInterval.
    std::chrono::milliseconds refresh_interval_{30'000};

    // When Idle, the time of the last refresh attempt. Used to decide
    // whether it's time to re-issue GetHeaders. Not used in other
    // states — those are driven by request_sent_at_.
    std::chrono::steady_clock::time_point last_refresh_at_{};
  };

} // namespace P2P