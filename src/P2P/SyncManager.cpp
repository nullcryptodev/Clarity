// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SyncManager.h"

#include "VersionMessage.h" // GetHeadersMessage

#include <algorithm>

namespace P2P
{
  namespace
  {
    // Timeouts. The Headers timeout is shorter because headers are
    // cheap and a peer that doesn't answer them is almost certainly
    // not worth waiting on. Blocks can be large and a slow link is
    // not the peer's fault, so the budget is more generous.
    constexpr auto HEADERS_TIMEOUT = std::chrono::seconds(30);
    constexpr auto BLOCKS_TIMEOUT = std::chrono::seconds(60);

    // Misbehavior scores.
    constexpr uint32_t SCORE_TIMEOUT = 1;
    constexpr uint32_t SCORE_PROTOCOL_VIOLATION = 50;
  } // anonymous namespace

  SyncManager::SyncManager(PeerId id, uint64_t max_block_bytes)
      : id_(id),
        max_block_bytes_(max_block_bytes),
        max_blocks_per_request_(maxBlocksPerRequest(max_block_bytes))
  {
  }

  // ---- Lifecycle ----

  void SyncManager::start()
  {
    last_refresh_at_ = std::chrono::steady_clock::now();

    // Always send GetHeaders on start, regardless of what the peer
    // advertised during the Version handshake. That value is a
    // snapshot from before this SyncManager existed and may already
    // be stale (the peer may have committed blocks since).
    //
    // If the peer is actually caught up with us, the response will
    // be empty and we'll go Idle on the first tick. If it's ahead,
    // sync proceeds normally. The cost of an unnecessary GetHeaders
    // is one small round-trip; the cost of a missed one is a node
    // that stays out of sync until the first refresh tick — up to
    // refresh_interval_ of stale state.
    requestHeaders();
  }

  void SyncManager::tick()
  {
    const auto now = std::chrono::steady_clock::now();

    // ---- Active request: check for timeout ----
    if (state_ != State::Idle)
    {
      if (request_sent_at_ == std::chrono::steady_clock::time_point{})
        return; // shouldn't happen — state implies a request

      const auto budget = (state_ == State::AwaitingHeaders)
                              ? HEADERS_TIMEOUT
                              : BLOCKS_TIMEOUT;

      if (now - request_sent_at_ >= budget)
        onRequestTimeout();
      return;
    }

    // ---- Idle: periodically re-check whether the peer has advanced ----
    //
    // This is the mechanism that lets a node notice new blocks from a
    // peer it's already caught up to. Without it, a SyncManager that
    // reaches Idle stays Idle forever, and a non-validator that caught
    // up at height N never learns about height N+1 unless the peer
    // sends a Block relay — which only fires for blocks committed
    // *after* the connection was established.
    if (now - last_refresh_at_ >= refresh_interval_)
    {
      last_refresh_at_ = now;

      // Re-issue GetHeaders unconditionally. If the peer is still at
      // our height, the response will be empty and we'll go back to
      // Idle. If it has advanced, we'll transition to AwaitingHeaders
      // and the normal flow takes over.
      requestHeaders();
    }
  }

  // ---- Incoming messages ----

  void SyncManager::onHeaders(const HeadersMessage &m)
  {
    if (state_ != State::AwaitingHeaders)
    {
      // Headers out of band — peer sent them without us asking.
      // This is a protocol violation but a benign one; some peers
      // announce blocks proactively. We just drop them.
      return;
    }

    // Sanity-check the response. We sent GetHeaders(startHeight =
    // our height + 1). Every entry must be strictly increasing in
    // height, starting at our_height + 1.
    //
    // We deliberately do NOT check against the peer's advertised
    // best height from the Version handshake. That value is a
    // snapshot and goes stale the moment the peer commits a block.
    // A peer that advertised height 0 at handshake time and now
    // serves headers up to height 100 is not misbehaving — it's
    // just ahead of where it was. The real defense against a peer
    // that serves unusable headers is apply_blocks: if a block
    // doesn't apply, we score the peer then.
    if (!m.entries.empty())
    {
      uint64_t expected = our_height ? our_height() + 1 : 0;
      uint64_t prev = expected - 1;
      for (const auto &e : m.entries)
      {
        if (e.height <= prev || e.height != prev + 1)
        {
          on_misbehavior(SCORE_PROTOCOL_VIOLATION,
                         "Headers not contiguous with requested range");
          state_ = State::Idle;
          request_sent_at_ = {};
          pending_headers_.clear();
          return;
        }
        prev = e.height;
      }
    }

    // Accept.
    pending_headers_.clear();
    for (const auto &e : m.entries)
      pending_headers_.push_back(e);

    request_sent_at_ = {};

    if (pending_headers_.empty())
    {
      // Peer says we're caught up.
      state_ = State::Idle;
      last_refresh_at_ = std::chrono::steady_clock::now();
      return;
    }

    requestNextBlocks();
  }

  void SyncManager::onBlocks(const BlocksMessage &m)
  {
    if (state_ != State::AwaitingBlocks)
    {
      // Same as Headers out of band.
      return;
    }

    // We asked for exactly pending_blocks_.size() blocks. The peer
    // may return fewer (it doesn't have them all) but never more.
    if (m.blocks.size() > pending_blocks_.size())
    {
      on_misbehavior(SCORE_PROTOCOL_VIOLATION,
                     "Blocks response larger than request");
      state_ = State::Idle;
      request_sent_at_ = {};
      pending_blocks_.clear();
      pending_headers_.clear();
      return;
    }

    // Apply. If any fail, the peer sent us something unusable.
    size_t applied = 0;
    if (apply_blocks)
      applied = apply_blocks(m.blocks);

    if (applied != m.blocks.size())
    {
      on_misbehavior(SCORE_PROTOCOL_VIOLATION,
                     "Block failed to apply");
      state_ = State::Idle;
      request_sent_at_ = {};
      pending_blocks_.clear();
      pending_headers_.clear();
      return;
    }

    // Pop the corresponding header entries. We use applied (==
    // m.blocks.size()) because the peer may legitimately return
    // fewer blocks than we asked for — we keep the unfulfilled
    // hashes queued for a retry.
    for (size_t i = 0; i < applied; ++i)
    {
      if (!pending_blocks_.empty())
        pending_blocks_.pop_front();
      if (!pending_headers_.empty())
        pending_headers_.pop_front();
    }

    request_sent_at_ = {};

    // If we have more queued work, keep going. This includes the
    // "peer returned fewer blocks than we asked for" case — the
    // unfulfilled hashes are still in pending_blocks_.
    if (!pending_blocks_.empty() || !pending_headers_.empty())
    {
      requestNextBlocks();
      return;
    }

    // Nothing left to apply. Go Idle. The periodic refresh will
    // re-issue GetHeaders after refresh_interval_, and if the peer
    // has advanced we'll pick up the new headers then.
    state_ = State::Idle;
    last_refresh_at_ = std::chrono::steady_clock::now();
  }

  // ---- Request construction ----

  void SyncManager::requestHeaders()
  {
    if (!our_height || !send)
      return;

    GetHeadersMessage req;
    req.startHeight = our_height() + 1;
    req.limit = MAX_HEADERS_PER_REQUEST;

    Message msg;
    msg.type = MessageType::GetHeaders;
    msg.payload = serializeGetHeaders(req);

    send(msg);

    state_ = State::AwaitingHeaders;
    request_sent_at_ = std::chrono::steady_clock::now();
  }

  void SyncManager::requestNextBlocks()
  {
    if (!send)
      return;

    // Pop up to max_blocks_per_request_ headers into pending_blocks_.
    // If pending_blocks_ is already populated (a retry after a
    // partial Blocks response), don't refill it from
    // pending_headers_ — we want to finish what we already asked
    // for.
    while (pending_blocks_.size() < max_blocks_per_request_ &&
           !pending_headers_.empty())
    {
      pending_blocks_.push_back(pending_headers_.front().hash);
      pending_headers_.pop_front();
    }

    if (pending_blocks_.empty())
    {
      state_ = State::Idle;
      last_refresh_at_ = std::chrono::steady_clock::now();
      return;
    }

    GetBlocksMessage req;
    req.hashes.assign(pending_blocks_.begin(), pending_blocks_.end());

    Message msg;
    msg.type = MessageType::GetBlocks;
    msg.payload = serializeGetBlocks(req);

    send(msg);

    state_ = State::AwaitingBlocks;
    request_sent_at_ = std::chrono::steady_clock::now();
  }

  // ---- Timeout ----

  void SyncManager::onRequestTimeout()
  {
    // Reset everything. The next tick will try again from the top.
    on_misbehavior(SCORE_TIMEOUT, "Sync request timed out");

    state_ = State::Idle;
    request_sent_at_ = {};
    pending_blocks_.clear();
    pending_headers_.clear();
    last_refresh_at_ = std::chrono::steady_clock::now();

    // Retry immediately. If the peer really is behind us, the
    // response will be empty and we'll go Idle again. If it's
    // ahead, we resume syncing.
    requestHeaders();
  }

} // namespace P2P