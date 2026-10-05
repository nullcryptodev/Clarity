// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <vector>

#include "P2P/SyncManager.h"
#include "P2P/SyncMessages.h"
#include "P2P/VersionMessage.h"

#include "Core/Block.h"

namespace
{
  // A tiny test harness that stands in for Node. Tracks the chain
  // height, records sent messages, and applies blocks by incrementing
  // the height.
  //
  // Note: SyncManager no longer takes a peer's advertised best height.
  // The manager's start() always sends GetHeaders, and periodic
  // refresh (via tick()) handles the "peer advanced since handshake"
  // case. See SyncManager.h for the rationale.
  struct Harness
  {
    P2P::SyncManager mgr{1, 256 * 1024};

    uint64_t our_height = 0;
    std::vector<P2P::Message> sent;
    size_t blocks_applied = 0;
    std::vector<std::pair<uint32_t, std::string>> misbehaviors;

    Harness()
    {
      mgr.our_height = [this]()
      { return our_height; };
      mgr.send = [this](const P2P::Message &m)
      { sent.push_back(m); };
      mgr.apply_blocks = [this](const std::vector<Core::Block> &bs)
      {
        blocks_applied += bs.size();
        for (size_t i = 0; i < bs.size(); ++i)
          our_height++;
        return bs.size();
      };
      mgr.on_misbehavior = [this](uint32_t score, const char *reason)
      {
        misbehaviors.push_back({score, std::string(reason)});
      };
    }

    // Convenience: build a HeadersMessage with contiguous entries
    // starting at `start_height`.
    static P2P::HeadersMessage makeBlockHeaders(uint64_t start_height, size_t n)
    {
      P2P::HeadersMessage h;
      for (size_t i = 0; i < n; ++i)
      {
        P2P::HeadersEntry e;
        e.height = start_height + i;
        // Deterministic hash.
        for (size_t b = 0; b < e.hash.data.size(); ++b)
          e.hash.data[b] = uint8_t(start_height + i + b);
        h.entries.push_back(e);
      }
      return h;
    }

    // Build a BlocksMessage with n empty blocks.
    static P2P::BlocksMessage makeBlocks(size_t n)
    {
      P2P::BlocksMessage b;
      for (size_t i = 0; i < n; ++i)
      {
        Core::Block blk;
        blk.header.version = 1;
        blk.header.chain_id = 0x434C5247;
        blk.header.height = uint64_t(i);
        b.blocks.push_back(blk);
      }
      return b;
    }

    P2P::GetHeadersMessage lastGetHeaders() const
    {
      for (auto it = sent.rbegin(); it != sent.rend(); ++it)
        if (it->type == P2P::MessageType::GetHeaders)
        {
          P2P::GetHeadersMessage g;
          EXPECT_TRUE(P2P::deserializeGetHeaders(
              it->payload.data(), it->payload.size(), g));
          return g;
        }
      return {};
    }

    P2P::GetBlocksMessage lastGetBlocks() const
    {
      for (auto it = sent.rbegin(); it != sent.rend(); ++it)
        if (it->type == P2P::MessageType::GetBlocks)
        {
          P2P::GetBlocksMessage g;
          EXPECT_TRUE(P2P::deserializeGetBlocks(
              it->payload.data(), it->payload.size(), g));
          return g;
        }
      return {};
    }

    size_t countMessagesOfType(P2P::MessageType t) const
    {
      size_t n = 0;
      for (const auto &m : sent)
        if (m.type == t)
          ++n;
      return n;
    }
  };
} // anonymous namespace

// ============================================================================
//  start() behavior
// ============================================================================

TEST(Node_SyncManager, StartAlwaysSendsGetHeaders)
{
  // start() is unconditional: it always sends GetHeaders, regardless
  // of what the peer advertised during the handshake. The advertised
  // height is a snapshot and may be stale; asking is the only way to
  // know where the peer actually is.
  //
  // If the peer happens to be caught up with us, the response will
  // be empty and we'll go Idle on the next message. If it's ahead,
  // sync proceeds normally.

  Harness h;
  h.our_height = 100;
  h.mgr.start();

  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);
  ASSERT_EQ(h.sent.size(), 1u);
  EXPECT_EQ(h.sent[0].type, P2P::MessageType::GetHeaders);

  auto req = h.lastGetHeaders();
  EXPECT_EQ(req.startHeight, 101u); // our_height + 1
  EXPECT_EQ(req.limit, P2P::MAX_HEADERS_PER_REQUEST);
}

TEST(Node_SyncManager, StartFromHeightZeroSendsGetHeadersForOne)
{
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);

  auto req = h.lastGetHeaders();
  EXPECT_EQ(req.startHeight, 1u);
}

// ============================================================================
//  Headers → GetBlocks
// ============================================================================

TEST(Node_SyncManager, HeadersTriggersGetBlocks)
{
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  h.mgr.onHeaders(Harness::makeBlockHeaders(1, 10));

  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingBlocks);
  EXPECT_EQ(h.mgr.pendingBlockCount(), 10u);

  auto req = h.lastGetBlocks();
  EXPECT_EQ(req.hashes.size(), 10u);
}

TEST(Node_SyncManager, EmptyHeadersGoesIdle)
{
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  // Peer responds with an empty Headers message: we're caught up.
  h.mgr.onHeaders(Harness::makeBlockHeaders(1, 0));
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);
}

// ============================================================================
//  Blocks → apply → continue
// ============================================================================

TEST(Node_SyncManager, BlocksAppliedThenGoesIdle)
{
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  h.mgr.onHeaders(Harness::makeBlockHeaders(1, 10));

  // Peer sends all 10 blocks.
  h.mgr.onBlocks(Harness::makeBlocks(10));

  EXPECT_EQ(h.blocks_applied, 10u);
  EXPECT_EQ(h.our_height, 10u);
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);
}

TEST(Node_SyncManager, PartialBlocksResponseContinuesSameBatch)
{
  // Ask for 10 blocks in one batch. Peer returns 5. We should
  // request the remaining 5 before going Idle.
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  h.mgr.onHeaders(Harness::makeBlockHeaders(1, 10));

  // First request went out for 10 blocks. Peer responds with 5.
  h.mgr.onBlocks(Harness::makeBlocks(5));

  // We applied 5, and should now have 5 more pending_blocks_ waiting.
  EXPECT_EQ(h.blocks_applied, 5u);
  EXPECT_EQ(h.our_height, 5u);
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingBlocks);

  auto req = h.lastGetBlocks();
  EXPECT_EQ(req.hashes.size(), 5u);
}

// ============================================================================
//  Validation
// ============================================================================

TEST(Node_SyncManager, NonContiguousHeadersAreMisbehavior)
{
  Harness h;
  h.our_height = 100;
  h.mgr.start();

  // We asked for height 101. Peer sends 200.
  P2P::HeadersMessage bad;
  P2P::HeadersEntry e;
  e.height = 200;
  bad.entries.push_back(e);

  h.mgr.onHeaders(bad);

  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);
  ASSERT_EQ(h.misbehaviors.size(), 1u);
  EXPECT_GE(h.misbehaviors[0].first, 50u);
}

TEST(Node_SyncManager, MoreBlocksThanRequestedIsMisbehavior)
{
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  h.mgr.onHeaders(Harness::makeBlockHeaders(1, 5));

  // Asked for 5 blocks. Peer sends 6.
  h.mgr.onBlocks(Harness::makeBlocks(6));

  ASSERT_EQ(h.misbehaviors.size(), 1u);
  EXPECT_GE(h.misbehaviors[0].first, 50u);
}

TEST(Node_SyncManager, FailedApplyIsMisbehavior)
{
  Harness h;
  h.our_height = 0;
  h.mgr.start();

  // Override apply_blocks to fail.
  h.mgr.apply_blocks = [](const std::vector<Core::Block> &) -> size_t
  { return 0; };

  h.mgr.onHeaders(Harness::makeBlockHeaders(1, 5));
  h.mgr.onBlocks(Harness::makeBlocks(5));

  ASSERT_EQ(h.misbehaviors.size(), 1u);
  EXPECT_GE(h.misbehaviors[0].first, 50u);
}

// ============================================================================
//  Timeout
// ============================================================================

TEST(Node_SyncManager, TickBeforeTimeoutIsNoOp)
{
  // Can't easily test the wall-clock timeout without a clock
  // injection. Instead, verify that calling tick() before the
  // timeout expires does nothing. A full timeout test requires a
  // mockable clock, deferred to a later patch.
  Harness h;
  h.our_height = 0;
  h.mgr.setRefreshInterval(std::chrono::hours(1));
  h.mgr.start();

  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);

  h.mgr.tick();
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);
  EXPECT_TRUE(h.misbehaviors.empty());
}

// ============================================================================
//  Idle refresh
// ============================================================================

TEST(Node_SyncManager, IdleRefreshSendsGetHeaders)
{
  Harness h;
  h.our_height = 5;
  h.mgr.setRefreshInterval(std::chrono::milliseconds(0)); // fire immediately
  h.mgr.start();

  // start() sends the initial GetHeaders, so we're in AwaitingHeaders.
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);
  EXPECT_EQ(h.countMessagesOfType(P2P::MessageType::GetHeaders), 1u);

  // Peer responds: empty, we're caught up.
  h.mgr.onHeaders(Harness::makeBlockHeaders(6, 0));
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);

  // First tick after the interval should send another GetHeaders.
  h.mgr.tick();

  EXPECT_EQ(h.countMessagesOfType(P2P::MessageType::GetHeaders), 2u);
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);

  auto req = h.lastGetHeaders();
  EXPECT_EQ(req.startHeight, 6u); // our_height + 1
}

TEST(Node_SyncManager, IdleRefreshNoOpBeforeInterval)
{
  Harness h;
  h.our_height = 5;
  h.mgr.setRefreshInterval(std::chrono::seconds(60));
  h.mgr.start();

  // start() sent the first GetHeaders. Consume the response so we
  // reach Idle.
  h.mgr.onHeaders(Harness::makeBlockHeaders(6, 0));
  ASSERT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);

  const size_t before = h.sent.size();

  // Tick immediately — the refresh interval hasn't elapsed.
  h.mgr.tick();
  EXPECT_EQ(h.sent.size(), before);
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);
}

TEST(Node_SyncManager, RefreshDiscoversNewBlocks)
{
  // The core self-healing scenario: SyncManager is Idle (caught up),
  // then the peer commits a new block. The refresh tick re-issues
  // GetHeaders, gets a non-empty response, and downloads the new
  // block — all without any external trigger.

  Harness h;
  h.our_height = 5;
  h.mgr.setRefreshInterval(std::chrono::milliseconds(0));
  h.mgr.start();

  // Initial sync: empty response, we're caught up.
  h.mgr.onHeaders(Harness::makeBlockHeaders(6, 0));
  ASSERT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);

  // Peer commits block 6. Our next tick discovers it.
  h.mgr.tick();
  ASSERT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingHeaders);

  // Peer tells us about block 6.
  h.mgr.onHeaders(Harness::makeBlockHeaders(6, 1));
  ASSERT_EQ(h.mgr.state(), P2P::SyncManager::State::AwaitingBlocks);

  // Peer sends block 6. We apply it and go Idle.
  h.mgr.onBlocks(Harness::makeBlocks(1));

  EXPECT_EQ(h.our_height, 6u);
  EXPECT_EQ(h.mgr.state(), P2P::SyncManager::State::Idle);
}