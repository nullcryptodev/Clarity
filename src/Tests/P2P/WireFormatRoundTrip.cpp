// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Consensus/Message.h"
#include "Consensus/Types.h"

#include "Core/Block.h"

#include "Crypto/Types.h"

#include "P2P/Message.h"
#include "P2P/MessageTypes.h"

using namespace Consensus;
using namespace P2P;
using namespace Tests;

// Proposal round trip:
// consensus encode -> P2P framing -> P2P decode -> consensus decode
// Every field must survive.

TEST(WireFormatRoundTrip, ProposalSurvivesEndToEnd)
{
  // Build a proposal.
  Proposal original;
  original.height = 42;
  original.round = 3;
  original.signer_index = 1;
  original.block_bytes = makeBlock(42).serialize();
  original.signature = makeSignature(0xA0);

  // Consensus encode.
  auto payload = encodeProposal(original);

  // Wrap in a P2P message.
  Message wire_msg(MessageType::Proposal, std::move(payload));

  // Through the framing layer and back.
  Message received = roundTripThroughWire(wire_msg);

  // The framing layer must preserve the message type.
  EXPECT_EQ(received.type, MessageType::Proposal);

  // The payload must be byte-identical.
  ASSERT_EQ(received.payload.size(), encodeProposal(original).size());
  EXPECT_EQ(received.payload, encodeProposal(original));

  // Consensus decode.
  Proposal decoded;
  ASSERT_TRUE(decodeProposal(received.payload.data(),
                             received.payload.size(),
                             decoded));

  // Every field.
  EXPECT_EQ(decoded.height, original.height);
  EXPECT_EQ(decoded.round, original.round);
  EXPECT_EQ(decoded.signer_index, original.signer_index);
  EXPECT_EQ(decoded.block_bytes, original.block_bytes);
  EXPECT_EQ(std::memcmp(decoded.signature.data.data(),
                        original.signature.data.data(), 64),
            0);
}

//  Vote round trip: same structure.

TEST(WireFormatRoundTrip, VoteSurvivesEndToEnd)
{
  Vote original;
  original.height = 42;
  original.round = 3;
  original.signer_index = 1;
  original.is_nil = false;
  original.block_hash = makeHash(0xC0);
  original.signature = makeSignature(0xE0);

  auto payload = encodeVote(original);
  Message wire_msg(MessageType::Prevote, std::move(payload));

  Message received = roundTripThroughWire(wire_msg);

  EXPECT_EQ(received.type, MessageType::Prevote);
  EXPECT_EQ(received.payload, encodeVote(original));

  Vote decoded;
  ASSERT_TRUE(decodeVote(received.payload.data(),
                         received.payload.size(),
                         decoded));

  EXPECT_EQ(decoded.height, original.height);
  EXPECT_EQ(decoded.round, original.round);
  EXPECT_EQ(decoded.signer_index, original.signer_index);
  EXPECT_EQ(decoded.is_nil, original.is_nil);
  EXPECT_EQ(std::memcmp(decoded.block_hash.data.data(),
                        original.block_hash.data.data(), 32),
            0);
  EXPECT_EQ(std::memcmp(decoded.signature.data.data(),
                        original.signature.data.data(), 64),
            0);
}

// Nil vote: the is_nil flag must survive (it changes the consensus
// engine's interpretation entirely).

TEST(WireFormatRoundTrip, NilVotePreservesFlag)
{
  Vote original;
  original.height = 1;
  original.round = 0;
  original.signer_index = 0;
  original.is_nil = true;
  original.block_hash = Crypto::Hash{};
  original.signature = makeSignature(0x11);

  auto payload = encodeVote(original);
  Message wire_msg(MessageType::Prevote, std::move(payload));
  Message received = roundTripThroughWire(wire_msg);

  Vote decoded;
  ASSERT_TRUE(decodeVote(received.payload.data(),
                         received.payload.size(),
                         decoded));
  EXPECT_TRUE(decoded.is_nil);
}

// Framing layer: message type must survive, and the magic must match.

TEST(WireFormatRoundTrip, MessageTypeSurvivesFraming)
{
  for (auto type : {MessageType::Proposal,
                    MessageType::Prevote,
                    MessageType::Precommit})
  {
    Message msg(type, {0x01, 0x02, 0x03});
    Message received = roundTripThroughWire(msg);
    EXPECT_EQ(received.type, type) << "type=" << static_cast<int>(type);
    EXPECT_EQ(received.payload, msg.payload);
  }
}

//  Framing layer: bad magic is rejected.

TEST(WireFormatRoundTrip, WrongMagicIsRejected)
{
  Message msg(MessageType::Proposal, {0x01, 0x02, 0x03});

  auto wire = encodeMessage(msg, TEST_MAGIC, TEST_MAX_SIZE);

  // Corrupt the magic.
  wire[0] ^= 0xFF;

  MessageDecoder decoder(TEST_MAGIC, TEST_MAX_SIZE);
  decoder.feed(wire.data(), wire.size());
  auto result = decoder.next();

  EXPECT_EQ(result.status, DecodeStatus::Corrupted);
}