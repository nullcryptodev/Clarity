// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>

#include "Fixtures.h"
#include "Tests/Temp.h"

#include "Consensus/Message.h"
#include "Consensus/Types.h"

#include "Core/EquivocationProof.h"
#include "Core/TransactionTypes.h"
#include "Core/ValidatorTypes.h"

#include "Crypto/Ed25519.h"

#include "State/StateAccess.h"

using namespace State;
using namespace Consensus;
using namespace Tests;

namespace
{
  //  Build a signed Vote with the given key. Used to construct proofs
  //  the verifier will accept.
  //
  //  signer_id is required, not defaulted. The verifier resolves the
  //  signer from signer_id (not signer_index, which is ambiguous
  //  across an emergency-set transition), so a vote constructed
  //  without it fails verification in a way that looks like a
  //  signature problem rather than a missing field. Making it a
  //  required parameter means the compiler catches an omission at the
  //  call site instead of the verifier rejecting it at runtime.
  //
  //  signer_index is provided for the on-wire format only; it does
  //  not affect verification, but the vote is not well-formed without
  //  it.
  Vote makeSignedVote(const Crypto::KeyPair &kp,
                      uint64_t height,
                      uint64_t round,
                      uint16_t signer_index,
                      Id signer_id,
                      bool is_nil,
                      const Crypto::Hash &block_hash)
  {
    Vote v;
    v.height = height;
    v.round = round;
    v.signer_index = signer_index;
    v.signer_id = signer_id;
    v.is_nil = is_nil;
    v.block_hash = block_hash;

    Crypto::Hash h = voteSigningHash(height, round, is_nil, block_hash);
    v.signature = Crypto::sign(h, kp.secretKey);
    return v;
  }

  //  Insert a validator into state whose reward_address doubles as the
  //  signing key. Returns the validator id.
  Id seedValidatorWithKey(StateAccess &s,
                          Id id,
                          const Crypto::KeyPair &kp,
                          uint64_t stake = GlobalConfig::VALIDATOR_MIN_STAKE)
  {
    Core::ValidatorInfo v;
    v.id = id;
    v.stake = stake;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.uptime_score = 10'000;

    std::memcpy(v.reward_address.data.data(),
                kp.publicKey.data.data(), 32);
    std::memcpy(v.owner.data.data(),
                kp.publicKey.data.data(), 32);

    s.putValidator(v);
    return id;
  }

  // Avoids overlap with the fixture's so tests can use their own naming.
  Crypto::Hash makeHash(uint64_t n)
  {
    Crypto::Hash h;
    for (int i = 0; i < 8; ++i)
      h.data[i] = uint8_t(n >> (i * 8));
    for (size_t i = 8; i < 32; ++i)
      h.data[i] = 0;
    return h;
  }
} // anonymous namespace

// ============================================================================
//  Vote-signing-hash equivalence
//
//  This is the load-bearing test for the entire slashing path. Core
//  re-implements voteSigningHash to avoid a layering
//  dependency; if the two ever diverge, every proof either fails to
//  verify (slashing silently stops working) or verifies when it
//  shouldn't (a forged proof could slash an honest validator). Either
//  is a consensus split. Do not delete this test.
// ============================================================================

TEST(Consensus_EquivocationProofTests, VoteSigningHashMatchesConsensus)
{
  for (uint64_t height : {0ULL, 1ULL, 1000ULL, 0xFFFFFFFFFFFFFFFFULL})
  {
    for (uint64_t round : {0ULL, 1ULL, 7ULL})
    {
      for (bool is_nil : {false, true})
      {
        Crypto::Hash bh = makeHash(height * 1000 + round * 10 + (is_nil ? 1 : 0));

        Crypto::Hash a = voteSigningHash(height, round, is_nil, bh);
        Crypto::Hash b = Core::voteSigningHashForCore(height, round, is_nil, bh);

        EXPECT_EQ(a, b)
            << "voteSigningHash divergence at height=" << height
            << " round=" << round << " is_nil=" << is_nil;
      }
    }
  }
}

// ============================================================================
//  Payload encoding
// ============================================================================

TEST(Consensus_EquivocationProofTests, EncodeThenVerifyRoundTrip)
{
  auto kp = Crypto::generateKeyPair();

  //  Validator 7 is seeded below; both votes name it.
  constexpr Id kSignerId = 7;

  Vote va = makeSignedVote(kp, 42, 1, 0, kSignerId, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, kSignerId, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);

  Id vid = seedValidatorWithKey(s, kSignerId, kp);
  std::vector<Id> active_set = {vid};

  auto result = Core::verifyEquivocationProof(payload, active_set, s);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, vid);
}

// ============================================================================
//  Rejection cases
// ============================================================================

TEST(Consensus_EquivocationProofTests, SameValueIsNotEquivocation)
{
  auto kp = Crypto::generateKeyPair();

  // Two votes with identical (block_hash, is_nil).
  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  auto result = Core::verifyEquivocationProof(payload, {7}, s);
  EXPECT_FALSE(result.has_value());
}

TEST(Consensus_EquivocationProofTests, DifferentHeightsRejected)
{
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 43, 1, 0, 7, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, DifferentRoundsRejected)
{
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 2, 0, 7, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, DifferentSignersRejected)
{
  auto kp_a = Crypto::generateKeyPair();
  auto kp_b = Crypto::generateKeyPair();

  //  Vote A names validator 7, vote B names validator 8. The proof
  //  framework rejects it because the two votes must name the same
  //  signer to be a proof of equivocation by one validator.
  Vote va = makeSignedVote(kp_a, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp_b, 42, 1, 1, 8, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp_a);
  seedValidatorWithKey(s, 8, kp_b);

  EXPECT_FALSE(
      Core::verifyEquivocationProof(payload, {7, 8}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, BadSignatureOnVoteARejected)
{
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(200));

  // Corrupt vote A's signature.
  va.signature.data[0] ^= 0x01;

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, BadSignatureOnVoteBRejected)
{
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(200));

  vb.signature.data[0] ^= 0x01;

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, SignerIdNotInActiveSetRejected)
{
  //  Votes name validator 7 by signer_id, but the active_set passed
  //  in does not contain it. The proof is rejected: the caller's
  //  policy is "a validator not currently in the slashable set
  //  cannot be slashed by this proof."
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {8, 9}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, ValidatorNotRegisteredRejected)
{
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  //  Deliberately do not seed the validator. The active_set names id
  //  7, but state has no record for it, so signature verification
  //  has no key to resolve against.

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, UnsetSignerIdRejected)
{
  //  A vote that carries no signer_id is not resolvable against a set.
  //  The verifier rejects it rather than falling back to signer_index,
  //  which would be ambiguous across an emergency-set transition.
  auto kp = Crypto::generateKeyPair();

  Vote va = makeSignedVote(kp, 42, 1, 0, INVALID_ID, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, INVALID_ID, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

// ============================================================================
//  nil / block conflict
// ============================================================================

TEST(Consensus_EquivocationProofTests, BlockVoteAndNilVoteConflict)
{
  auto kp = Crypto::generateKeyPair();
  constexpr Id kSignerId = 7;

  //  Same (height, round, signer). One votes the block, one votes nil.
  //  This is an equivocation even though the block vote carries a
  //  non-zero hash and the nil vote carries the null hash; the is_nil
  //  flag is what disambiguates.
  Vote va = makeSignedVote(kp, 42, 1, 0, kSignerId, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, kSignerId, true, Crypto::Hash{});

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  TempDB db;
  StateAccess s(db.db(), 0);
  Id vid = seedValidatorWithKey(s, kSignerId, kp);

  auto result = Core::verifyEquivocationProof(payload, {vid}, s);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(*result, vid);
}

// ============================================================================
//  Framing
// ============================================================================

TEST(Consensus_EquivocationProofTests, TruncatedPayloadRejected)
{
  auto kp = Crypto::generateKeyPair();
  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  payload.resize(payload.size() - 1);

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, TrailingBytesRejected)
{
  auto kp = Crypto::generateKeyPair();
  Vote va = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(100));
  Vote vb = makeSignedVote(kp, 42, 1, 0, 7, false, makeHash(200));

  auto payload = Core::encodeSlashPayload(
      encodeVote(va),
      encodeVote(vb));

  payload.push_back(0xFF);

  TempDB db;
  StateAccess s(db.db(), 0);
  seedValidatorWithKey(s, 7, kp);

  EXPECT_FALSE(Core::verifyEquivocationProof(payload, {7}, s).has_value());
}

TEST(Consensus_EquivocationProofTests, EmptyPayloadRejected)
{
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<uint8_t> empty;
  EXPECT_FALSE(Core::verifyEquivocationProof(empty, {}, s).has_value());
}