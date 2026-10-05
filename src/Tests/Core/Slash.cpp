// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"

#include "Consensus/Message.h"
#include "Consensus/Types.h"
#include "Core/Block.h"
#include "Core/BlockProcessor.h"
#include "Core/EquivocationProof.h"
#include "Core/GlobalState.h"
#include "Core/RewardTypes.h"
#include "Core/TransactionTypes.h"
#include "Core/ValidatorTypes.h"
#include "Crypto/Ed25519.h"
#include "State/StateAccess.h"

#include <cstring>

using namespace Core;
using namespace Tests;

namespace
{
  //  signer_id is mandatory. Consensus::Vote carries both signer_id
  //  and signer_index; verifyEquivocationProof resolves the signer
  //  from signer_id, not from signer_index, because the index means
  //  different things in the committed set and an emergency set. A
  //  vote with signer_id == INVALID_ID is rejected before any
  //  signature check runs, so tests that want a slash to succeed must
  //  populate both fields.
  Consensus::Vote makeSignedVote(const Crypto::KeyPair &kp,
                                 Id signer_id,
                                 uint64_t height,
                                 uint64_t round,
                                 uint16_t signer_index,
                                 bool is_nil,
                                 const Crypto::Hash &block_hash)
  {
    Consensus::Vote v;
    v.height = height;
    v.round = round;
    v.signer_index = signer_index;
    v.signer_id = signer_id;
    v.is_nil = is_nil;
    v.block_hash = block_hash;
    v.signature = Crypto::sign(
        Consensus::voteSigningHash(height, round, is_nil, block_hash),
        kp.secretKey);
    return v;
  }

  std::vector<uint8_t> makeSlashPayload(const Consensus::Vote &a,
                                        const Consensus::Vote &b)
  {
    return Core::encodeSlashPayload(Consensus::encodeVote(a),
                                    Consensus::encodeVote(b));
  }

  Core::Transaction makeSlashTx(uint64_t chain_id,
                                const Consensus::Vote &a,
                                const Consensus::Vote &b)
  {
    Core::Transaction tx;
    tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
    tx.chain_id = chain_id;
    tx.tx_type = TxType::Slash;
    tx.payload = makeSlashPayload(a, b);
    return tx;
  }
} // anonymous namespace

// ============================================================================
//  Slash integration: a block containing a Slash tx is accepted, the
//  target's stake is reduced, and the pot is credited by exactly the
//  amount the stake lost.
// ============================================================================

TEST_F(Core_BlockProcessorFixture, SlashTxInBlock_ReducesStakeAndCreditsPot)
{
  //  Fresh non-seed validator. It goes at index 0 of the active set;
  //  the two genesis seeds fill indices 1 and 2. bftQuorum(3) = 3,
  //  so all three sign.
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  constexpr uint64_t TARGET_STAKE = 1'000'000'000ULL;

  registerValidatorWithKey(TARGET_ID, target_key, TARGET_STAKE);

  const std::vector<Id> slash_set = {TARGET_ID, 1, 2};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(slash_set)); });

  //  Equivocation at height 1, round 0, signer_index 0 (the target).
  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(1001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(1002));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  uint64_t pot_before = currentPot();
  ValidatorInfo before;
  ASSERT_TRUE(readValidator(TARGET_ID, before));
  ASSERT_EQ(before.stake, TARGET_STAKE);
  ASSERT_EQ(before.infraction_count, 0);
  ASSERT_EQ(before.reward_multiplier, REWARD_MULTIPLIER_START);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx},
                             /*dry_run=*/false, slash_set);
  ASSERT_TRUE(r.valid) << r.error;
  ASSERT_EQ(r.receipts.size(), 1u);
  EXPECT_EQ(r.receipts[0].status, ReceiptStatus::Success);

  ValidatorInfo after;
  ASSERT_TRUE(readValidator(TARGET_ID, after));
  const uint64_t expected_slash = applyBps(TARGET_STAKE, SLASH_AMOUNT_BPS);

  EXPECT_EQ(after.stake, TARGET_STAKE - expected_slash);
  EXPECT_EQ(after.reward_multiplier,
            REWARD_MULTIPLIER_START - REWARD_MULTIPLIER_PENALTY);
  EXPECT_EQ(after.infraction_count, 1u);
  EXPECT_EQ(after.last_infraction_height, 1u);

  //  The pot receives the slash amount PLUS whatever the reward
  //  distribution path contributes on the same block. The reward
  //  path credits the pot with three separate things:
  //
  //    1. The staker share of the block reward, on every block.
  //    2. The penalty difference from the producer's reduced
  //       multiplier, if the producer's multiplier is below 100%.
  //    3. The penalty difference from each active validator's
  //       reduced multiplier.
  //
  //  The slashed validator has multiplier 8000 after this block, so
  //  contribution (3) is nonzero here — the slash reduces the reward
  //  the validator receives from this same block, and the difference
  //  flows to the pot.
  //
  //  We assert the lower bound: the pot grew by at least the slash.
  //  Asserting the exact total would require duplicating
  //  computeBlockReward's arithmetic in the test, coupling this test
  //  to the reward path. The reward path's own contribution to the
  //  pot is covered by RewardMultiplierApplied, SlashedRewardsGoToPot,
  //  and TotalRewardsEqualBlockReward in this same suite.
  EXPECT_GE(currentPot() - pot_before, expected_slash);
}

TEST_F(Core_BlockProcessorFixture, SlashTxWithSameValueVotesIsRejected)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  registerValidatorWithKey(TARGET_ID, target_key);

  const std::vector<Id> slash_set = {TARGET_ID, 1, 2};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(slash_set)); });

  //  Identical value: not a conflict.
  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(3001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(3001));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx}, false, slash_set);
  EXPECT_FALSE(r.valid);
  EXPECT_NE(r.error.find("slash failed"), std::string::npos)
      << "got: " << r.error;
}

TEST_F(Core_BlockProcessorFixture, SlashTxWithBadSignatureIsRejected)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  registerValidatorWithKey(TARGET_ID, target_key);

  const std::vector<Id> slash_set = {TARGET_ID, 1, 2};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(slash_set)); });

  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(4001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(4002));
  vote_b.signature.data[0] ^= 0x01;

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx}, false, slash_set);
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, SlashTxAgainstUnregisteredValidatorIsRejected)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;

  //  Register the key for quorum-signing purposes, but do NOT put a
  //  validator record in state. checkQuorum will sign and verify
  //  successfully (it resolves the pubkey from validator_keys_ in
  //  the fixture, not from state), but verifyEquivocationProof will
  //  fail at the state lookup step.
  validator_keys_[TARGET_ID] = target_key;

  const std::vector<Id> slash_set = {TARGET_ID, 1, 2};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(slash_set)); });

  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(5001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(5002));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx}, false, slash_set);
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, SlashTxForDifferentHeightIsRejected)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  registerValidatorWithKey(TARGET_ID, target_key);

  const std::vector<Id> slash_set = {TARGET_ID, 1, 2};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(slash_set)); });

  //  Different heights — not an equivocation.
  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(6001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 2, 0, 0, false, makeHash(6002));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx}, false, slash_set);
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, SlashTxChangesStateRoot)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  constexpr uint64_t TARGET_STAKE = 1'000'000'000ULL;

  registerValidatorWithKey(TARGET_ID, target_key, TARGET_STAKE);

  const std::vector<Id> slash_set = {TARGET_ID, 1, 2};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(slash_set)); });

  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(7001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 1, 0, 0, false, makeHash(7002));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx}, false, slash_set);
  ASSERT_TRUE(r.valid) << r.error;

  //  The block's own state-root check (inside applyBlock) already
  //  proves the post-state root matches what the block committed to;
  //  ASSERT_TRUE(r.valid) above is that check passing. What we assert
  //  here is the observable state change that caused the root to
  //  differ from an empty-block root.
  ValidatorInfo after;
  ASSERT_TRUE(readValidator(TARGET_ID, after));
  EXPECT_LT(after.stake, TARGET_STAKE);
  EXPECT_EQ(after.infraction_count, 1u);
}

// ============================================================================
//  Slash against a validator that rotated out between the equivocation
//  and the block that carries the proof.
//
//  verifyEquivocationProof resolves the signer from signer_id, not
//  from active_set[signer_index], so the proof is self-contained
//  across a rotation. But it also applies a set-membership check
//  ("is this signer currently slashable?") that, on the on-chain
//  path, is redundant with the checks executeSystemSlash performs
//  against the record. BlockProcessor::applySlash passes an empty
//  active_set to disable that redundant check.
//
//  Without the empty set, this test fails: the proof is rejected
//  because the target is no longer active, and the block is refused.
// ============================================================================

TEST_F(Core_BlockProcessorFixture, SlashAgainstRotatedOutValidatorStillSlashes)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  constexpr uint64_t TARGET_STAKE = 1'000'000'000ULL;

  // Register the target as an *inactive* validator. Its record
  // exists and its key is registered for signing, but it is not in
  // the active set. This is exactly the post-rotation state.
  registerValidatorWithKey(TARGET_ID, target_key, TARGET_STAKE,
                           /*is_seed=*/false, /*is_active=*/false);

  // The active set for the slash block is {1, 2} — the seeds. The
  // target is deliberately NOT in it.
  const std::vector<Id> slash_set = {1, 2};

  // The equivocation is at height 1, round 0, signer_id 100,
  // signer_index 0. The index is meaningless here (it refers to a
  // set the target has left) but verifyEquivocationProof resolves
  // by id, so the proof is still valid.
  Consensus::Vote vote_a = makeSignedVote(target_key, TARGET_ID, 1, 0, 0,
                                          false, makeHash(8001));
  Consensus::Vote vote_b = makeSignedVote(target_key, TARGET_ID, 1, 0, 0,
                                          false, makeHash(8002));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  uint64_t pot_before = currentPot();
  ValidatorInfo before;
  ASSERT_TRUE(readValidator(TARGET_ID, before));
  ASSERT_EQ(before.stake, TARGET_STAKE);

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx},
                             /*dry_run=*/false, slash_set);
  ASSERT_TRUE(r.valid) << r.error;

  ValidatorInfo after;
  ASSERT_TRUE(readValidator(TARGET_ID, after));
  const uint64_t expected_slash = applyBps(TARGET_STAKE, SLASH_AMOUNT_BPS);
  EXPECT_EQ(after.stake, TARGET_STAKE - expected_slash);
  EXPECT_EQ(after.infraction_count, 1u);

  EXPECT_GE(currentPot() - pot_before, expected_slash);
}

// ============================================================================
//  A Slash tx against a seed must be a no-op, not a block-rejection.
//
//  Before Change C, executeSystemSlash returned Failure for a seed
//  target, and applySlash treated that Failure as a block-level
//  error. A proposer that included a Slash against a seed in every
//  block would halt the chain. Now the block is accepted and the
//  seed's record is untouched.
// ============================================================================

TEST_F(Core_BlockProcessorFixture, SlashAgainstSeedIsAcceptedNoOp)
{
  // The seeds' keys are deterministic and already registered by the
  // fixture. The active set is the seeds themselves.
  const std::vector<Id> slash_set = {1, 2};
  constexpr Id SEED_ID = 1;

  // A real equivocation by seed 1. The proof is valid, but the seed
  // exemption in executeSystemSlash turns it into a no-op.
  Consensus::Vote vote_a = makeSignedVote(seed1_, SEED_ID, 1, 0, 0,
                                          false, makeHash(9001));
  Consensus::Vote vote_b = makeSignedVote(seed1_, SEED_ID, 1, 0, 0,
                                          false, makeHash(9002));

  Transaction slash_tx = makeSlashTx(genesis_config_.chain_id, vote_a, vote_b);

  ValidatorInfo before;
  ASSERT_TRUE(readValidator(SEED_ID, before));
  const uint64_t stake_before = before.stake;
  const uint16_t multiplier_before = before.reward_multiplier;
  const uint16_t infractions_before = before.infraction_count;

  BlockResult r = applyBlock(1, genesis_hash_, {slash_tx},
                             /*dry_run=*/false, slash_set);
  ASSERT_TRUE(r.valid) << r.error;

  // Seed record is completely unchanged.
  ValidatorInfo after;
  ASSERT_TRUE(readValidator(SEED_ID, after));
  EXPECT_EQ(after.stake, stake_before);
  EXPECT_EQ(after.reward_multiplier, multiplier_before);
  EXPECT_EQ(after.infraction_count, infractions_before);
}