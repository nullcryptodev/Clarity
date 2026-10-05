// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>
#include <cstring>
#include <functional>

#include "Fixtures.h"
#include "Tests/Temp.h"

#include "Consensus/Types.h"

#include "Core/ValidatorTypes.h"

#include "State/StateAccess.h"

using namespace State;
using namespace Consensus;
using namespace Tests;

namespace
{
  //  Build a signer that returns a valid signature for a given hash.
  //  Different signers get different keypairs so their signatures
  //  differ, which matters for dedup tests.
  struct TestSigner
  {
    Crypto::KeyPair kp = Crypto::generateKeyPair();

    Crypto::Signature sign(const Crypto::Hash &h) const
    {
      return Crypto::sign(h, kp.secretKey);
    }

    Crypto::PublicKey pub() const { return kp.publicKey; }
  };

  //  Seed a validator into state whose reward_address is the
  //  signer's public key. This is the codebase convention: the
  //  validator's signing key is its reward_address. Mirrors
  //  seedValidatorWithKey in Consensus_EquivocationProofTests.
  void seedValidator(StateAccess &s, Id id, const TestSigner &signer,
                     uint64_t stake = GlobalConfig::VALIDATOR_MIN_STAKE)
  {
    Core::ValidatorInfo v;
    v.id = id;
    v.stake = stake;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.uptime_score = 10'000;
    std::memcpy(v.reward_address.data.data(),
                signer.pub().data.data(), 32);
    std::memcpy(v.owner.data.data(), signer.pub().data.data(), 32);
    s.putValidator(v);
  }

  //  Make a certificate from a set of signers at a single round.
  TimeoutCertificate makeCert(Height h, Round r,
                              const std::vector<Index> &signers,
                              const std::vector<TestSigner> &keyring,
                              Round round_override_for_vote_a =
                                  std::numeric_limits<Round>::max())
  {
    TimeoutCertificate cert;
    cert.votes.reserve(signers.size());

    const Crypto::Hash signing_hash = timeoutVoteSigningHash(h, r);

    for (size_t i = 0; i < signers.size(); ++i)
    {
      TimeoutVote tv;
      tv.height = h;
      tv.round = r;
      tv.signer_index = signers[i];

      //  For the wrong-round test we want the first vote to carry a
      //  different round while its signature is over the real (h, r).
      //  That's a signature over a different message and would fail
      //  for the wrong reason, so we override the round of the vote
      //  AND sign over the overridden round, so the test exercises
      //  the round-mismatch check and not the signature check.
      if (i == 0 && round_override_for_vote_a !=
                        std::numeric_limits<Round>::max())
      {
        tv.round = round_override_for_vote_a;
        tv.signature = keyring.at(signers[i]).sign(timeoutVoteSigningHash(h, round_override_for_vote_a));
      }
      else
      {
        tv.signature = keyring.at(signers[i]).sign(signing_hash);
      }

      cert.votes.push_back(tv);
    }

    return cert;
  }

  //  Count how many distinct signer indices appear in a certificate.
  size_t distinctSigners(const TimeoutCertificate &cert)
  {
    std::set<Index> s;
    for (const auto &v : cert.votes)
      s.insert(v.signer_index);
    return s.size();
  }
} // anonymous namespace

// ============================================================================
//  Positive path
// ============================================================================

TEST(Consensus_TimeoutCertificate, ValidFPlusOneCertificateVerifies)
{
  //  n=4, f=1, required=2. Two distinct signers at round 30.
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  {
    return s.getValidator(vid, out);
  };

  std::string error;
  EXPECT_TRUE(verifyTimeoutCertificate(cert, committed, 0,
                                       Core::EMERGENCY_ROTATION_ROUNDS,
                                       lookup, error))
      << error;
}

TEST(Consensus_TimeoutCertificate, LargerCertificateVerifies)
{
  //  More than required signers is fine — the verifier stops counting
  //  once it reaches f+1.
  std::vector<TestSigner> keyring(7);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 7; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4, 5, 6, 7};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS,
                       {0, 1, 2, 3, 4}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  {
    return s.getValidator(vid, out);
  };

  std::string error;
  EXPECT_TRUE(verifyTimeoutCertificate(cert, committed, 0,
                                       Core::EMERGENCY_ROTATION_ROUNDS,
                                       lookup, error));
}

// ============================================================================
//  Negative path: framing and count
// ============================================================================

TEST(Consensus_TimeoutCertificate, TooFewAttestationsRejected)
{
  //  n=4 needs f+1=2. A cert with 1 signer is rejected.
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
  EXPECT_FALSE(error.empty());
}

TEST(Consensus_TimeoutCertificate, EmptyCertificateRejected)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  TimeoutCertificate cert;

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, CommittedSetTooSmallRejected)
{
  //  A committed set below 4 cannot form a BFT quorum, and the
  //  verifier refuses outright rather than computing f+1 from a
  //  nonsensical n.
  std::vector<TestSigner> keyring(3);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 3; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

// ============================================================================
//  Negative path: per-vote field checks
// ============================================================================

TEST(Consensus_TimeoutCertificate, VoteForWrongHeightRejected)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  //  Corrupt the first vote's height. The signature is over the
  //  original (height, round), so this vote now fails on the height
  //  check before the signature check runs.
  cert.votes[0].height = 99;

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, VoteForWrongRoundRejected)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};

  //  Sign vote A over round (threshold + 5) and set the certificate's
  //  round to (threshold). Vote A's round then disagrees with the
  //  block's emergency_rotation.
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring,
                       /*round_override_for_vote_a=*/Core::EMERGENCY_ROTATION_ROUNDS + 5);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, RoundBelowThresholdRejected)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};

  //  Valid signatures, but at a round below EMERGENCY_ROTATION_ROUNDS.
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS - 1, {0, 1}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS - 1,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, SignerIndexOutOfRangeRejected)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  //  Push the second vote's signer index past the committed set.
  cert.votes[1].signer_index = 99;

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, DuplicateSignerRejected)
{
  //  Two votes from the same signer is not two attestations. The
  //  verifier rejects the duplicate rather than silently letting one
  //  signer count twice.
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};

  //  Build two votes both from signer 0. Their signatures are valid
  //  but identical, which the dedup check catches by signer index.
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 0}, keyring);
  ASSERT_EQ(distinctSigners(cert), 1u);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, UnknownValidatorRejected)
{
  //  The signer index resolves to a validator id that isn't in state.
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  //  Seed only validators 1 and 2 — 3 and 4 are missing.
  seedValidator(s, 1, keyring[0]);
  seedValidator(s, 2, keyring[1]);

  std::vector<Id> committed = {1, 2, 3, 4}; // id 3 unknown to state
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 2}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, BadSignatureRejected)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  cert.votes[0].signature.data[0] ^= 0xFF;

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, BothSignaturesMustVerify)
{
  //  If only the second vote is corrupt, the verifier still rejects.
  //  A test that only corrupts the first vote is insufficient — the
  //  verifier must check every vote, not just the first.
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  cert.votes[1].signature.data[0] ^= 0xFF;

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

TEST(Consensus_TimeoutCertificate, SignerIdentityMatters)
{
  //  Same signature bytes, but the cert claims a different signer
  //  index. The signature was produced by validator 1 but the index
  //  says validator 2. Verification must fail.
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  //  Vote 0 was signed by keyring[0] (validator 1). Change its index
  //  to 1 (validator 2). The signature no longer matches.
  cert.votes[0].signer_index = 1;

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error;
  EXPECT_FALSE(verifyTimeoutCertificate(cert, committed, 0,
                                        Core::EMERGENCY_ROTATION_ROUNDS,
                                        lookup, error));
}

// ============================================================================
//  Idempotence
// ============================================================================

TEST(Consensus_TimeoutCertificate, VerificationIsIdempotent)
{
  std::vector<TestSigner> keyring(4);
  TempDB db;
  StateAccess s(db.db(), 0);
  for (size_t i = 0; i < 4; ++i)
    seedValidator(s, static_cast<Id>(i + 1), keyring[i]);

  std::vector<Id> committed = {1, 2, 3, 4};
  auto cert = makeCert(0, Core::EMERGENCY_ROTATION_ROUNDS, {0, 1}, keyring);

  auto lookup = [&s](Id vid, Core::ValidatorInfo &out) -> bool
  { return s.getValidator(vid, out); };

  std::string error1, error2;
  EXPECT_TRUE(verifyTimeoutCertificate(cert, committed, 0,
                                       Core::EMERGENCY_ROTATION_ROUNDS,
                                       lookup, error1));
  EXPECT_TRUE(verifyTimeoutCertificate(cert, committed, 0,
                                       Core::EMERGENCY_ROTATION_ROUNDS,
                                       lookup, error2));
  EXPECT_TRUE(error1.empty());
  EXPECT_TRUE(error2.empty());
}