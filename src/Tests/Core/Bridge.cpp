// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/BridgeTypes.h"
#include "Core/BridgeWatcherTypes.h"
#include "Core/Bridge/ConcealCCX.h"
#include "Core/GlobalState.h"

#include "Crypto/Helpers.h"

#include "State/StateAccess.h"

#include "Fixtures.h"

using namespace Core;
using namespace Tests;

namespace
{
  //  Make a Hash whose first byte is `b`, rest zero. Used by tests
  //  that need distinguishable, non-null hashes; the value has no
  //  cryptographic meaning.
  Crypto::Hash hashWithFirstByte(uint8_t b)
  {
    Crypto::Hash h;
    h.data[0] = b;
    return h;
  }

  //  Make a PublicKey whose first byte is `b`, rest zero. Same
  //  caveat — not a real ed25519 point, but encodeDestination /
  //  decodeDestination only check nullness.
  Crypto::PublicKey pubkeyWithFirstByte(uint8_t b)
  {
    Crypto::PublicKey pk;
    pk.data[0] = b;
    return pk;
  }

  //  Build the [2] count LE || N*66 signature block used by
  //  verifyGovernanceSignatures and by any caller that wants to
  //  hand-build a governance signature block.
  std::vector<uint8_t> makeSignatureBlock(
      const std::vector<std::pair<uint16_t, Crypto::KeyPair>> &signers,
      const Crypto::Hash &signing_hash)
  {
    std::vector<uint8_t> block;
    const uint16_t count = static_cast<uint16_t>(signers.size());
    block.push_back(uint8_t(count));
    block.push_back(uint8_t(count >> 8));

    for (const auto &[idx, kp] : signers)
    {
      block.push_back(uint8_t(idx));
      block.push_back(uint8_t(idx >> 8));
      const Crypto::Signature sig =
          Crypto::sign(signing_hash, kp.secretKey);
      block.insert(block.end(), sig.data.begin(), sig.data.end());
    }
    return block;
  }

  std::vector<uint8_t> leU64(uint64_t v)
  {
    std::vector<uint8_t> out(8);
    for (int i = 0; i < 8; ++i)
      out[i] = uint8_t(v >> (i * 8));
    return out;
  }

  Crypto::Hash signGovernanceMessage(const char *domain,
                                     const std::vector<uint8_t> &message)
  {
    return Crypto::hashDomain(domain, message.data(), message.size());
  }
} // anonymous namespace

// ============================================================================
//  BridgeMint — happy paths
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_Succeeds)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0xAA);

  //  Build the message once, verify the fixture signs what the
  //  executor verifies.
  std::vector<uint8_t> msg;
  for (int i = 0; i < 8; ++i)
    msg.push_back(uint8_t(CcxBridge::CCX_CHAIN_ID >> (i * 8)));
  msg.insert(msg.end(), source_tx_hash.data.begin(), source_tx_hash.data.end());
  for (int i = 0; i < 4; ++i)
    msg.push_back(0);
  msg.insert(msg.end(), alice_addr.data.begin(), alice_addr.data.end());
  for (int i = 0; i < 8; ++i)
    msg.push_back(uint8_t(uint64_t(1000) >> (i * 8)));

  const Crypto::Hash test_hash =
      Crypto::hashDomain("bmin", msg.data(), msg.size());

  //  Now build the sig block directly (no helper), signing test_hash.
  std::vector<uint8_t> sigs;
  sigs.push_back(2);
  sigs.push_back(0);
  for (auto [idx, kp] : std::vector<std::pair<uint16_t, Crypto::KeyPair>>{
           {0, seed1_}, {1, seed2_}})
  {
    sigs.push_back(uint8_t(idx));
    sigs.push_back(uint8_t(idx >> 8));
    Crypto::Signature s = Crypto::sign(test_hash, kp.secretKey);
    sigs.insert(sigs.end(), s.data.begin(), s.data.end());
  }

  //  Build the tx payload manually.
  std::vector<uint8_t> payload = msg;
  payload.insert(payload.end(), sigs.begin(), sigs.end());

  const Transaction tx = TransactionBuilder()
                             .type(Core::TxType::BridgeMint)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .tokenId(NATIVE_TOKEN_ID)
                             .chainId(genesis_config_.chain_id)
                             .payload(std::move(payload))
                             .build();

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  ASSERT_TRUE(r.valid) << r.error;
}

TEST_F(Core_BlockProcessorFixture, BridgeMint_TwoDistinctDepositsInOneBlock)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);

  const Crypto::Hash h1 = hashWithFirstByte(0x01);
  const Crypto::Hash h2 = hashWithFirstByte(0x02);

  auto make_mint = [&](const Crypto::Hash &h, uint64_t nonce)
  {
    const std::vector<uint8_t> sigs = signBridgeMintMessage(
        CcxBridge::CCX_CHAIN_ID, h, 0, alice_addr, 500,
        {{0, seed1_}, {1, seed2_}});
    return makeBridgeMintTx(alice_, CcxBridge::CCX_CHAIN_ID,
                            h, 0, alice_addr, 500, sigs, nonce);
  };

  const uint64_t before = balanceOfToken(alice_addr, wrapped);

  const BlockResult r = applyBlock(1, genesis_hash_,
                                   {make_mint(h1, 0), make_mint(h2, 1)});
  ASSERT_TRUE(r.valid) << r.error;

  EXPECT_EQ(balanceOfToken(alice_addr, wrapped), before + 1'000);

  //  Reader after all writes.
  EXPECT_EQ(makeGlobalReader().bridgeConsumedCount(), 2u);
}

// ============================================================================
//  BridgeMint — replay
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsReplay)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0xBB);

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  ASSERT_TRUE(applyBlock(1, genesis_hash_, {tx}).valid);

  const std::vector<uint8_t> sigs2 = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});
  const Transaction tx2 = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs2, /*nonce=*/1);

  const BlockResult r = applyBlock(2, currentStateRoot(), {tx2});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  BridgeMint — signer failures
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsBadSignature)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0xCC);

  std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});

  sigs[6] ^= 0xFF;

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsBelowThreshold)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0xDD);

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsDuplicateSigner)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0xEE);

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {0, seed1_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  BridgeMint — active-set minimum
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsIfWatcherSetDropsBelowMin)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0xFF);

  withState([&](State::StateAccess &s)
            {
    BridgeWatcherInfo w2;
    ASSERT_TRUE(s.getBridgeWatcher(2, w2));
    w2.is_active = false;
    s.putBridgeWatcher(w2); });

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  BridgeMint — chain / token failures
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsUnknownChain)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0x11);
  constexpr uint64_t UNKNOWN_CHAIN = 0xDEADBEEF;

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      UNKNOWN_CHAIN, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, UNKNOWN_CHAIN, source_tx_hash, 0, alice_addr, 1'000,
      sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsWrongTokenFingerprint)
{
  const Id wrapped = wrappedCcxTokenId();

  withState([&](State::StateAccess &s)
            {
    TokenInfo t;
    ASSERT_TRUE(s.getToken(wrapped, t));
    t.fingerprint = hashWithFirstByte(0xFF);
    s.putToken(t); });

  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0x22);

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  BridgeMint — paused
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_RejectsWhenPaused)
{
  withState([&](State::StateAccess &s)
            { GlobalStateWriter(s).setBridgePaused(true); });

  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0x33);

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 1'000,
      {{0, seed1_}, {1, seed2_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 1'000, sigs, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  BridgeBurn — happy path
//
//  Reordered from the previous version: the `pending_before` read
//  (which needs makeGlobalReader) is now done AFTER the block is
//  applied, not before. Reading it before would hold a read txn
//  open across the applyBlock's write txn and deadlock.
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeBurn_SucceedsAndEnqueues)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  fundWrappedCcx(alice_addr, 5'000);

  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x01));
  ASSERT_EQ(blob.size(), CcxBridge::CCX_DESTINATION_BYTES);

  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, /*amount=*/2'000,
      wrapped, /*nonce=*/0);

  const uint64_t before = balanceOfToken(alice_addr, wrapped);

  //  Apply first; all writes done here.
  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  ASSERT_TRUE(r.valid) << r.error;

  EXPECT_EQ(balanceOfToken(alice_addr, wrapped), before - 2'000);

  //  Now read the pending count. It was 0 before the burn, and the
  //  apply added one withdrawal.
  EXPECT_EQ(makeGlobalReader().bridgeWithdrawalsPending(), 1u);

  BridgeWithdrawal w;
  readState([&](State::StateAccess &s)
            { ASSERT_TRUE(s.getBridgeWithdrawal(1, w)); });
  EXPECT_EQ(w.id, 1u);
  EXPECT_EQ(w.source_chain_id, CcxBridge::CCX_CHAIN_ID);
  EXPECT_EQ(w.wrapped_token_id, wrapped);
  EXPECT_EQ(w.burner, alice_addr);
  EXPECT_EQ(w.amount, 2'000u);
  EXPECT_EQ(w.destination_blob, blob);
  EXPECT_TRUE(w.isWellFormed());
}

// ============================================================================
//  BridgeBurn — failures
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeBurn_RejectsInsufficientBalance)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x02));

  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, /*amount=*/1'000,
      wrapped, /*nonce=*/0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeBurn_RejectsWrongToken)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  fundToken(alice_addr, /*token_id=*/100, 5'000);

  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x03));

  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, /*amount=*/1'000,
      /*wrapped_token_id=*/100, /*nonce=*/0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeBurn_RejectsWhenPaused)
{
  withState([&](State::StateAccess &s)
            { GlobalStateWriter(s).setBridgePaused(true); });

  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  fundWrappedCcx(alice_addr, 5'000);

  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x04));

  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, 1'000, wrapped, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeBurn_RejectsBlobTooShort)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);

  fundWrappedCcx(alice_addr, 5'000);

  std::vector<uint8_t> short_blob(32, 0xAA);

  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, short_blob, 1'000,
      wrapped, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeBurn_RejectsBlobTooLong)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);

  fundWrappedCcx(alice_addr, 5'000);

  std::vector<uint8_t> long_blob(128, 0xBB);

  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, long_blob, 1'000,
      wrapped, 0);

  const BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  BridgeAckWithdrawal — happy path + failure modes
//
//  Same reorder as BridgeBurn: reads before the burn apply (which
//  is the last write before the ack) are done via readState, not
//  makeGlobalReader. The reader is called only after the ack is
//  applied and no further writes happen.
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeAck_DeletesRecordAndDecrementsPending)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  fundWrappedCcx(alice_addr, 5'000);

  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x05));

  //  Create a withdrawal. This is the last write before the ack.
  const Transaction burn = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, 1'000, wrapped, 0);
  ASSERT_TRUE(applyBlock(1, genesis_hash_, {burn}).valid);

  //  Build the ack.
  const std::vector<uint8_t> msg = leU64(1);
  const Crypto::Hash signing_hash = signGovernanceMessage("back", msg);

  const std::vector<uint8_t> sig_block = makeSignatureBlock(
      {{0, seed1_}, {1, seed2_}}, signing_hash);

  std::vector<uint8_t> payload;
  payload.insert(payload.end(), msg.begin(), msg.end());
  payload.insert(payload.end(), sig_block.begin(), sig_block.end());

  const Transaction ack = TransactionBuilder()
                              .type(Core::TxType::BridgeAckWithdrawal)
                              .from(alice_)
                              .to(Crypto::Address{})
                              .amount(0)
                              .fee(1)
                              .nonce(1)
                              .tokenId(NATIVE_TOKEN_ID)
                              .chainId(genesis_config_.chain_id)
                              .payload(payload)
                              .build();

  const BlockResult r = applyBlock(2, currentStateRoot(), {ack});
  ASSERT_TRUE(r.valid) << r.error;

  //  Record gone.
  readState([&](State::StateAccess &s)
            {
    BridgeWithdrawal w;
    EXPECT_FALSE(s.getBridgeWithdrawal(1, w)); });

  //  Pending count is now 0 (was 0, burn added 1, ack removed 1).
  EXPECT_EQ(makeGlobalReader().bridgeWithdrawalsPending(), 0u);
}

TEST_F(Core_BlockProcessorFixture, BridgeAck_RejectsMissingWithdrawal)
{
  const std::vector<uint8_t> msg = leU64(42);
  const Crypto::Hash signing_hash = signGovernanceMessage("back", msg);
  const std::vector<uint8_t> sig_block = makeSignatureBlock(
      {{0, seed1_}, {1, seed2_}}, signing_hash);

  std::vector<uint8_t> payload;
  payload.insert(payload.end(), msg.begin(), msg.end());
  payload.insert(payload.end(), sig_block.begin(), sig_block.end());

  const Transaction ack = TransactionBuilder()
                              .type(Core::TxType::BridgeAckWithdrawal)
                              .from(alice_)
                              .to(Crypto::Address{})
                              .amount(0)
                              .fee(1)
                              .nonce(0)
                              .tokenId(NATIVE_TOKEN_ID)
                              .chainId(genesis_config_.chain_id)
                              .payload(payload)
                              .build();

  const BlockResult r = applyBlock(1, genesis_hash_, {ack});
  EXPECT_FALSE(r.valid);
}

TEST_F(Core_BlockProcessorFixture, BridgeAck_RejectsBelowThreshold)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  fundWrappedCcx(alice_addr, 5'000);
  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x06));
  const Transaction burn = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, 1'000, wrapped, 0);
  ASSERT_TRUE(applyBlock(1, genesis_hash_, {burn}).valid);

  const std::vector<uint8_t> msg = leU64(1);
  const Crypto::Hash signing_hash = signGovernanceMessage("back", msg);
  const std::vector<uint8_t> sig_block = makeSignatureBlock(
      {{0, seed1_}}, signing_hash);

  std::vector<uint8_t> payload;
  payload.insert(payload.end(), msg.begin(), msg.end());
  payload.insert(payload.end(), sig_block.begin(), sig_block.end());

  const Transaction ack = TransactionBuilder()
                              .type(Core::TxType::BridgeAckWithdrawal)
                              .from(alice_)
                              .to(Crypto::Address{})
                              .amount(0)
                              .fee(1)
                              .nonce(1)
                              .tokenId(NATIVE_TOKEN_ID)
                              .chainId(genesis_config_.chain_id)
                              .payload(payload)
                              .build();

  const BlockResult r = applyBlock(2, currentStateRoot(), {ack});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  Governance — pause / unpause
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgePause_RoundTrip)
{
  const std::vector<uint8_t> msg = leU64(/*bound_height=*/1);
  const Crypto::Hash signing_hash = signGovernanceMessage("bpau", msg);

  const std::vector<uint8_t> sig_block = makeSignatureBlock(
      {{0, seed1_}, {1, seed2_}}, signing_hash);

  std::vector<uint8_t> payload;
  payload.insert(payload.end(), msg.begin(), msg.end());
  payload.insert(payload.end(), sig_block.begin(), sig_block.end());

  const Transaction pause = TransactionBuilder()
                                .type(Core::TxType::BridgePause)
                                .from(alice_)
                                .to(Crypto::Address{})
                                .amount(0)
                                .fee(1)
                                .nonce(0)
                                .tokenId(NATIVE_TOKEN_ID)
                                .chainId(genesis_config_.chain_id)
                                .payload(payload)
                                .build();

  const BlockResult r = applyBlock(1, genesis_hash_, {pause});
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_TRUE(makeGlobalReader().bridgePaused());

  const std::vector<uint8_t> unpause_msg = leU64(/*bound_height=*/2);
  const Crypto::Hash unpause_hash =
      signGovernanceMessage("bunp", unpause_msg);

  const std::vector<uint8_t> unpause_sigs = makeSignatureBlock(
      {{0, seed1_}, {1, seed2_}}, unpause_hash);

  std::vector<uint8_t> unpause_payload;
  unpause_payload.insert(unpause_payload.end(),
                         unpause_msg.begin(), unpause_msg.end());
  unpause_payload.insert(unpause_payload.end(),
                         unpause_sigs.begin(), unpause_sigs.end());

  const Transaction unpause = TransactionBuilder()
                                  .type(Core::TxType::BridgeUnpause)
                                  .from(alice_)
                                  .to(Crypto::Address{})
                                  .amount(0)
                                  .fee(1)
                                  .nonce(1)
                                  .tokenId(NATIVE_TOKEN_ID)
                                  .chainId(genesis_config_.chain_id)
                                  .payload(unpause_payload)
                                  .build();

  const BlockResult r2 = applyBlock(2, currentStateRoot(), {unpause});
  ASSERT_TRUE(r2.valid) << r2.error;
  EXPECT_FALSE(makeGlobalReader().bridgePaused());
}

TEST_F(Core_BlockProcessorFixture, BridgePause_RejectsBelowGovernanceThreshold)
{
  const std::vector<uint8_t> msg = leU64(1);
  const Crypto::Hash signing_hash = signGovernanceMessage("bpau", msg);

  const std::vector<uint8_t> sig_block = makeSignatureBlock(
      {{0, seed1_}}, signing_hash);

  std::vector<uint8_t> payload;
  payload.insert(payload.end(), msg.begin(), msg.end());
  payload.insert(payload.end(), sig_block.begin(), sig_block.end());

  const Transaction pause = TransactionBuilder()
                                .type(Core::TxType::BridgePause)
                                .from(alice_)
                                .to(Crypto::Address{})
                                .amount(0)
                                .fee(1)
                                .nonce(0)
                                .tokenId(NATIVE_TOKEN_ID)
                                .chainId(genesis_config_.chain_id)
                                .payload(payload)
                                .build();

  const BlockResult r = applyBlock(1, genesis_hash_, {pause});
  EXPECT_FALSE(r.valid);
}

// ============================================================================
//  Dry-run / apply invariant
// ============================================================================

TEST_F(Core_BlockProcessorFixture, BridgeMint_SimulateAndApplyProduceSameRoot)
{
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Hash source_tx_hash = hashWithFirstByte(0x77);

  const std::vector<uint8_t> sigs = signBridgeMintMessage(
      CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0, alice_addr, 500,
      {{0, seed1_}, {1, seed2_}});

  const Transaction tx = makeBridgeMintTx(
      alice_, CcxBridge::CCX_CHAIN_ID, source_tx_hash, 0,
      alice_addr, 500, sigs, 0);

  const Core::Block block =
      makeProcessableBlock(1, genesis_hash_, {tx}, activeSet());

  Crypto::Hash dry_root;
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    BlockContext ctx = makeContext(1, /*dry_run=*/true);
    const BlockResult r = BlockProcessor::applyBlock(s, block, ctx);
    ASSERT_TRUE(r.valid) << "dry-run failed: " << r.error;
    dry_root = r.new_state_root;
    t.abort();
  }

  Crypto::Hash apply_root;
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    BlockContext ctx = makeContext(1, /*dry_run=*/false);
    const BlockResult r = BlockProcessor::applyBlock(s, block, ctx);
    ASSERT_TRUE(r.valid) << "apply failed: " << r.error;
    apply_root = r.new_state_root;
    s.commit(1);
    t.commit();
  }

  EXPECT_EQ(dry_root, apply_root);
}

TEST_F(Core_BlockProcessorFixture, BridgeBurn_SimulateAndApplyProduceSameRoot)
{
  const Id wrapped = wrappedCcxTokenId();
  const Crypto::Address alice_addr = addressOf(alice_);
  const Crypto::Address bob_addr = addressOf(bob_);

  fundWrappedCcx(alice_addr, 5'000);

  const std::vector<uint8_t> blob = CcxBridge::encodeDestination(
      bob_addr, pubkeyWithFirstByte(0x08));
  const Transaction tx = makeBridgeBurnTx(
      alice_, CcxBridge::CCX_CHAIN_ID, blob, 2'000, wrapped, 0);

  const Core::Block block =
      makeProcessableBlock(1, genesis_hash_, {tx}, activeSet());

  Crypto::Hash dry_root;
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    BlockContext ctx = makeContext(1, /*dry_run=*/true);
    const BlockResult r = BlockProcessor::applyBlock(s, block, ctx);
    ASSERT_TRUE(r.valid) << "dry-run failed: " << r.error;
    dry_root = r.new_state_root;
    t.abort();
  }

  Crypto::Hash apply_root;
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    BlockContext ctx = makeContext(1, /*dry_run=*/false);
    const BlockResult r = BlockProcessor::applyBlock(s, block, ctx);
    ASSERT_TRUE(r.valid) << "apply failed: " << r.error;
    apply_root = r.new_state_root;
    s.commit(1);
    t.commit();
  }

  EXPECT_EQ(dry_root, apply_root);
}

// ============================================================================
//  CCX adapter codec round-trip
// ============================================================================

TEST(Core_CcxBridge, DestinationRoundTrip)
{
  const Crypto::PublicKey spend = pubkeyWithFirstByte(0xAA);
  const Crypto::PublicKey view = pubkeyWithFirstByte(0xBB);

  const std::vector<uint8_t> blob =
      CcxBridge::encodeDestination(spend, view);

  ASSERT_EQ(blob.size(), CcxBridge::CCX_DESTINATION_BYTES);

  Crypto::PublicKey spend_out, view_out;
  ASSERT_TRUE(CcxBridge::decodeDestination(blob, spend_out, view_out));
  EXPECT_EQ(spend_out, spend);
  EXPECT_EQ(view_out, view);
}

TEST(Core_CcxBridge, DestinationRejectsNullKey)
{
  const Crypto::PublicKey zero;
  const Crypto::PublicKey real = pubkeyWithFirstByte(0xAA);

  EXPECT_TRUE(CcxBridge::encodeDestination(zero, real).empty());
  EXPECT_TRUE(CcxBridge::encodeDestination(real, zero).empty());
  EXPECT_TRUE(CcxBridge::encodeDestination(zero, zero).empty());
}

TEST(Core_CcxBridge, DestinationDecodeRejectsWrongLength)
{
  Crypto::PublicKey s, v;
  EXPECT_FALSE(CcxBridge::decodeDestination({}, s, v));
  EXPECT_FALSE(
      CcxBridge::decodeDestination(std::vector<uint8_t>(32), s, v));
  EXPECT_FALSE(
      CcxBridge::decodeDestination(std::vector<uint8_t>(128), s, v));
}

TEST(Core_CcxBridge, FingerprintIsDeterministic)
{
  EXPECT_EQ(CcxBridge::wrappedTokenFingerprint(),
            CcxBridge::wrappedTokenFingerprint());
}

TEST(Core_CcxBridge, FingerprintIsNotNull)
{
  EXPECT_FALSE(CcxBridge::wrappedTokenFingerprint().isNull());
}

TEST(Core_CcxBridge, FingerprintDependsOnChainId)
{
  const auto fp_ccx = CcxBridge::wrappedTokenFingerprint();
  const auto fp_different =
      Crypto::hashDomain("ccw", /*dummy payload*/ nullptr, 0);
  EXPECT_NE(fp_ccx, fp_different);
}