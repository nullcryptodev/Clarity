// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"

#include "Core/NftTypes.h"
#include "Core/TokenTypes.h"

#include "State/StateAccess.h"
#include "State/SparseMerkleTree.h"

using namespace Core;
using namespace State;
using namespace Tests;

namespace
{
  // ===================================================================
  //  Codec sample builders
  // ===================================================================

  NftInfo makeStandaloneNft()
  {
    NftInfo n;
    n.id = 42;
    n.owner = Crypto::addrFromHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    n.creator = n.owner;
    n.shadow_token_id = 42;
    n.underlying_token_id = 0;
    n.wrapped_amount = 0;
    n.collection_id = 0;
    n.metadata_hash = Crypto::Hash{};
    n.metadata_uri = "ipfs://QmTest";
    n.frozen = false;
    n.last_accrual_height = 100;
    n.accrued_owed = 0;
    n.created_at_height = 100;
    return n;
  }

  NftInfo makeWrappedNft()
  {
    NftInfo n = makeStandaloneNft();
    n.id = 43;
    n.shadow_token_id = 43;
    n.underlying_token_id = 7;
    n.wrapped_amount = 5000;
    n.collection_id = 3;

    Crypto::Hash h;
    for (size_t i = 0; i < 32; ++i)
      h.data[i] = static_cast<uint8_t>(0x80 + i);
    n.metadata_hash = h;
    n.metadata_uri = "";
    n.frozen = true;
    return n;
  }

  NftCollection makeCollection()
  {
    NftCollection c;
    c.id = 1;
    c.creator = Crypto::addrFromHex(
        "2222222222222222222222222222222222222222222222222222222222222222");
    c.name = "Test Collection";
    c.symbol = "TCOL";
    c.base_uri = "ipfs://QmBase/";
    c.reward_token_id = 5;
    c.reward_rate_per_epoch = 10;
    c.reward_escrow_remaining = 1000;
    c.reward_paused = false;
    c.created_at_height = 50;
    c.minted_count = 3;
    return c;
  }

  // ===================================================================
  //  Executor payload encoders
  //
  //  These match the layouts in TransactionExecutor.cpp exactly.
  //  Kept local to the test file because the executor's parsers are
  //  the authority, and a test that builds a malformed payload on
  //  purpose needs to do so without going through a well-formed
  //  builder.
  // ===================================================================

  uint64_t readGlobalU64(State::StateAccess &state, const char *name)
  {
    std::vector<uint8_t> bytes;
    if (!state.getGlobal(name, bytes) || bytes.size() != 8)
      return 0;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v |= uint64_t(bytes[i]) << (i * 8);
    return v;
  }

  void appendU32(std::vector<uint8_t> &p, uint32_t v)
  {
    for (int i = 0; i < 4; ++i)
      p.push_back(uint8_t(v >> (i * 8)));
  }

  void appendU64(std::vector<uint8_t> &p, uint64_t v)
  {
    for (int i = 0; i < 8; ++i)
      p.push_back(uint8_t(v >> (i * 8)));
  }

  std::vector<uint8_t> encodeCreateCollectionPayload(
      const std::string &name,
      const std::string &symbol,
      const std::string &base_uri,
      Id reward_token_id,
      uint64_t reward_rate_per_epoch,
      uint64_t escrow_amount)
  {
    std::vector<uint8_t> p;
    p.push_back(static_cast<uint8_t>(name.size()));
    p.insert(p.end(), name.begin(), name.end());
    p.push_back(static_cast<uint8_t>(symbol.size()));
    p.insert(p.end(), symbol.begin(), symbol.end());
    p.push_back(static_cast<uint8_t>(base_uri.size() & 0xFF));
    p.push_back(static_cast<uint8_t>((base_uri.size() >> 8) & 0xFF));
    p.insert(p.end(), base_uri.begin(), base_uri.end());
    appendU32(p, reward_token_id);
    appendU64(p, reward_rate_per_epoch);
    appendU64(p, escrow_amount);
    return p;
  }

  std::vector<uint8_t> encodeMintNftPayload(
      uint64_t collection_id,
      const Crypto::Hash &metadata_hash,
      bool has_hash,
      const std::string &metadata_uri)
  {
    std::vector<uint8_t> p;
    appendU64(p, collection_id);
    p.insert(p.end(), metadata_hash.data.begin(), metadata_hash.data.end());
    p.push_back(has_hash ? 1 : 0);
    p.push_back(static_cast<uint8_t>(metadata_uri.size() & 0xFF));
    p.push_back(static_cast<uint8_t>((metadata_uri.size() >> 8) & 0xFF));
    p.insert(p.end(), metadata_uri.begin(), metadata_uri.end());
    return p;
  }

  std::vector<uint8_t> encodeWrapNftPayload(
      Id underlying_token_id,
      uint64_t wrapped_amount,
      uint64_t collection_id,
      const Crypto::Hash &metadata_hash,
      bool has_hash,
      const std::string &metadata_uri)
  {
    std::vector<uint8_t> p;
    appendU32(p, underlying_token_id);
    appendU64(p, wrapped_amount);
    appendU64(p, collection_id);
    p.insert(p.end(), metadata_hash.data.begin(), metadata_hash.data.end());
    p.push_back(has_hash ? 1 : 0);
    p.push_back(static_cast<uint8_t>(metadata_uri.size() & 0xFF));
    p.push_back(static_cast<uint8_t>((metadata_uri.size() >> 8) & 0xFF));
    p.insert(p.end(), metadata_uri.begin(), metadata_uri.end());
    return p;
  }

  std::vector<uint8_t> encodeTransferNftPayload(
      uint64_t nft_id, const Crypto::Address &new_owner)
  {
    std::vector<uint8_t> p;
    appendU64(p, nft_id);
    p.insert(p.end(), new_owner.data.begin(), new_owner.data.end());
    return p;
  }

  std::vector<uint8_t> encodeNftIdPayload(uint64_t nft_id)
  {
    std::vector<uint8_t> p;
    appendU64(p, nft_id);
    return p;
  }

  std::vector<uint8_t> encodeTopUpNftPayload(
      uint64_t nft_id, Id token_id, uint64_t amount)
  {
    std::vector<uint8_t> p;
    appendU64(p, nft_id);
    appendU32(p, token_id);
    appendU64(p, amount);
    return p;
  }

  std::vector<uint8_t> encodeUpdateMetadataPayload(
      uint64_t nft_id,
      const Crypto::Hash &metadata_hash,
      bool has_hash,
      const std::string &metadata_uri,
      bool freeze)
  {
    std::vector<uint8_t> p;
    appendU64(p, nft_id);
    p.insert(p.end(), metadata_hash.data.begin(), metadata_hash.data.end());
    p.push_back(has_hash ? 1 : 0);
    p.push_back(static_cast<uint8_t>(metadata_uri.size() & 0xFF));
    p.push_back(static_cast<uint8_t>((metadata_uri.size() >> 8) & 0xFF));
    p.insert(p.end(), metadata_uri.begin(), metadata_uri.end());
    p.push_back(freeze ? 1 : 0);
    return p;
  }

  std::vector<uint8_t> encodeRefillPayload(uint64_t collection_id,
                                           uint64_t amount)
  {
    std::vector<uint8_t> p;
    appendU64(p, collection_id);
    appendU64(p, amount);
    return p;
  }
}

// =====================================================================
//  NftInfo codec
// =====================================================================

TEST(Core_NftInfo, DefaultIsInvalid)
{
  NftInfo n;
  EXPECT_EQ(n.id, INVALID_ID);
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, StandaloneIsValid)
{
  NftInfo n = makeStandaloneNft();
  EXPECT_TRUE(n.isValid());
  EXPECT_TRUE(n.isStandalone());
  EXPECT_FALSE(n.isWrapped());
}

TEST(Core_NftInfo, WrappedIsValid)
{
  NftInfo n = makeWrappedNft();
  EXPECT_TRUE(n.isValid());
  EXPECT_TRUE(n.isWrapped());
  EXPECT_FALSE(n.isStandalone());
}

TEST(Core_NftInfo, RejectsStandaloneWithAmount)
{
  NftInfo n = makeStandaloneNft();
  n.wrapped_amount = 1;
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, RejectsWrappedWithZeroAmount)
{
  NftInfo n = makeWrappedNft();
  n.wrapped_amount = 0;
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, RejectsSelfWrapping)
{
  NftInfo n = makeWrappedNft();
  n.underlying_token_id = n.shadow_token_id;
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, RejectsNullOwner)
{
  NftInfo n = makeStandaloneNft();
  n.owner = Crypto::Address{};
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, RejectsNullCreator)
{
  NftInfo n = makeStandaloneNft();
  n.creator = Crypto::Address{};
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, RejectsZeroShadowTokenId)
{
  NftInfo n = makeStandaloneNft();
  n.shadow_token_id = 0;
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, RejectsOverlongUri)
{
  NftInfo n = makeStandaloneNft();
  n.metadata_uri.assign(NFT_URI_MAX + 1, 'x');
  EXPECT_FALSE(n.isValid());
}

TEST(Core_NftInfo, AcceptsUriAtCap)
{
  NftInfo n = makeStandaloneNft();
  n.metadata_uri.assign(NFT_URI_MAX, 'x');
  EXPECT_TRUE(n.isValid());
}

TEST(Core_NftInfo, StateRoundTripStandalone)
{
  NftInfo original = makeStandaloneNft();
  auto bytes = original.serializeState();

  NftInfo restored;
  ASSERT_TRUE(NftInfo::deserializeState(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.id, original.id);
  EXPECT_EQ(restored.owner.toString(), original.owner.toString());
  EXPECT_EQ(restored.creator.toString(), original.creator.toString());
  EXPECT_EQ(restored.shadow_token_id, original.shadow_token_id);
  EXPECT_EQ(restored.underlying_token_id, original.underlying_token_id);
  EXPECT_EQ(restored.wrapped_amount, original.wrapped_amount);
  EXPECT_EQ(restored.collection_id, original.collection_id);
  EXPECT_TRUE(restored.metadata_hash.isNull());
  EXPECT_EQ(restored.metadata_uri, original.metadata_uri);
  EXPECT_FALSE(restored.frozen);
  EXPECT_EQ(restored.last_accrual_height, original.last_accrual_height);
  EXPECT_EQ(restored.accrued_owed, original.accrued_owed);
  EXPECT_EQ(restored.created_at_height, original.created_at_height);
}

TEST(Core_NftInfo, StateRoundTripWrapped)
{
  NftInfo original = makeWrappedNft();
  auto bytes = original.serializeState();

  NftInfo restored;
  ASSERT_TRUE(NftInfo::deserializeState(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.id, original.id);
  EXPECT_EQ(restored.underlying_token_id, original.underlying_token_id);
  EXPECT_EQ(restored.wrapped_amount, original.wrapped_amount);
  EXPECT_EQ(restored.collection_id, original.collection_id);
  ASSERT_FALSE(restored.metadata_hash.isNull());
  EXPECT_EQ(restored.metadata_hash.toString(),
            original.metadata_hash.toString());
  EXPECT_TRUE(restored.metadata_uri.empty());
  EXPECT_TRUE(restored.frozen);
}

TEST(Core_NftInfo, StateDeterministic)
{
  NftInfo n = makeStandaloneNft();
  EXPECT_EQ(n.serializeState(), n.serializeState());

  NftInfo w = makeWrappedNft();
  EXPECT_EQ(w.serializeState(), w.serializeState());
}

TEST(Core_NftInfo, DeserializeRejectsTruncated)
{
  NftInfo n = makeStandaloneNft();
  auto bytes = n.serializeState();

  NftInfo restored;
  EXPECT_FALSE(NftInfo::deserializeState(
      bytes.data(), bytes.size() / 2, restored));
}

TEST(Core_NftInfo, DeserializeRejectsTrailingBytes)
{
  NftInfo n = makeStandaloneNft();
  auto bytes = n.serializeState();
  bytes.push_back(0xFF);

  NftInfo restored;
  EXPECT_FALSE(NftInfo::deserializeState(
      bytes.data(), bytes.size(), restored));
}

// =====================================================================
//  NftCollection codec
// =====================================================================

TEST(Core_NftCollection, DefaultIsInvalid)
{
  NftCollection c;
  EXPECT_EQ(c.id, INVALID_ID);
  EXPECT_FALSE(c.isValid());
}

TEST(Core_NftCollection, ValidCollection)
{
  NftCollection c = makeCollection();
  EXPECT_TRUE(c.isValid());
  EXPECT_TRUE(c.hasReward());
  EXPECT_TRUE(c.isActive());
}

TEST(Core_NftCollection, NoRewardIsValid)
{
  NftCollection c = makeCollection();
  c.reward_token_id = 0;
  c.reward_rate_per_epoch = 0;
  c.reward_escrow_remaining = 0;
  EXPECT_TRUE(c.isValid());
  EXPECT_FALSE(c.hasReward());
  EXPECT_FALSE(c.isActive());
}

TEST(Core_NftCollection, RejectsRewardTokenWithoutRate)
{
  NftCollection c = makeCollection();
  c.reward_token_id = 5;
  c.reward_rate_per_epoch = 0;
  EXPECT_FALSE(c.isValid());
}

TEST(Core_NftCollection, RejectsRateWithoutRewardToken)
{
  NftCollection c = makeCollection();
  c.reward_token_id = 0;
  c.reward_rate_per_epoch = 10;
  EXPECT_FALSE(c.isValid());
}

TEST(Core_NftCollection, RejectsEscrowWithoutRewardToken)
{
  NftCollection c = makeCollection();
  c.reward_token_id = 0;
  c.reward_rate_per_epoch = 0;
  c.reward_escrow_remaining = 1000;
  EXPECT_FALSE(c.isValid());
}

TEST(Core_NftCollection, PausedIsNotActive)
{
  NftCollection c = makeCollection();
  c.reward_paused = true;
  EXPECT_TRUE(c.isValid());
  EXPECT_TRUE(c.hasReward());
  EXPECT_FALSE(c.isActive());
}

TEST(Core_NftCollection, StateRoundTrip)
{
  NftCollection original = makeCollection();
  auto bytes = original.serializeState();

  NftCollection restored;
  ASSERT_TRUE(NftCollection::deserializeState(
      bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.id, original.id);
  EXPECT_EQ(restored.creator.toString(), original.creator.toString());
  EXPECT_EQ(restored.name, original.name);
  EXPECT_EQ(restored.symbol, original.symbol);
  EXPECT_EQ(restored.base_uri, original.base_uri);
  EXPECT_EQ(restored.reward_token_id, original.reward_token_id);
  EXPECT_EQ(restored.reward_rate_per_epoch,
            original.reward_rate_per_epoch);
  EXPECT_EQ(restored.reward_escrow_remaining,
            original.reward_escrow_remaining);
  EXPECT_EQ(restored.reward_paused, original.reward_paused);
  EXPECT_EQ(restored.created_at_height, original.created_at_height);
  EXPECT_EQ(restored.minted_count, original.minted_count);
}

TEST(Core_NftCollection, StateDeterministic)
{
  NftCollection c = makeCollection();
  EXPECT_EQ(c.serializeState(), c.serializeState());
}

TEST(Core_NftCollection, DeserializeRejectsTruncated)
{
  NftCollection c = makeCollection();
  auto bytes = c.serializeState();

  NftCollection restored;
  EXPECT_FALSE(NftCollection::deserializeState(
      bytes.data(), bytes.size() / 2, restored));
}

// =====================================================================
//  Executor: CreateNftCollection
// =====================================================================

TEST_F(Core_ExecutorFixture, CreateCollection_NoReward)
{
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::CreateNftCollection)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeCreateCollectionPayload(
                                 "My Collection", "MCOL", "ipfs://base/", 0, 0, 0))
                             .build();

  Core::Receipt r = run(tx);
  ASSERT_EQ(r.status, Core::ReceiptStatus::Success);

  //  Fresh state: next_collection_id defaults to 1 on first use.
  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.creator.toString(), alice_.publicKey.toString());
  EXPECT_EQ(c.name, "My Collection");
  EXPECT_EQ(c.symbol, "MCOL");
  EXPECT_EQ(c.base_uri, "ipfs://base/");
  EXPECT_EQ(c.reward_token_id, 0);
  EXPECT_FALSE(c.hasReward());
  EXPECT_EQ(c.minted_count, 0);
  EXPECT_EQ(c.created_at_height, 100);

  EXPECT_EQ(readGlobalU64(*state_, "next_collection_id"), 2);
}

TEST_F(Core_ExecutorFixture, CreateCollection_RewardEscrowFunded)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 5000);

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::CreateNftCollection)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeCreateCollectionPayload(
                                 "Rewards", "REW", "", reward_token, /*rate=*/10, /*escrow=*/1000))
                             .build();

  Core::Receipt r = run(tx);
  ASSERT_EQ(r.status, Core::ReceiptStatus::Success);

  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.reward_token_id, reward_token);
  EXPECT_EQ(c.reward_rate_per_epoch, 10);
  EXPECT_EQ(c.reward_escrow_remaining, 1000);
  EXPECT_FALSE(c.reward_paused);

  //  Alice's reward-token balance dropped by the escrow.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, reward_token), 4000);

  //  The escrow address holds the escrow.
  const Crypto::Address escrow = State::Keys::nftCollectionAddress(1);
  EXPECT_EQ(state_->getTokenBalance(escrow, reward_token), 1000);
}

TEST_F(Core_ExecutorFixture, CreateCollection_EscrowWithoutRateRejected)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 5000);

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::CreateNftCollection)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeCreateCollectionPayload(
                                 "Bad", "BAD", "", reward_token, /*rate=*/0, /*escrow=*/1000))
                             .build();

  Core::Receipt r = run(tx);
  EXPECT_EQ(r.status, Core::ReceiptStatus::Failure);

  Core::NftCollection c;
  EXPECT_FALSE(state_->getNftCollection(1, c));
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, reward_token), 5000);
}

TEST_F(Core_ExecutorFixture, CreateCollection_InsufficientEscrowRejected)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 500);

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::CreateNftCollection)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeCreateCollectionPayload(
                                 "Rewards", "REW", "", reward_token, /*rate=*/10, /*escrow=*/1000))
                             .build();

  Core::Receipt r = run(tx);
  EXPECT_EQ(r.status, Core::ReceiptStatus::Failure);

  Core::NftCollection c;
  EXPECT_FALSE(state_->getNftCollection(1, c));
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, reward_token), 500);
}

TEST_F(Core_ExecutorFixture, CreateCollection_SecondCollectionGetsId2)
{
  auto make_create = [&](const std::string &name, const std::string &sym,
                         uint64_t nonce)
  {
    return TransactionBuilder()
        .type(Core::TxType::CreateNftCollection)
        .from(alice_)
        .to(Crypto::Address{})
        .amount(0)
        .fee(1)
        .nonce(nonce)
        .chainId(EXEC_CHAIN_ID)
        .payload(encodeCreateCollectionPayload(name, sym, "", 0, 0, 0))
        .build();
  };

  ASSERT_EQ(run(make_create("First", "FST", 0)).status,
            Core::ReceiptStatus::Success);
  ASSERT_EQ(run(make_create("Second", "SND", 1)).status,
            Core::ReceiptStatus::Success);

  Core::NftCollection a, b;
  ASSERT_TRUE(state_->getNftCollection(1, a));
  ASSERT_TRUE(state_->getNftCollection(2, b));
  EXPECT_EQ(a.name, "First");
  EXPECT_EQ(b.name, "Second");
  EXPECT_EQ(readGlobalU64(*state_, "next_collection_id"), 3);
}

// =====================================================================
//  Executor: MintNft
// =====================================================================

TEST_F(Core_ExecutorFixture, MintNft_StandaloneNoCollection)
{
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::MintNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeMintNftPayload(
                                 0, Crypto::Hash{}, false, "ipfs://QmTest"))
                             .build();

  Core::Receipt r = run(tx);
  ASSERT_EQ(r.status, Core::ReceiptStatus::Success);

  //  First mint gets id 1 from the shared token counter.
  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.owner.toString(), alice_.publicKey.toString());
  EXPECT_EQ(n.creator.toString(), alice_.publicKey.toString());
  EXPECT_EQ(n.shadow_token_id, 1);
  EXPECT_EQ(n.underlying_token_id, 0);
  EXPECT_EQ(n.wrapped_amount, 0);
  EXPECT_EQ(n.collection_id, 0);
  EXPECT_TRUE(n.isStandalone());
  EXPECT_EQ(n.metadata_uri, "ipfs://QmTest");
  EXPECT_EQ(n.created_at_height, 100);
  EXPECT_EQ(n.last_accrual_height, 100);

  //  Shadow token exists with the right shape.
  Core::TokenInfo shadow;
  ASSERT_TRUE(state_->getToken(1, shadow));
  EXPECT_EQ(shadow.decimals, 0);
  EXPECT_EQ(shadow.maxSupply, 1);
  EXPECT_EQ(shadow.creator.toString(), alice_.publicKey.toString());

  //  Alice holds one unit of the shadow token.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, 1), 1);
  EXPECT_EQ(state_->getTokenSupply(1), 1);

  //  Shared counter bumped.
  EXPECT_EQ(readGlobalU64(*state_, "next_token_id"), 2);
}

TEST_F(Core_ExecutorFixture, MintNft_WithCollection)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Punks", "PNK", "", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.collection_id, 1);

  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.minted_count, 1);

  //  Shadow token inherits name and symbol from the collection.
  Core::TokenInfo shadow;
  ASSERT_TRUE(state_->getToken(1, shadow));
  EXPECT_EQ(shadow.symbol, "PNK");
  EXPECT_EQ(shadow.name, "Punks #1");
}

TEST_F(Core_ExecutorFixture, MintNft_IncrementsCollectionMintedCount)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Punks", "PNK", "", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  for (uint64_t i = 0; i < 3; ++i)
  {
    ASSERT_EQ(run(TransactionBuilder()
                      .type(Core::TxType::MintNft)
                      .from(alice_)
                      .to(Crypto::Address{})
                      .amount(0)
                      .fee(1)
                      .nonce(1 + i)
                      .chainId(EXEC_CHAIN_ID)
                      .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, ""))
                      .build())
                  .status,
              Core::ReceiptStatus::Success);
  }

  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.minted_count, 3);
}

TEST_F(Core_ExecutorFixture, MintNft_UnknownCollectionRejected)
{
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::MintNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeMintNftPayload(999, Crypto::Hash{}, false, ""))
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, MintNft_OverlongUriRejected)
{
  std::string uri(NFT_URI_MAX + 1, 'x');
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::MintNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, uri))
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, MintNft_HashFlagMismatchRejected)
{
  //  has_hash = 0 but the hash bytes are non-zero.
  Crypto::Hash h;
  for (size_t i = 0; i < 32; ++i)
    h.data[i] = 0xAB;

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::MintNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeMintNftPayload(0, h, /*has_hash=*/false, ""))
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: WrapNft
// =====================================================================

TEST_F(Core_ExecutorFixture, WrapNft_CustodyAtVirtualAddress)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 10000);

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::WrapNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeWrapNftPayload(
                                 underlying, /*amount=*/5000, /*collection=*/0,
                                 Crypto::Hash{}, false, ""))
                             .build();

  Core::Receipt r = run(tx);
  ASSERT_EQ(r.status, Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.underlying_token_id, underlying);
  EXPECT_EQ(n.wrapped_amount, 5000);
  EXPECT_TRUE(n.isWrapped());

  //  Alice's balance dropped by the wrapped amount.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, underlying), 5000);

  //  The custody address holds the wrapped amount.
  const Crypto::Address custody = State::Keys::nftAddress(1);
  EXPECT_EQ(state_->getTokenBalance(custody, underlying), 5000);

  //  The shadow token exists and alice holds it.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, 1), 1);
}

TEST_F(Core_ExecutorFixture, WrapNft_InsufficientUnderlyingRejected)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 100);

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::WrapNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeWrapNftPayload(
                                 underlying, /*amount=*/5000, /*collection=*/0,
                                 Crypto::Hash{}, false, ""))
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);

  Core::NftInfo n;
  EXPECT_FALSE(state_->getNft(1, n));
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, underlying), 100);
}

TEST_F(Core_ExecutorFixture, WrapNft_ZeroAmountRejected)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 10000);

  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::WrapNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeWrapNftPayload(
                                 underlying, /*amount=*/0, /*collection=*/0,
                                 Crypto::Hash{}, false, ""))
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, WrapNft_ZeroUnderlyingRejected)
{
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::WrapNft)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload(encodeWrapNftPayload(
                                 0, /*amount=*/5000, /*collection=*/0,
                                 Crypto::Hash{}, false, ""))
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: TransferNft
// =====================================================================

TEST_F(Core_ExecutorFixture, TransferNft_StandaloneMovesOwnerAndShadow)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, bob_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.owner.toString(), bob_.publicKey.toString());

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, 1), 0);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, 1), 1);
}

TEST_F(Core_ExecutorFixture, TransferNft_WrappedKeepsCustodyInPlace)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 10000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::WrapNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeWrapNftPayload(
                        underlying, 5000, 0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, bob_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.owner.toString(), bob_.publicKey.toString());
  EXPECT_EQ(n.wrapped_amount, 5000);
  EXPECT_EQ(n.underlying_token_id, underlying);

  //  Custody stays at the NFT's virtual address.
  const Crypto::Address custody = State::Keys::nftAddress(1);
  EXPECT_EQ(state_->getTokenBalance(custody, underlying), 5000);
}

TEST_F(Core_ExecutorFixture, TransferNft_NonOwnerRejected)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Bob does not own NFT 1.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, carol_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.owner.toString(), alice_.publicKey.toString());
}

TEST_F(Core_ExecutorFixture, TransferNft_SelfTransferRejected)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, alice_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, TransferNft_UnknownNftRejected)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(9999, bob_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: BurnNft
// =====================================================================

TEST_F(Core_ExecutorFixture, BurnNft_StandaloneDeletesRecord)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(1))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  EXPECT_FALSE(state_->getNft(1, n));
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, 1), 0);
  EXPECT_EQ(state_->getTokenSupply(1), 0);
}

TEST_F(Core_ExecutorFixture, BurnNft_WrappedReleasesCustodyToOwner)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 10000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::WrapNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeWrapNftPayload(
                        underlying, 5000, 0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, underlying), 5000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(1))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Custody returned to the owner.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, underlying), 10000);

  //  Custody address is empty.
  const Crypto::Address custody = State::Keys::nftAddress(1);
  EXPECT_EQ(state_->getTokenBalance(custody, underlying), 0);

  Core::NftInfo n;
  EXPECT_FALSE(state_->getNft(1, n));
}

TEST_F(Core_ExecutorFixture, BurnNft_DecrementsCollectionMintedCount)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Punks", "PNK", "", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftCollection before;
  ASSERT_TRUE(state_->getNftCollection(1, before));
  EXPECT_EQ(before.minted_count, 1);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(1))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftCollection after;
  ASSERT_TRUE(state_->getNftCollection(1, after));
  EXPECT_EQ(after.minted_count, 0);
}

TEST_F(Core_ExecutorFixture, BurnNft_NonOwnerRejected)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(1))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  Core::NftInfo n;
  EXPECT_TRUE(state_->getNft(1, n));
}

// =====================================================================
//  Executor: UpdateNftMetadata
// =====================================================================

TEST_F(Core_ExecutorFixture, UpdateMetadata_OwnerCanUpdate)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(
                        0, Crypto::Hash{}, false, "old-uri"))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateNftMetadata)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateMetadataPayload(
                        1, Crypto::Hash{}, false, "new-uri", false))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.metadata_uri, "new-uri");
  EXPECT_FALSE(n.frozen);
}

TEST_F(Core_ExecutorFixture, UpdateMetadata_FreezeIsOneWay)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(
                        0, Crypto::Hash{}, false, "uri1"))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Freeze.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateNftMetadata)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateMetadataPayload(
                        1, Crypto::Hash{}, false, "uri2", /*freeze=*/true))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_TRUE(n.frozen);
  EXPECT_EQ(n.metadata_uri, "uri2");

  //  Second update rejected because the NFT is frozen.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateNftMetadata)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateMetadataPayload(
                        1, Crypto::Hash{}, false, "uri3", false))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.metadata_uri, "uri2");
}

TEST_F(Core_ExecutorFixture, UpdateMetadata_NonOwnerRejected)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(
                        0, Crypto::Hash{}, false, "uri1"))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateNftMetadata)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateMetadataPayload(
                        1, Crypto::Hash{}, false, "hacked", false))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.metadata_uri, "uri1");
}

// =====================================================================
//  Executor: TopUpNft
// =====================================================================

TEST_F(Core_ExecutorFixture, TopUpNft_WrappedUpdatesAmountAndCustody)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 10000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::WrapNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeWrapNftPayload(
                        underlying, 1000, 0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Alice tops up the wrapped NFT with 500 more of the underlying.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TopUpNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTopUpNftPayload(1, underlying, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.wrapped_amount, 1500);

  const Crypto::Address custody = State::Keys::nftAddress(1);
  EXPECT_EQ(state_->getTokenBalance(custody, underlying), 1500);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, underlying), 8500);
}

TEST_F(Core_ExecutorFixture, TopUpNft_WrappedRejectsWrongToken)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  const Id other = createTokenDirect(alice_, "Other", "OTH",
                                     /*max_supply=*/0, /*token_id=*/81);
  setTokenBalance(alice_.publicKey, underlying, 10000);
  setTokenBalance(alice_.publicKey, other, 10000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::WrapNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeWrapNftPayload(
                        underlying, 1000, 0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TopUpNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTopUpNftPayload(1, other, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, TopUpNft_StandaloneAcceptsAnyToken)
{
  const Id gift = createTokenDirect(bob_, "Gift", "GFT",
                                    /*max_supply=*/0, /*token_id=*/82);
  setTokenBalance(bob_.publicKey, gift, 500);

  //  Alice mints a standalone NFT.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Bob gifts a token to the NFT's custody address.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TopUpNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTopUpNftPayload(1, gift, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Custody address has the gift.
  const Crypto::Address custody = State::Keys::nftAddress(1);
  EXPECT_EQ(state_->getTokenBalance(custody, gift), 500);

  //  wrapped_amount is unchanged: a standalone NFT's wrapped_amount
  //  stays zero because it has no underlying.
  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.wrapped_amount, 0);
  EXPECT_TRUE(n.isStandalone());
}

// =====================================================================
//  Executor: ClaimNftReward
// =====================================================================

TEST_F(Core_ExecutorFixture, ClaimNftReward_AccruesPerEpoch)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 100000);

  //  Collection with rate 10 per NFT per epoch, escrow 50000.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Rewards", "REW", "",
                        reward_token, /*rate=*/10, /*escrow=*/50000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Mint an NFT into the collection at height 100.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Claim at height 100 + 3 * ROTATION_INTERVAL. The accrual is
  //  (current - last_accrual) / ROTATION_INTERVAL * rate
  //  = (3 * ROTATION_INTERVAL) / ROTATION_INTERVAL * 10 = 30.
  const uint64_t claim_height = 100 + 3 * Core::ROTATION_INTERVAL;

  Core::Receipt claim = run(
      TransactionBuilder()
          .type(Core::TxType::ClaimNftReward)
          .from(alice_)
          .to(Crypto::Address{})
          .amount(0)
          .fee(1)
          .nonce(2)
          .chainId(EXEC_CHAIN_ID)
          .payload({})
          .build(),
      claim_height);

  ASSERT_EQ(claim.status, Core::ReceiptStatus::Success);

  Core::Account acct = state_->getAccount(alice_.publicKey);
  EXPECT_EQ(acct.pending_rewards, 30);

  //  last_accrual_height reset to the claim height.
  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.last_accrual_height, claim_height);
}

TEST_F(Core_ExecutorFixture, ClaimNftReward_NoAccrualNoCredit)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 100000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Rewards", "REW", "", reward_token, 10, 50000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Claim at the same height as the mint: no full epoch has passed.
  Core::Receipt claim = run(
      TransactionBuilder()
          .type(Core::TxType::ClaimNftReward)
          .from(alice_)
          .to(Crypto::Address{})
          .amount(0)
          .fee(1)
          .nonce(2)
          .chainId(EXEC_CHAIN_ID)
          .payload({})
          .build(),
      /*height=*/100);

  ASSERT_EQ(claim.status, Core::ReceiptStatus::Success);

  Core::Account acct = state_->getAccount(alice_.publicKey);
  EXPECT_EQ(acct.pending_rewards, 0);
}

TEST_F(Core_ExecutorFixture, ClaimNftReward_EmptyPayloadRequired)
{
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::ClaimNftReward)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload({0x00})
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: RefillCollectionReward
// =====================================================================

TEST_F(Core_ExecutorFixture, Refill_AddsToEscrowAndUnpauses)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 10000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Rewards", "REW", "", reward_token, 10, 1000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Simulate the collection having drained. A real epoch-boundary
  //  drain moves the escrow tokens out of the escrow address AND
  //  decrements reward_escrow_remaining, keeping the record and the
  //  address consistent. A test that only zeroes the record leaves
  //  the tokens sitting at the escrow address, so the next refill
  //  lands on top of them and the address shows more than the
  //  record claims.
  //
  //  To make the setup consistent with the invariant, move the
  //  escrow tokens back to the creator (in a real drain they would
  //  go to holders; the creator is a convenient sink for the test)
  //  and zero the record.
  {
    const Crypto::Address escrow = State::Keys::nftCollectionAddress(1);
    const uint64_t escrow_bal =
        state_->getTokenBalance(escrow, reward_token);
    state_->putTokenBalance(escrow, reward_token, 0);

    const uint64_t creator_bal =
        state_->getTokenBalance(alice_.publicKey, reward_token);
    state_->putTokenBalance(alice_.publicKey, reward_token,
                            creator_bal + escrow_bal);

    Core::NftCollection c;
    ASSERT_TRUE(state_->getNftCollection(1, c));
    c.reward_escrow_remaining = 0;
    c.reward_paused = true;
    state_->putNftCollection(c);
  }

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::RefillCollectionReward)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeRefillPayload(1, 2000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.reward_escrow_remaining, 2000);
  EXPECT_FALSE(c.reward_paused);

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, reward_token), 8000);
  const Crypto::Address escrow = State::Keys::nftCollectionAddress(1);
  EXPECT_EQ(state_->getTokenBalance(escrow, reward_token), 2000);
}

TEST_F(Core_ExecutorFixture, Refill_NonCreatorRejected)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/50);
  setTokenBalance(alice_.publicKey, reward_token, 10000);
  setTokenBalance(bob_.publicKey, reward_token, 10000);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Rewards", "REW", "", reward_token, 10, 1000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Bob, not the creator, tries to refill.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::RefillCollectionReward)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeRefillPayload(1, 2000))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.reward_escrow_remaining, 1000);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, reward_token), 10000);
}

TEST_F(Core_ExecutorFixture, Refill_NoRewardCollectionRejected)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "NoReward", "NOR", "", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::RefillCollectionReward)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeRefillPayload(1, 2000))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

// =====================================================================
//  State layer: index maintenance through the iterators
// =====================================================================

TEST_F(Core_ExecutorFixture, ForEachNftForOwner_FindsOwnedNfts)
{
  //  Alice mints two, Bob mints one.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  std::vector<uint64_t> alice_ids;
  state_->forEachNftForOwner(
      alice_.publicKey,
      [&](const Core::NftInfo &n)
      { alice_ids.push_back(n.id); });
  ASSERT_EQ(alice_ids.size(), 2u);
  EXPECT_EQ(alice_ids[0], 1u);
  EXPECT_EQ(alice_ids[1], 2u);

  std::vector<uint64_t> bob_ids;
  state_->forEachNftForOwner(
      bob_.publicKey,
      [&](const Core::NftInfo &n)
      { bob_ids.push_back(n.id); });
  ASSERT_EQ(bob_ids.size(), 1u);
  EXPECT_EQ(bob_ids[0], 3u);
}

TEST_F(Core_ExecutorFixture, ForEachNftForOwner_DropsNftAfterTransfer)
{
  //  Alice mints, then transfers to Bob.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, bob_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Alice no longer holds any NFT.
  uint64_t alice_count = 0;
  state_->forEachNftForOwner(
      alice_.publicKey,
      [&](const Core::NftInfo &)
      { ++alice_count; });
  EXPECT_EQ(alice_count, 0u);

  //  Bob holds exactly one.
  uint64_t bob_count = 0;
  state_->forEachNftForOwner(
      bob_.publicKey,
      [&](const Core::NftInfo &)
      { ++bob_count; });
  EXPECT_EQ(bob_count, 1u);
}

TEST_F(Core_ExecutorFixture, ForEachNftForCollection_RespectsMembership)
{
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Punks", "PNK", "", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Apes", "APE", "", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Two in collection 1, one in collection 2, one standalone.
  for (uint64_t i = 0; i < 2; ++i)
  {
    ASSERT_EQ(run(TransactionBuilder()
                      .type(Core::TxType::MintNft)
                      .from(alice_)
                      .to(Crypto::Address{})
                      .amount(0)
                      .fee(1)
                      .nonce(2 + i)
                      .chainId(EXEC_CHAIN_ID)
                      .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, ""))
                      .build())
                  .status,
              Core::ReceiptStatus::Success);
  }
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(4)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(2, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(5)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  uint64_t c1_count = 0;
  state_->forEachNftForCollection(
      1, [&](const Core::NftInfo &n)
      { ++c1_count; EXPECT_EQ(n.collection_id, 1u); });
  EXPECT_EQ(c1_count, 2u);

  uint64_t c2_count = 0;
  state_->forEachNftForCollection(
      2, [&](const Core::NftInfo &n)
      { ++c2_count; EXPECT_EQ(n.collection_id, 2u); });
  EXPECT_EQ(c2_count, 1u);
}

TEST_F(Core_ExecutorFixture, ForEachNft_EnumeratesAll)
{
  for (uint64_t i = 0; i < 5; ++i)
  {
    ASSERT_EQ(run(TransactionBuilder()
                      .type(Core::TxType::MintNft)
                      .from(alice_)
                      .to(Crypto::Address{})
                      .amount(0)
                      .fee(1)
                      .nonce(i)
                      .chainId(EXEC_CHAIN_ID)
                      .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                      .build())
                  .status,
              Core::ReceiptStatus::Success);
  }

  uint64_t count = 0;
  state_->forEachNft([&](const Core::NftInfo &)
                     { ++count; });
  EXPECT_EQ(count, 5u);
}

// =====================================================================
//  Integration: full lifecycle
// =====================================================================

TEST_F(Core_ExecutorFixture, Integration_StandaloneLifecycle)
{
  const Crypto::Address &alice = alice_.publicKey;
  const Crypto::Address &bob = bob_.publicKey;
  const Crypto::Address &carol = carol_.publicKey;

  //  1. Alice creates a collection.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateNftCollection)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateCollectionPayload(
                        "Punks", "PNK", "ipfs://base/", 0, 0, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  2. Alice mints.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(1, Crypto::Hash{}, false, "ipfs://1"))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  3. Alice transfers to Bob.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, bob))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  4. Bob updates metadata and freezes.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateNftMetadata)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateMetadataPayload(
                        1, Crypto::Hash{}, false, "ipfs://frozen", true))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  5. Bob transfers to Carol.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, carol))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  6. Carol cannot update (frozen).
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateNftMetadata)
                    .from(carol_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateMetadataPayload(
                        1, Crypto::Hash{}, false, "hacked", false))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  //  7. Carol burns. Nonce 0, not 1: her update in step 6 failed
  //     (the NFT is frozen), and a failed transaction does not bump
  //     the sender's nonce — the executor charges the fee but
  //     leaves the nonce in place. Carol's only prior transaction
  //     is the failed update, so her nonce is still 0.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(carol_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(1))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Final state: NFT gone, collection minted_count back to 0.
  Core::NftInfo n;
  EXPECT_FALSE(state_->getNft(1, n));
  Core::NftCollection c;
  ASSERT_TRUE(state_->getNftCollection(1, c));
  EXPECT_EQ(c.minted_count, 0);
}

TEST_F(Core_ExecutorFixture, Integration_WrappedLifecycle)
{
  const Id underlying = createTokenDirect(alice_, "Fungible", "FUN",
                                          /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, underlying, 10000);

  //  1. Alice wraps 4000 of the underlying.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::WrapNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeWrapNftPayload(
                        underlying, 4000, 0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  2. Alice tops up 1000.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TopUpNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTopUpNftPayload(1, underlying, 1000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  3. Alice transfers to Bob. Custody stays at the virtual
  //     address; Bob now controls it.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(1, bob_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  const Crypto::Address custody = State::Keys::nftAddress(1);
  EXPECT_EQ(state_->getTokenBalance(custody, underlying), 5000);

  Core::NftInfo n;
  ASSERT_TRUE(state_->getNft(1, n));
  EXPECT_EQ(n.wrapped_amount, 5000);
  EXPECT_EQ(n.owner.toString(), bob_.publicKey.toString());

  //  4. Bob burns. The 5000 underlying goes to Bob, not Alice.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(1))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(state_->getTokenBalance(custody, underlying), 0);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, underlying), 5000);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, underlying), 5000);
}

TEST_F(Core_BlockProcessorFixture, NftReward_EpochBoundaryDrainsEscrow)
{
  //  Set up a reward-bearing collection and an NFT in it, directly
  //  through state.
  //
  //  Escrow = 10'000, rate = 10 per NFT per epoch, one NFT minted.
  //  After one epoch boundary the escrow should be 9'990.
  constexpr uint64_t ESCROW_START = 10'000;
  constexpr uint64_t RATE = 10;

  withState(
      [&](State::StateAccess &s)
      {
        Core::NftCollection c;
        c.id = 1;
        c.creator = alice_.publicKey;
        c.name = "Rewards";
        c.symbol = "REW";
        c.reward_token_id = 7;
        c.reward_rate_per_epoch = RATE;
        c.reward_escrow_remaining = ESCROW_START;
        c.created_at_height = 1;
        c.minted_count = 1;
        s.putNftCollection(c);
      });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;

  //  Build the block with makeProcessableBlock. The dry run inside
  //  it aborts and leaves state untouched.
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  //  Apply the block manually, so we control the commit. This is
  //  the same path the passing diagnostic uses.
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  Core::NftCollection in_txn;
  ASSERT_TRUE(s.getNftCollection(1, in_txn));
  EXPECT_EQ(in_txn.reward_escrow_remaining, ESCROW_START - RATE);
  EXPECT_FALSE(in_txn.reward_paused);

  s.commit(0);
  t.commit();

  Core::NftCollection after;
  readState([&](State::StateAccess &s2)
            { ASSERT_TRUE(s2.getNftCollection(1, after)); });
  EXPECT_EQ(after.reward_escrow_remaining, ESCROW_START - RATE);
  EXPECT_FALSE(after.reward_paused);
}

TEST_F(Core_BlockProcessorFixture, NftReward_ExhaustedEscrowPausesCollection)
{
  constexpr uint64_t ESCROW_START = 5;
  constexpr uint64_t RATE = 10;

  withState(
      [&](State::StateAccess &s)
      {
        Core::NftCollection c;
        c.id = 1;
        c.creator = alice_.publicKey;
        c.name = "Rewards";
        c.symbol = "REW";
        c.reward_token_id = 7;
        c.reward_rate_per_epoch = RATE;
        c.reward_escrow_remaining = ESCROW_START;
        c.created_at_height = 1;
        c.minted_count = 1;
        s.putNftCollection(c);

      });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  Core::NftCollection in_txn;
  ASSERT_TRUE(s.getNftCollection(1, in_txn));
  EXPECT_EQ(in_txn.reward_escrow_remaining, 0u);
  EXPECT_TRUE(in_txn.reward_paused);

  s.commit(0);
  t.commit();

  Core::NftCollection after;
  readState([&](State::StateAccess &s2)
            { ASSERT_TRUE(s2.getNftCollection(1, after)); });
  EXPECT_EQ(after.reward_escrow_remaining, 0u);
  EXPECT_TRUE(after.reward_paused);
}

TEST_F(Core_BlockProcessorFixture, NftReward_SimulateAndApplyProduceSameRoot)
{
  //  The reward pass writes through the SMT unconditionally, so it
  //  runs on both the dry-run and apply paths. This test proves that
  //  by simulating a block, aborting, then applying it for real and
  //  comparing the resulting state roots. If the reward loop were
  //  accidentally inside an `if (!ctx.dry_run)` guard, the two roots
  //  would diverge and this test would fail.
  withState(
      [&](State::StateAccess &s)
      {
        Core::NftCollection c;
        c.id = 1;
        c.creator = alice_.publicKey;
        c.name = "Rewards";
        c.symbol = "REW";
        c.reward_token_id = 7;
        c.reward_rate_per_epoch = 10;
        c.reward_escrow_remaining = 10'000;
        c.created_at_height = 1;
        c.minted_count = 3;
        s.putNftCollection(c);
      });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  //  Simulate: run the block with dry_run=true and capture the root.
  //  The fixture's makeProcessableBlock already did this once to fill
  //  in the header, but it doesn't expose the root. Do it again
  //  explicitly and abort.
  Crypto::Hash simulated_root;
  {
    auto txn = db_->beginWrite();
    State::StateAccess s(*db_, txn, 0);
    Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/true);
    Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
    ASSERT_TRUE(r.valid) << r.error;
    simulated_root = r.new_state_root;
    txn.abort();
  }

  //  Apply: run the same block for real, committing the result.
  Core::BlockResult applied = applyPrebuiltBlock(b);
  ASSERT_TRUE(applied.valid) << applied.error;

  //  The committed state root after apply must equal the simulated
  //  root. If the reward pass were gated on !dry_run, the apply path
  //  would mutate state the simulate path didn't, and the roots
  //  would differ.
  EXPECT_EQ(currentStateRoot(), simulated_root);
}

// =====================================================================
//  Executor: nested wrapping
//
//  The design allows wrapping an NFT's shadow token inside another
//  NFT. The WrapNft executor's only guard is
//  `underlying_token_id != next_nft_id`, which prevents an NFT from
//  wrapping its own shadow token but permits wrapping a *different*
//  NFT's shadow token. This test proves the model holds: both
//  records exist, both custody balances are correct, and the inner
//  NFT's shadow token is held at the outer NFT's custody address.
// =====================================================================

TEST_F(Core_ExecutorFixture, WrapNft_NestedWrapIsAllowedAndConsistent)
{
  //  1. Alice mints standalone NFT A (id 1).
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::MintNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeMintNftPayload(0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Alice now holds 1 unit of shadow token 1.
  ASSERT_EQ(state_->getTokenBalance(alice_.publicKey, 1), 1);

  //  2. Alice wraps shadow token 1 into a new NFT B (id 2). The
  //     executor allocates id 2 from the shared token counter.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::WrapNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeWrapNftPayload(
                        /*underlying=*/1, /*amount=*/1,
                        /*collection=*/0, Crypto::Hash{}, false, ""))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  NFT A is unchanged; NFT B wraps shadow token 1.
  Core::NftInfo a, b;
  ASSERT_TRUE(state_->getNft(1, a));
  ASSERT_TRUE(state_->getNft(2, b));

  EXPECT_TRUE(a.isStandalone());
  EXPECT_EQ(a.owner.toString(), alice_.publicKey.toString());

  EXPECT_TRUE(b.isWrapped());
  EXPECT_EQ(b.underlying_token_id, 1);
  EXPECT_EQ(b.wrapped_amount, 1);
  EXPECT_EQ(b.owner.toString(), alice_.publicKey.toString());

  //  Alice's shadow-token-1 balance moved to NFT B's custody address.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, 1), 0);
  const Crypto::Address custody_b = State::Keys::nftAddress(2);
  EXPECT_EQ(state_->getTokenBalance(custody_b, 1), 1);

  //  Alice holds shadow token 2 (NFT B's own shadow).
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, 2), 1);

  //  3. Transferring NFT B moves control of NFT A with it. Alice
  //     sends B to Bob; Bob should now be the effective controller
  //     of A, because A's shadow token sits at B's custody address.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::TransferNft)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeTransferNftPayload(2, bob_.publicKey))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_TRUE(state_->getNft(2, b));
  EXPECT_EQ(b.owner.toString(), bob_.publicKey.toString());

  //  The custody balance of shadow token 1 stays at NFT B's custody
  //  address; the transfer moved the NFT record's owner, not the
  //  custody.
  EXPECT_EQ(state_->getTokenBalance(custody_b, 1), 1);

  //  4. Bob burns NFT B. The shadow token 1 returns to Bob, giving
  //     Bob control of NFT A.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::BurnNft)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeNftIdPayload(2))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  NFT B is gone; NFT A still exists.
  Core::NftInfo after_burn;
  EXPECT_FALSE(state_->getNft(2, after_burn));
  ASSERT_TRUE(state_->getNft(1, a));
  EXPECT_EQ(a.owner.toString(), alice_.publicKey.toString());

  //  Bob now holds shadow token 1.
  EXPECT_EQ(state_->getTokenBalance(custody_b, 1), 0);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, 1), 1);
}

TEST_F(Core_ExecutorFixture, ForEachNftCollection_SeesWrittenCollection)
{
  Core::NftCollection c;
  c.id = 1;
  c.creator = alice_.publicKey;
  c.name = "Rewards";
  c.symbol = "REW";
  c.reward_token_id = 7;
  c.reward_rate_per_epoch = 10;
  c.reward_escrow_remaining = 10'000;
  c.created_at_height = 1;
  c.minted_count = 1;
  state_->putNftCollection(c);

  //  SMT read must find it.
  Core::NftCollection got;
  ASSERT_TRUE(state_->getNftCollection(1, got));

  //  The iterator must see it too. If this fails while the SMT read
  //  passes, the mirror row in TBL_NFT_COLLECTIONS is not being
  //  written, or forEachNftCollection is scanning the wrong table.
  uint64_t count = 0;
  state_->forEachNftCollection([&](const Core::NftCollection &seen)
                               {
                                 ++count;
                                 EXPECT_EQ(seen.id, 1u); });
  EXPECT_EQ(count, 1u);
}

TEST_F(Core_BlockProcessorFixture, NftCollection_MirrorRowSurvivesCommitAndReopen)
{
  //  Write a collection through a committing txn.
  withState(
      [&](State::StateAccess &s)
      {
        Core::NftCollection c;
        c.id = 1;
        c.creator = alice_.publicKey;
        c.name = "Rewards";
        c.symbol = "REW";
        c.reward_token_id = 7;
        c.reward_rate_per_epoch = 10;
        c.reward_escrow_remaining = 10'000;
        c.created_at_height = 1;
        c.minted_count = 1;
        s.putNftCollection(c);
      });

  //  Read it through a fresh txn: SMT first, then the iterator.
  readState(
      [&](State::StateAccess &s)
      {
        //  SMT read: expected to work (the executor tests prove this
        //  path works within a single txn, and it works across
        //  commits for every other record type).
        Core::NftCollection via_smt;
        ASSERT_TRUE(s.getNftCollection(1, via_smt));

        //  Iterator read: this is the one the reward pass uses. If
        //  it sees nothing here, the mirror row did not survive the
        //  commit, and the reward pass can never find the collection.
        uint64_t via_iter = 0;
        s.forEachNftCollection([&](const Core::NftCollection &)
                               { ++via_iter; });
        EXPECT_EQ(via_iter, 1u);
      });
}

TEST_F(Core_BlockProcessorFixture, NftReward_Diagnostic_ReadInsideApplyTxn)
{
  withState(
      [&](State::StateAccess &s)
      {
        Core::NftCollection c;
        c.id = 1;
        c.creator = alice_.publicKey;
        c.name = "Rewards";
        c.symbol = "REW";
        c.reward_token_id = 7;
        c.reward_rate_per_epoch = 10;
        c.reward_escrow_remaining = 10'000;
        c.created_at_height = 1;
        c.minted_count = 1;
        s.putNftCollection(c);
      });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  //  Apply the block in a txn, and read the escrow BEFORE commit.
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  Core::NftCollection in_txn;
  ASSERT_TRUE(s.getNftCollection(1, in_txn));
  EXPECT_EQ(in_txn.reward_escrow_remaining, 9'990u)
      << "loop did not run inside the apply txn";

  s.commit(0);
  t.commit();

  //  Now read after commit.
  readState(
      [&](State::StateAccess &s2)
      {
        Core::NftCollection after;
        ASSERT_TRUE(s2.getNftCollection(1, after));
        EXPECT_EQ(after.reward_escrow_remaining, 9'990u)
            << "commit dropped the decrement";
      });
}

TEST_F(Core_BlockProcessorFixture, StateLayer_TwoSmtWritesInOneCommitSurvive)
{
  //  Write two SMT-backed records in a single txn-bound StateAccess,
  //  commit, then read both back through a fresh StateAccess.
  //
  //  If this fails while a single-record write succeeds, the SMT's
  //  save() is losing one of the two updates in a multi-record
  //  commit, and every executor path that writes more than one SMT
  //  record per transaction is affected — not just NFT rewards.

  withState([&](State::StateAccess &s)
            {
              Core::NftCollection a;
              a.id = 1;
              a.creator = alice_.publicKey;
              a.name = "A";
              a.symbol = "AAAA";
              a.created_at_height = 1;
              s.putNftCollection(a);

              Core::NftCollection b;
              b.id = 2;
              b.creator = alice_.publicKey;
              b.name = "B";
              b.symbol = "BBBB";
              b.created_at_height = 1;
              s.putNftCollection(b); });

  readState([&](State::StateAccess &s)
            {
              Core::NftCollection a, b;
              EXPECT_TRUE(s.getNftCollection(1, a))
                  << "first write lost";
              EXPECT_TRUE(s.getNftCollection(2, b))
                  << "second write lost"; });
}

TEST_F(Core_BlockProcessorFixture, StateLayer_UpdateThenGetThenUpdate)
{
  //  Write record A (SMT update), read record B (SMT get — this
  //  is what putNft does now to unindex the old owner), then
  //  write record B (SMT update). Commit, then read both back.
  //
  //  If A doesn't survive but B does, the SMT's get() is
  //  clobbering the pending write buffer, and putNft's read-
  //  before-write pattern is the trigger.

  withState([&](State::StateAccess &s)
            {
              //  Update A: a collection.
              Core::NftCollection a;
              a.id = 1;
              a.creator = alice_.publicKey;
              a.name = "A";
              a.symbol = "AAAA";
              a.created_at_height = 1;
              s.putNftCollection(a);

              //  Get B: read an NFT that doesn't exist. This is the
              //  same read putNft does at the top of its body.
              Core::NftInfo probe;
              const bool got = s.getNft(99, probe);
              EXPECT_FALSE(got);

              //  Update B: write a different collection.
              Core::NftCollection b;
              b.id = 2;
              b.creator = alice_.publicKey;
              b.name = "B";
              b.symbol = "BBBB";
              b.created_at_height = 1;
              s.putNftCollection(b); });

  readState([&](State::StateAccess &s)
            {
              Core::NftCollection a, b;
              EXPECT_TRUE(s.getNftCollection(1, a))
                  << "update before the get was lost";
              EXPECT_TRUE(s.getNftCollection(2, b))
                  << "update after the get was lost"; });
}