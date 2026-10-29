// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Bridge/ConcealCCX.h"

#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include <cstring>
#include <set>
#include <vector>

namespace
{
  //  Build a keypair whose secret half is the *scalar*, not the
  //  seed. CcxBridge::deriveSubaddress calls sc_check on the
  //  view_priv input, so it needs the scalar form. The spend_pub
  //  input is a public key; either keypair shape works for it,
  //  but we use the scalar form for both so that a single fixture
  //  provides a coherent pair (the "spend" and "view" halves
  //  come from distinct scalars, which is what a real CCX
  //  address looks like).
  Crypto::KeyPair makeKeypairFromBytes(
      const std::vector<uint8_t> &bytes)
  {
    Crypto::SecretKey seed;
    std::memcpy(seed.data.data(), bytes.data(), 32);
    return Crypto::generateScalarKeyPairFromSeed(seed);
  }

  struct SubaddressPair
  {
    Crypto::PublicKey spend_pub;
    Crypto::SecretKey view_priv;
    Crypto::PublicKey view_pub;
  };

  //  Fixture: a valid (spend_pub, view_priv) pair suitable for
  //  deriveSubaddress. Both halves come from distinct seeds, so
  //  the pair is "spend and view from different keypairs", which
  //  is what a real CCX address is — the spend pubkey and the view
  //  pubkey are unrelated points, and only the view private half
  //  is needed by the derivation.
  SubaddressPair makeFixturePair(
      const std::vector<uint8_t> &spend_seed,
      const std::vector<uint8_t> &view_seed)
  {
    auto spend_kp = makeKeypairFromBytes(spend_seed);
    auto view_kp = makeKeypairFromBytes(view_seed);

    SubaddressPair p;
    p.spend_pub = spend_kp.publicKey;
    p.view_priv = view_kp.secretKey;
    p.view_pub = view_kp.publicKey;
    return p;
  }
} // anonymous namespace

TEST(CcxSubaddress, DeriveIsDeterministic)
{
  //  Same inputs must produce the same outputs. This is the
  //  fundamental invariant: the scanner and the wallet both derive
  //  from the same (chain, index), and must agree.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto p = makeFixturePair(spend_seed, view_seed);

  Crypto::PublicKey a_spend, a_view, b_spend, b_view;
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 1,
      a_spend, a_view));
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 1,
      b_spend, b_view));
  EXPECT_EQ(a_spend, b_spend);
  EXPECT_EQ(a_view, b_view);
}

TEST(CcxSubaddress, DifferentIndicesProduceDifferentSubaddresses)
{
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto p = makeFixturePair(spend_seed, view_seed);

  std::set<std::vector<uint8_t>> seen;

  for (uint64_t i = 1; i <= 16; ++i)
  {
    Crypto::PublicKey sub_spend, sub_view;
    ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
        p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, i,
        sub_spend, sub_view));

    std::vector<uint8_t> key;
    key.insert(key.end(),
               sub_spend.data.begin(), sub_spend.data.end());
    key.insert(key.end(),
               sub_view.data.begin(), sub_view.data.end());
    seen.insert(std::move(key));
  }

  EXPECT_EQ(seen.size(), 16u);
}

TEST(CcxSubaddress, DifferentChainsProduceDifferentSubaddresses)
{
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto p = makeFixturePair(spend_seed, view_seed);

  Crypto::PublicKey sub_a_spend, sub_a_view;
  Crypto::PublicKey sub_b_spend, sub_b_view;

  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, 0x43435831ULL, 1,
      sub_a_spend, sub_a_view));
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, 0x43435854ULL, 1,
      sub_b_spend, sub_b_view));

  EXPECT_NE(sub_a_spend, sub_b_spend);
  EXPECT_NE(sub_a_view, sub_b_view);
}

TEST(CcxSubaddress, RejectsNullSpendPub)
{
  //  A null spend_pub is caught by ge_frombytes_vartime (the
  //  all-zeros input does not decode to a valid spend pubkey in
  //  the way deriveSubaddress requires). Even if that guard were
  //  not there, the input guard at the top of deriveSubaddress
  //  rejects the null pubkey before any computation.
  const std::vector<uint8_t> view_seed(32, 0x20);
  auto view_kp = makeKeypairFromBytes(view_seed);

  Crypto::PublicKey null_spend{};
  Crypto::PublicKey sub_spend, sub_view;
  EXPECT_FALSE(Core::CcxBridge::deriveSubaddress(
      null_spend, view_kp.secretKey,
      Core::CcxBridge::CCX_CHAIN_ID, 1,
      sub_spend, sub_view));
}

TEST(CcxSubaddress, RejectsNullViewPriv)
{
  //  A null view_priv is a valid scalar (0 < ℓ), so sc_check
  //  accepts it — the derivation would produce
  //  view_pub = 0 * sub_spend_pub = identity, which is a well-
  //  defined but useless view key. The input guard at the top of
  //  deriveSubaddress rejects the null view_priv before any
  //  computation, so this test asserts that guard.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  auto spend_kp = makeKeypairFromBytes(spend_seed);

  Crypto::SecretKey null_view{};
  Crypto::PublicKey sub_spend, sub_view;
  EXPECT_FALSE(Core::CcxBridge::deriveSubaddress(
      spend_kp.publicKey, null_view,
      Core::CcxBridge::CCX_CHAIN_ID, 1,
      sub_spend, sub_view));
}

TEST(CcxSubaddress, DerivedViewPubIsDeterministic)
{
  //  The view pubkey is view_priv * sub_spend_pub. If we recompute
  //  it a second time from the same inputs, we must get the same
  //  point. This catches a bug where sc_reduce32 or ge_scalarmult
  //  leaves the reduction buffer or the output buffer in a state
  //  that leaks into the next call.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto p = makeFixturePair(spend_seed, view_seed);

  Crypto::PublicKey first_spend, first_view;
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 7,
      first_spend, first_view));

  //  Recompute with a different index in between to perturb any
  //  global state.
  Crypto::PublicKey tmp_spend, tmp_view;
  Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 8,
      tmp_spend, tmp_view);

  Crypto::PublicKey second_spend, second_view;
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 7,
      second_spend, second_view));

  EXPECT_EQ(first_spend, second_spend);
  EXPECT_EQ(first_view, second_view);
}

TEST(CcxSubaddress, BlobHelperMatchesTypedOverload)
{
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto p = makeFixturePair(spend_seed, view_seed);

  Crypto::PublicKey typed_spend, typed_view;
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 3,
      typed_spend, typed_view));

  const auto blob = Core::CcxBridge::deriveSubaddressBlob(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 3);

  ASSERT_EQ(blob.size(), 64u);
  EXPECT_EQ(std::memcmp(blob.data(), typed_spend.data.data(), 32), 0);
  EXPECT_EQ(std::memcmp(blob.data() + 32,
                        typed_view.data.data(), 32),
            0);
}

TEST(CcxSubaddress, BlobRoutripThroughDecodeDestination)
{
  //  deriveSubaddressBlob produces a 64-byte (spend || view) pair
  //  that decodeDestination must accept. This is the contract with
  //  the RPC and the scanner: the watcher derives, the caller
  //  stores as destination_blob, and any later reader
  //  decodeDestination's the blob back into the same pair.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto p = makeFixturePair(spend_seed, view_seed);

  const auto blob = Core::CcxBridge::deriveSubaddressBlob(
      p.spend_pub, p.view_priv, Core::CcxBridge::CCX_CHAIN_ID, 42);
  ASSERT_EQ(blob.size(), 64u);

  Crypto::PublicKey decoded_spend, decoded_view;
  ASSERT_TRUE(Core::CcxBridge::decodeDestination(
      blob, decoded_spend, decoded_view));

  EXPECT_EQ(std::memcmp(blob.data(), decoded_spend.data.data(), 32), 0);
  EXPECT_EQ(std::memcmp(blob.data() + 32,
                        decoded_view.data.data(), 32),
            0);
}