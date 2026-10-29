// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Apps/Bridge/Adapters/Conceal/ConcealCCX.h"
#include "Core/Bridge/ConcealCCX.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Helpers.h"

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

using namespace Bridge;

namespace
{
  //  ---- Fixture primitives ---------------------------------------------

  //  Fixed seeds. The same seeds as the CcxSubaddress test, so the
  //  expected subaddresses there and the ones here are the same
  //  vectors — a bug in deriveSubaddress would be caught by both.
  const std::vector<uint8_t> kSpendSeed(32, 0x10);
  const std::vector<uint8_t> kViewSeed(32, 0x20);

  Crypto::KeyPair makeScalarKeypair(const std::vector<uint8_t> &seed_bytes)
  {
    Crypto::SecretKey seed;
    std::memcpy(seed.data.data(), seed_bytes.data(), 32);
    return Crypto::generateScalarKeyPairFromSeed(seed);
  }

  std::string toHex(const uint8_t *data, size_t len)
  {
    static const char HEX[] = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i)
    {
      s.push_back(HEX[data[i] >> 4]);
      s.push_back(HEX[data[i] & 0xF]);
    }
    return s;
  }

  std::string hashToHex(const Crypto::Hash &h)
  {
    return toHex(h.data.data(), h.data.size());
  }

  std::string pubkeyToHex(const Crypto::PublicKey &pk)
  {
    return toHex(pk.data.data(), pk.data.size());
  }

  //  A full test fixture: the adapter, the cache, the custody
  //  keypair, and helpers to build synthetic CCX JSON.
  struct ScanFixture
  {
    CcxAdapter adapter;
    BridgeDepositCache cache;

    //  Custody keypair (spend pub used as the "master" — subaddresses
    //  derive from it) and view secret (for generateKeyDerivation).
    Crypto::KeyPair custody_spend;
    Crypto::KeyPair custody_view;
    std::vector<uint8_t> custody_blob; // 64 bytes: spend||view pubkeys

    //  A recipient "tx pubkey" for synthetic transactions. Any valid
    //  point works; we use a fixed scalar keypair.
    Crypto::KeyPair tx_keypair;

    ScanFixture()
    {
      custody_spend = makeScalarKeypair(kSpendSeed);
      custody_view = makeScalarKeypair(kViewSeed);
      tx_keypair = makeScalarKeypair(std::vector<uint8_t>(32, 0x30));

      //  Build the 64-byte custody address blob and hand it to the
      //  adapter, exactly as cmd_start would.
      custody_blob.resize(64);
      std::memcpy(custody_blob.data(),
                  custody_spend.publicKey.data.data(), 32);
      std::memcpy(custody_blob.data() + 32,
                  custody_view.publicKey.data.data(), 32);
      adapter.set_deposit_address(custody_blob);
      adapter.set_deposit_ident_secret(custody_view.secretKey);
      adapter.set_bridge_deposits_cache(&cache);
    }

    //  Register a subaddress in the cache. Returns the sub_spend_pub
    //  so the caller can construct a synthetic vout that pays to it.
    Crypto::PublicKey registerSubaddress(
        uint64_t index,
        const Crypto::Address &destination)
    {
      Crypto::PublicKey sub_spend, sub_view;
      EXPECT_TRUE(Core::CcxBridge::deriveSubaddress(
          custody_spend.publicKey,
          custody_view.secretKey,
          Core::CcxBridge::CCX_CHAIN_ID,
          index,
          sub_spend, sub_view));

      BridgeDepositCacheEntry entry;
      entry.index = index;
      entry.destination = destination;
      entry.authority = destination; // not checked by the scanner
      entry.registered_at_height = 1;
      cache[sub_spend] = entry;

      return sub_spend;
    }

    //  Build a CCX JSON tx that pays `amount` to a vout whose
    //  on-chain pubkey is `derivePublicKey(derivation, vout_index,
    //  sub_spend_pub)`.
    //
    //  The test builds the JSON in the exact shape the CCX daemon
    //  returns from /get_raw_transactions_by_heights, so
    //  populateDepositsFromJson sees what it would see in
    //  production. Nothing about the test's setup reflects a
    //  different code path.
    Common::Json makeTx(
        const Crypto::Hash &tx_hash,
        uint64_t height,
        const std::vector<std::pair<Crypto::PublicKey, uint64_t>> &vouts)
    {
      //  extra: [0x01 tag][32-byte tx_pub]
      std::vector<uint8_t> extra;
      extra.push_back(0x01);
      extra.insert(extra.end(),
                   tx_keypair.publicKey.data.begin(),
                   tx_keypair.publicKey.data.end());

      Common::Json vout_arr = Common::Json::array();
      for (const auto &[pk, amount] : vouts)
      {
        Common::Json v = Common::Json::object();
        v["amount"] = amount;
        Common::Json target_data = Common::Json::object();
        target_data["key"] = pubkeyToHex(pk);
        Common::Json target = Common::Json::object();
        target["data"] = target_data;
        v["target"] = target;
        vout_arr.push_back(std::move(v));
      }

      Common::Json txobj = Common::Json::object();
      txobj["extra"] = toHex(extra.data(), extra.size());
      txobj["vout"] = std::move(vout_arr);

      Common::Json out = Common::Json::object();
      out["hash"] = hashToHex(tx_hash);
      out["height"] = height;
      out["transaction"] = std::move(txobj);
      return out;
    }

    //  Given a subaddress spend pubkey, derive the on-chain output
    //  pubkey at vout_index for our test tx's derivation. That's
    //  what the CCX wallet would have done when paying to the
    //  subaddress, and what the reverse-derive in the scanner
    //  inverts.
    Crypto::PublicKey
    onChainPubkeyFor(const Crypto::PublicKey &sub_spend_pub,
                     uint32_t vout_index)
    {
      Crypto::KeyDerivation derivation;
      EXPECT_TRUE(Crypto::generateKeyDerivation(
          tx_keypair.publicKey,
          custody_view.secretKey,
          derivation));

      Crypto::PublicKey expected;
      EXPECT_TRUE(Crypto::derivePublicKey(
          derivation, vout_index, sub_spend_pub, expected));
      return expected;
    }
  };

  //  A deterministic destination address for cache entries.
  Crypto::Address destinationFor(uint8_t b)
  {
    Crypto::Address a;
    a.data[0] = b;
    return a;
  }
} // anonymous namespace

// ============================================================================
//  Case 1: one matching vout
// ============================================================================

TEST(Core_CcxScanDeposits, SingleVoutMatchesRegisteredSubaddress)
{
  ScanFixture f;

  const Crypto::Address destination = destinationFor(0xA1);
  const Crypto::PublicKey sub_spend = f.registerSubaddress(1, destination);

  const Crypto::PublicKey onchain = f.onChainPubkeyFor(sub_spend, 0);
  const Crypto::Hash tx_hash = Crypto::Hash{};
  auto tx = f.makeTx(tx_hash, 100, {{onchain, 5000}});
  //  Fix the tx hash to a non-null value so the deposit key is
  //  meaningful.
  tx["hash"] = hashToHex(
      Crypto::hashDomain("test", reinterpret_cast<const uint8_t *>("1"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  ASSERT_FALSE(had_unresolved);
  ASSERT_EQ(deposits.size(), 1u);

  EXPECT_EQ(deposits[0].amount_source_atomic, 5000u);
  EXPECT_EQ(deposits[0].source_output_index, 0u);
  EXPECT_EQ(deposits[0].block_height, 100u);
  EXPECT_EQ(deposits[0].destination, destination);
  EXPECT_EQ(deposits[0].source_chain_id,
            Core::CcxBridge::CCX_CHAIN_ID);
}

// ============================================================================
//  Case 2: one tx with two vouts to two different subaddresses
// ============================================================================

TEST(Core_CcxScanDeposits, MultipleVoutsToDifferentSubaddresses)
{
  ScanFixture f;

  const Crypto::Address dest_a = destinationFor(0xB1);
  const Crypto::Address dest_b = destinationFor(0xB2);
  const Crypto::PublicKey sub_a = f.registerSubaddress(1, dest_a);
  const Crypto::PublicKey sub_b = f.registerSubaddress(2, dest_b);

  const Crypto::PublicKey onchain_a = f.onChainPubkeyFor(sub_a, 0);
  const Crypto::PublicKey onchain_b = f.onChainPubkeyFor(sub_b, 1);

  auto tx = f.makeTx(Crypto::Hash{}, 101, {{onchain_a, 1000}, {onchain_b, 2000}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("2"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  ASSERT_FALSE(had_unresolved);
  ASSERT_EQ(deposits.size(), 2u);

  //  Deposits in vout order.
  EXPECT_EQ(deposits[0].source_output_index, 0u);
  EXPECT_EQ(deposits[0].amount_source_atomic, 1000u);
  EXPECT_EQ(deposits[0].destination, dest_a);

  EXPECT_EQ(deposits[1].source_output_index, 1u);
  EXPECT_EQ(deposits[1].amount_source_atomic, 2000u);
  EXPECT_EQ(deposits[1].destination, dest_b);
}

// ============================================================================
//  Case 3: vout to the custody address directly — not a deposit
// ============================================================================

TEST(Core_CcxScanDeposits, VoutToCustodyAddressIsNotABridgeDeposit)
{
  ScanFixture f;

  //  No subaddress registered; the vout pays the custody address
  //  itself. This is a "user sent to the bridge address but didn't
  //  register a destination" scenario. The scanner must not emit
  //  a deposit, but it must also NOT count as unresolved (there is
  //  no reason to hold the cursor — this vout will never become a
  //  deposit).
  Crypto::KeyDerivation derivation;
  ASSERT_TRUE(Crypto::generateKeyDerivation(
      f.tx_keypair.publicKey,
      f.custody_view.secretKey,
      derivation));

  Crypto::PublicKey custody_vout_pub;
  ASSERT_TRUE(Crypto::derivePublicKey(
      derivation, 0, f.custody_spend.publicKey, custody_vout_pub));

  auto tx = f.makeTx(Crypto::Hash{}, 200, {{custody_vout_pub, 1000}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("3"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  EXPECT_FALSE(had_unresolved);  // resolved: not a deposit, done
  EXPECT_TRUE(deposits.empty()); // nothing emitted
}

// ============================================================================
//  Case 4: cache miss → unresolved vout
// ============================================================================

TEST(Core_CcxScanDeposits, CacheMissHoldsCursor)
{
  ScanFixture f;

  //  Make a vout that pays to a subaddress at index 99. Don't
  //  register it.
  Crypto::PublicKey sub_spend, sub_view;
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      f.custody_spend.publicKey,
      f.custody_view.secretKey,
      Core::CcxBridge::CCX_CHAIN_ID, 99,
      sub_spend, sub_view));

  const Crypto::PublicKey onchain = f.onChainPubkeyFor(sub_spend, 0);

  auto tx = f.makeTx(Crypto::Hash{}, 300, {{onchain, 500}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("4"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  EXPECT_TRUE(had_unresolved);
  EXPECT_TRUE(deposits.empty());
}

// ============================================================================
//  Case 5: mixed clean + cache-miss — the scanner stops at the miss
// ============================================================================

TEST(Core_CcxScanDeposits, MixedCleanAndCacheMissStopsAtMiss)
{
  ScanFixture f;

  //  Register index 1 (clean); leave index 2 out (miss).
  const Crypto::Address dest_a = destinationFor(0xC1);
  const Crypto::PublicKey sub_a = f.registerSubaddress(1, dest_a);

  Crypto::PublicKey sub_b_spend, sub_b_view;
  ASSERT_TRUE(Core::CcxBridge::deriveSubaddress(
      f.custody_spend.publicKey,
      f.custody_view.secretKey,
      Core::CcxBridge::CCX_CHAIN_ID, 2,
      sub_b_spend, sub_b_view));

  const Crypto::PublicKey onchain_a = f.onChainPubkeyFor(sub_a, 0);
  const Crypto::PublicKey onchain_b = f.onChainPubkeyFor(sub_b_spend, 1);

  auto tx = f.makeTx(Crypto::Hash{}, 400,
                     {{onchain_a, 1000}, {onchain_b, 2000}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("5"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  //  The clean vout still emits its deposit — the miss doesn't
  //  suppress the deposits the scanner *did* match. The
  //  had_unresolved flag is what tells the scan loop to hold the
  //  cursor past this height so a later refresh picks up the miss.
  EXPECT_TRUE(had_unresolved);
  ASSERT_EQ(deposits.size(), 1u);
  EXPECT_EQ(deposits[0].destination, dest_a);
  EXPECT_EQ(deposits[0].amount_source_atomic, 1000u);
}

// ============================================================================
//  Case 6: null cache → every vout is unresolvable, no deposits
// ============================================================================

TEST(Core_CcxScanDeposits, NullCacheEmitsNothing)
{
  ScanFixture f;

  const Crypto::Address dest = destinationFor(0xD1);
  const Crypto::PublicKey sub = f.registerSubaddress(1, dest);
  const Crypto::PublicKey onchain = f.onChainPubkeyFor(sub, 0);

  auto tx = f.makeTx(Crypto::Hash{}, 500, {{onchain, 1000}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("6"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, /*cache=*/nullptr, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  EXPECT_TRUE(had_unresolved);
  EXPECT_TRUE(deposits.empty());
}

// ============================================================================
//  Case 7: missing view key → every vout is unresolvable
// ============================================================================

TEST(Core_CcxScanDeposits, MissingViewKeyEmitsNothing)
{
  ScanFixture f;

  const Crypto::Address dest = destinationFor(0xE1);
  const Crypto::PublicKey sub = f.registerSubaddress(1, dest);
  const Crypto::PublicKey onchain = f.onChainPubkeyFor(sub, 0);

  auto tx = f.makeTx(Crypto::Hash{}, 600, {{onchain, 1000}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("7"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob,
      /*custody_view_key=*/std::nullopt,
      deposits, had_unresolved));

  EXPECT_TRUE(had_unresolved);
  EXPECT_TRUE(deposits.empty());
}

// ============================================================================
//  Case 8: a vout that pays a *different* registered subaddress at
//  the wrong vout index doesn't match (reverse derivation is
//  index-sensitive)
// ============================================================================

TEST(Core_CcxScanDeposits, WrongIndexDoesNotMatch)
{
  ScanFixture f;

  const Crypto::Address dest = destinationFor(0xF1);
  const Crypto::PublicKey sub = f.registerSubaddress(1, dest);

  //  Derive the on-chain pubkey at index 2, but put it in vout 0.
  //  The reverse-derive will compute the candidate for index 0,
  //  which won't match the cache entry for `sub` (that entry was
  //  derived at index 1).
  const Crypto::PublicKey onchain = f.onChainPubkeyFor(sub, 2);

  auto tx = f.makeTx(Crypto::Hash{}, 700, {{onchain, 1000}});
  tx["hash"] = hashToHex(Crypto::hashDomain(
      "test", reinterpret_cast<const uint8_t *>("8"), 1));

  std::vector<ObservedDeposit> deposits;
  bool had_unresolved = false;
  ASSERT_TRUE(CcxAdapter::populateDepositsFromJson(
      tx, &f.cache, f.custody_blob, f.custody_view.secretKey,
      deposits, had_unresolved));

  //  Doesn't match. Counts as unresolved (the scanner can't tell
  //  "wrong index" from "cache miss" — both are "this candidate
  //  isn't in the cache, retry after refresh").
  EXPECT_TRUE(had_unresolved);
  EXPECT_TRUE(deposits.empty());
}