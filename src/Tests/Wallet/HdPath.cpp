// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Wallet/HdPath.h"
#include "Wallet/WalletError.h"
#include "Wallet/WalletTypes.h"

using namespace Wallet;

//  HdPath parsing and canonical form.
//
//  The path format is:
//    m / 44' / 9000' / account' / change' / index'
//
//  All components hardened in the CLRTY convention. The parser is
//  strict: missing leading 'm', empty components, index overflow,
//  whitespace, and unknown hardened markers are all rejected.

//  Canonical form

TEST(Wallet_HdPath, ClrtyPathCanonicalForm)
{
  const HdPath p = clrtyPath(0, 0, 0);
  EXPECT_EQ(p.toString(), "m/44'/9000'/0'/0'/0'");
}

TEST(Wallet_HdPath, ClrtyPathNonZeroAccount)
{
  const HdPath p = clrtyPath(7, 0, 0);
  EXPECT_EQ(p.toString(), "m/44'/9000'/7'/0'/0'");
}

TEST(Wallet_HdPath, ClrtyPathChangeChain)
{
  const HdPath p = clrtyPath(0, 1, 0);
  EXPECT_EQ(p.toString(), "m/44'/9000'/0'/1'/0'");
}

TEST(Wallet_HdPath, ClrtyPathIndex)
{
  const HdPath p = clrtyPath(0, 0, 12345);
  EXPECT_EQ(p.toString(), "m/44'/9000'/0'/0'/12345'");
}

TEST(Wallet_HdPath, ReceiveAndChangeHelpers)
{
  EXPECT_EQ(receivePath(0, 0).toString(), "m/44'/9000'/0'/0'/0'");
  EXPECT_EQ(receivePath(0, 5).toString(), "m/44'/9000'/0'/0'/5'");
  EXPECT_EQ(changePath(0, 0).toString(), "m/44'/9000'/0'/1'/0'");
  EXPECT_EQ(changePath(0, 5).toString(), "m/44'/9000'/0'/1'/5'");
}

//  Parse success
//
//  Canonical strings round-trip cleanly.

TEST(Wallet_HdPath, ParseCanonical)
{
  WalletStatus st;
  auto p = parseHdPath("m/44'/9000'/0'/0'/0'", &st);
  ASSERT_TRUE(p.has_value()) << "error: " << walletErrorMessage(st.code);
  EXPECT_EQ(p->toString(), "m/44'/9000'/0'/0'/0'");
}

TEST(Wallet_HdPath, ParseAllMarkerVariants)
{
  // ' (apostrophe), h, and H are all accepted as hardened markers.
  WalletStatus st;

  auto a = parseHdPath("m/44'/9000'/0'/0'/0'", &st);
  ASSERT_TRUE(a.has_value());

  auto b = parseHdPath("m/44h/9000h/0h/0h/0h", &st);
  ASSERT_TRUE(b.has_value());

  auto c = parseHdPath("m/44H/9000H/0H/0H/0H", &st);
  ASSERT_TRUE(c.has_value());

  // All three must produce the same canonical form.
  EXPECT_EQ(a->toString(), b->toString());
  EXPECT_EQ(a->toString(), c->toString());
}

TEST(Wallet_HdPath, ParseMixedMarkers)
{
  WalletStatus st;
  auto p = parseHdPath("m/44h/9000'/0H/0'/0h", &st);
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->toString(), "m/44'/9000'/0'/0'/0'");
}

TEST(Wallet_HdPath, ParseSingleComponent)
{
  WalletStatus st;
  auto p = parseHdPath("m/0", &st);
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->length, 1u);
  EXPECT_EQ(p->toString(), "m/0");
}

TEST(Wallet_HdPath, ParseUppercaseM)
{
  WalletStatus st;
  auto p = parseHdPath("M/44'/9000'", &st);
  ASSERT_TRUE(p.has_value());
  // Canonical form always uses lowercase 'm'.
  EXPECT_EQ(p->toString(), "m/44'/9000'");
}

TEST(Wallet_HdPath, ParseZeroIndices)
{
  WalletStatus st;
  auto p = parseHdPath("m/0/0/0/0/0", &st);
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->toString(), "m/0/0/0/0/0");
}

TEST(Wallet_HdPath, ParseMaxIndex)
{
  // Maximum non-hardened index is 2^31 - 1 = 2147483647.
  WalletStatus st;
  auto p = parseHdPath("m/2147483647", &st);
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->elements[0].index, 2147483647u);
  EXPECT_FALSE(p->elements[0].hardened);
}

TEST(Wallet_HdPath, ParseMaxHardenedIndex)
{
  WalletStatus st;
  auto p = parseHdPath("m/2147483647'", &st);
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->elements[0].index, 2147483647u);
  EXPECT_TRUE(p->elements[0].hardened);
}

//  Parse failure — empty / degenerate
//
//  Note: parseHdPath returns std::nullopt on failure. When the
//  error_out parameter is non-null, it fills in a WalletStatus.

TEST(Wallet_HdPath, ParseEmpty)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("", &st).has_value());
  EXPECT_EQ(st.code, WalletError::InvalidPath);
}

TEST(Wallet_HdPath, ParseBareM)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("m", &st).has_value());
  EXPECT_EQ(st.code, WalletError::InvalidPath);
}

TEST(Wallet_HdPath, ParseBareSlash)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("/", &st).has_value());
}

TEST(Wallet_HdPath, ParseMissingLeadingM)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("44'/9000'", &st).has_value());
  EXPECT_FALSE(parseHdPath("0/0/0", &st).has_value());
  EXPECT_FALSE(parseHdPath("x/0", &st).has_value());
}

TEST(Wallet_HdPath, ParseTrailingSlash)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("m/44'/", &st).has_value());
}

TEST(Wallet_HdPath, ParseEmptyComponent)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("m//44'", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/44'//9000'", &st).has_value());
}

//  Parse failure — index validation

TEST(Wallet_HdPath, ParseIndexOverflow)
{
  WalletStatus st;
  // 2^31 = 2147483648, one past MAX_INDEX.
  EXPECT_FALSE(parseHdPath("m/2147483648", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/2147483648'", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/4294967296", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/99999999999999", &st).has_value());
}

TEST(Wallet_HdPath, ParseNegativeIndex)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath("m/-1", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/-1'", &st).has_value());
}

TEST(Wallet_HdPath, ParseHexIndex)
{
  WalletStatus st;
  // Hex is not accepted. Indices are decimal only.
  EXPECT_FALSE(parseHdPath("m/0x10", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/0X10", &st).has_value());
}

TEST(Wallet_HdPath, ParseWhitespace)
{
  WalletStatus st;
  EXPECT_FALSE(parseHdPath(" m/0", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/0 ", &st).has_value());
  EXPECT_FALSE(parseHdPath("m /0", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/ 0", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/0 1", &st).has_value());
}

TEST(Wallet_HdPath, ParseEmptyAfterMarker)
{
  WalletStatus st;
  // "44'" is fine, but "'" alone has no index.
  EXPECT_FALSE(parseHdPath("m/'", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/h", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/H", &st).has_value());
}

TEST(Wallet_HdPath, ParseDoubleMarker)
{
  WalletStatus st;
  // Two markers on one component: after stripping the last one, the
  // remaining text still has a marker that isn't a digit.
  EXPECT_FALSE(parseHdPath("m/44''", &st).has_value());
  EXPECT_FALSE(parseHdPath("m/44'h", &st).has_value());
}

//  Parse failure — depth

TEST(Wallet_HdPath, ParseTooDeep)
{
  // MAX_PATH_LENGTH is 16. Build a path with 17 components.
  std::string s = "m";
  for (int i = 0; i < 17; ++i)
    s += "/0";
  WalletStatus st;
  EXPECT_FALSE(parseHdPath(s, &st).has_value());
}

TEST(Wallet_HdPath, ParseMaxDepthAccepted)
{
  std::string s = "m";
  for (int i = 0; i < 16; ++i)
    s += "/0";
  WalletStatus st;
  auto p = parseHdPath(s, &st);
  ASSERT_TRUE(p.has_value()) << "error: " << walletErrorMessage(st.code);
  EXPECT_EQ(p->length, 16u);
}

//  Round-trip

TEST(Wallet_HdPath, RoundTripMany)
{
  for (uint32_t account : {0u, 1u, 7u, 100u, 4294967u})
  {
    for (uint32_t change : {0u, 1u})
    {
      for (uint32_t index : {0u, 1u, 10u, 1000u, 1000000u})
      {
        const HdPath original = clrtyPath(account, change, index);
        const std::string s = original.toString();

        WalletStatus st;
        auto parsed = parseHdPath(s, &st);
        ASSERT_TRUE(parsed.has_value())
            << "failed to parse: " << s
            << " (error: " << walletErrorMessage(st.code) << ")";

        EXPECT_EQ(parsed->toString(), s);
        EXPECT_EQ(*parsed, original);
      }
    }
  }
}

//  Equality

TEST(Wallet_HdPath, Equality)
{
  const HdPath a = clrtyPath(0, 0, 0);
  const HdPath b = clrtyPath(0, 0, 0);
  const HdPath c = clrtyPath(0, 0, 1);

  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a == c);
  EXPECT_TRUE(a != c);
  EXPECT_FALSE(a != b);
}

TEST(Wallet_HdPath, EqualityLengthMismatch)
{
  WalletStatus st;
  auto a = parseHdPath("m/0", &st);
  auto b = parseHdPath("m/0/0", &st);
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());

  EXPECT_FALSE(*a == *b);
  EXPECT_TRUE(*a != *b);
}

TEST(Wallet_HdPath, EqualityHardenedMismatch)
{
  WalletStatus st;
  auto a = parseHdPath("m/0", &st);
  auto b = parseHdPath("m/0'", &st);
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());

  EXPECT_FALSE(*a == *b);
  EXPECT_TRUE(*a != *b);
}

//  push()

TEST(Wallet_HdPath, Push)
{
  HdPath p;
  EXPECT_TRUE(p.push(44, true));
  EXPECT_TRUE(p.push(9000, true));
  EXPECT_EQ(p.length, 2u);
  EXPECT_EQ(p.toString(), "m/44'/9000'");
}

TEST(Wallet_HdPath, PushRejectsTooDeep)
{
  HdPath p;
  for (size_t i = 0; i < MAX_PATH_LENGTH; ++i)
  {
    EXPECT_TRUE(p.push(0, false)) << "at index " << i;
  }
  // One more must fail.
  EXPECT_FALSE(p.push(0, false));
  EXPECT_EQ(p.length, MAX_PATH_LENGTH);
}

TEST(Wallet_HdPath, PushRejectsIndexOverflow)
{
  HdPath p;
  EXPECT_FALSE(p.push(0x80000000u, false)); // == hardened bit alone
  EXPECT_FALSE(p.push(0xFFFFFFFFu, false));
}

//  Raw index computation

TEST(Wallet_HdPath, RawIndexIncludesHardenedBit)
{
  PathElement e;
  e.index = 44;
  e.hardened = false;
  EXPECT_EQ(e.raw(), 44u);

  e.hardened = true;
  EXPECT_EQ(e.raw(), 44u | HARDENED_BIT);
  EXPECT_EQ(e.raw(), 0x8000002Cu);
}

TEST(Wallet_HdPath, RawIndexMaxValue)
{
  PathElement e;
  e.index = MAX_INDEX; // 0x7FFFFFFF
  e.hardened = true;
  EXPECT_EQ(e.raw(), 0xFFFFFFFFu);
}

//  Constants

TEST(Wallet_HdPath, Constants)
{
  EXPECT_EQ(BIP44_PURPOSE, 44u);
  EXPECT_EQ(COIN_TYPE_CLRTY, 9000u);
  EXPECT_EQ(HD_EXTERNAL_CHAIN, 0u);
  EXPECT_EQ(HD_INTERNAL_CHAIN, 1u);
  EXPECT_EQ(CLRTY_PATH_LENGTH, 5u);
}