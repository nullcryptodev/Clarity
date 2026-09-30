// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/Wire.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace Common;

// ============================================================================
//  Primitives — read*
// ============================================================================

TEST(Common_Wire_Primitives, ReadU8)
{
  const uint8_t buf[] = {0xAB};
  EXPECT_EQ(readU8(buf), 0xAB);
}

TEST(Common_Wire_Primitives, ReadU16LittleEndian)
{
  const uint8_t buf[] = {0x34, 0x12};
  EXPECT_EQ(readU16(buf), 0x1234);
}

TEST(Common_Wire_Primitives, ReadU32LittleEndian)
{
  const uint8_t buf[] = {0x78, 0x56, 0x34, 0x12};
  EXPECT_EQ(readU32(buf), 0x12345678u);
}

TEST(Common_Wire_Primitives, ReadU64LittleEndian)
{
  const uint8_t buf[] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
  EXPECT_EQ(readU64(buf), 0x0123456789ABCDEFull);
}

TEST(Common_Wire_Primitives, ReadAllZeros)
{
  const uint8_t buf[8] = {};
  EXPECT_EQ(readU8(buf), 0);
  EXPECT_EQ(readU16(buf), 0);
  EXPECT_EQ(readU32(buf), 0u);
  EXPECT_EQ(readU64(buf), 0ull);
}

TEST(Common_Wire_Primitives, ReadAllOnes)
{
  const uint8_t buf[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  EXPECT_EQ(readU8(buf), 0xFF);
  EXPECT_EQ(readU16(buf), 0xFFFF);
  EXPECT_EQ(readU32(buf), 0xFFFFFFFFu);
  EXPECT_EQ(readU64(buf), 0xFFFFFFFFFFFFFFFFull);
}

// ============================================================================
//  Primitives — put*
// ============================================================================

TEST(Common_Wire_Primitives, PutU8)
{
  std::vector<uint8_t> out;
  putU8(out, 0xAB);
  ASSERT_EQ(out.size(), 1u);
  EXPECT_EQ(out[0], 0xAB);
}

TEST(Common_Wire_Primitives, PutU16LittleEndian)
{
  std::vector<uint8_t> out;
  putU16(out, 0x1234);
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0], 0x34);
  EXPECT_EQ(out[1], 0x12);
}

TEST(Common_Wire_Primitives, PutU32LittleEndian)
{
  std::vector<uint8_t> out;
  putU32(out, 0x12345678u);
  ASSERT_EQ(out.size(), 4u);
  EXPECT_EQ(out[0], 0x78);
  EXPECT_EQ(out[1], 0x56);
  EXPECT_EQ(out[2], 0x34);
  EXPECT_EQ(out[3], 0x12);
}

TEST(Common_Wire_Primitives, PutU64LittleEndian)
{
  std::vector<uint8_t> out;
  putU64(out, 0x0123456789ABCDEFull);
  ASSERT_EQ(out.size(), 8u);
  EXPECT_EQ(out[0], 0xEF);
  EXPECT_EQ(out[1], 0xCD);
  EXPECT_EQ(out[2], 0xAB);
  EXPECT_EQ(out[3], 0x89);
  EXPECT_EQ(out[4], 0x67);
  EXPECT_EQ(out[5], 0x45);
  EXPECT_EQ(out[6], 0x23);
  EXPECT_EQ(out[7], 0x01);
}

TEST(Common_Wire_Primitives, PutBytesEmpty)
{
  std::vector<uint8_t> out;
  putBytes(out, nullptr, 0);
  EXPECT_TRUE(out.empty());
}

TEST(Common_Wire_Primitives, PutBytesAppends)
{
  std::vector<uint8_t> out = {0xAA, 0xBB};
  const uint8_t src[] = {0x01, 0x02, 0x03};
  putBytes(out, src, sizeof(src));

  ASSERT_EQ(out.size(), 5u);
  EXPECT_EQ(out[0], 0xAA);
  EXPECT_EQ(out[1], 0xBB);
  EXPECT_EQ(out[2], 0x01);
  EXPECT_EQ(out[3], 0x02);
  EXPECT_EQ(out[4], 0x03);
}

// ============================================================================
//  Primitives — put/read round trips
// ============================================================================

TEST(Common_Wire_Primitives, RoundTripU16)
{
  std::vector<uint8_t> out;
  putU16(out, 0xBEEF);
  EXPECT_EQ(readU16(out.data()), 0xBEEF);
}

TEST(Common_Wire_Primitives, RoundTripU32)
{
  std::vector<uint8_t> out;
  putU32(out, 0xDEADBEEFu);
  EXPECT_EQ(readU32(out.data()), 0xDEADBEEFu);
}

TEST(Common_Wire_Primitives, RoundTripU64)
{
  std::vector<uint8_t> out;
  putU64(out, 0xFEEDFACECAFEBEEFull);
  EXPECT_EQ(readU64(out.data()), 0xFEEDFACECAFEBEEFull);
}

TEST(Common_Wire_Primitives, RoundTripBoundaryValues)
{
  for (uint64_t v : {0ull, 1ull, 0x7Full, 0x80ull, 0xFFull,
                     0xFFFFull, 0xFFFFFFFFull,
                     0x7FFFFFFFFFFFFFFFull,
                     0x8000000000000000ull,
                     0xFFFFFFFFFFFFFFFFull})
  {
    std::vector<uint8_t> out;
    putU64(out, v);
    EXPECT_EQ(readU64(out.data()), v) << "value = 0x" << std::hex << v;
  }
}

// ============================================================================
//  Reader — happy path
// ============================================================================

TEST(Common_Reader, ReadsFieldsInOrder)
{
  std::vector<uint8_t> buf;
  putU8(buf, 0x01);
  putU16(buf, 0x0203);
  putU32(buf, 0x04050607u);
  putU64(buf, 0x08090A0B0C0D0E0Full);

  Reader r(buf.data(), buf.size());

  EXPECT_EQ(r.readU8(), 0x01);
  EXPECT_EQ(r.readU16(), 0x0203);
  EXPECT_EQ(r.readU32(), 0x04050607u);
  EXPECT_EQ(r.readU64(), 0x08090A0B0C0D0E0Full);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}

TEST(Common_Reader, RemainingTracksConsumption)
{
  std::vector<uint8_t> buf(16, 0);
  Reader r(buf.data(), buf.size());

  EXPECT_EQ(r.remaining(), 16u);
  r.readU8();
  EXPECT_EQ(r.remaining(), 15u);
  r.readU64();
  EXPECT_EQ(r.remaining(), 7u);
  r.readU16();
  EXPECT_EQ(r.remaining(), 5u);
}

TEST(Common_Reader, ReadBytes)
{
  std::vector<uint8_t> buf;
  putU16(buf, 0xAAAA);
  putU32(buf, 0xBBBBBBBBu);

  Reader r(buf.data(), buf.size());
  r.readU16();

  uint8_t out[4] = {};
  r.readBytes(out, 4);
  ASSERT_TRUE(r.ok());

  EXPECT_EQ(out[0], 0xBB);
  EXPECT_EQ(out[1], 0xBB);
  EXPECT_EQ(out[2], 0xBB);
  EXPECT_EQ(out[3], 0xBB);
}

TEST(Common_Reader, ReadString)
{
  std::vector<uint8_t> buf = {'h', 'e', 'l', 'l', 'o'};
  Reader r(buf.data(), buf.size());

  EXPECT_EQ(r.readString(5), "hello");
  EXPECT_TRUE(r.ok());
}

TEST(Common_Reader, ReadVector)
{
  std::vector<uint8_t> buf = {0x01, 0x02, 0x03, 0x04};
  Reader r(buf.data(), buf.size());

  auto v = r.readVector(4);
  ASSERT_TRUE(r.ok());
  ASSERT_EQ(v.size(), 4u);
  EXPECT_EQ(v[0], 0x01);
  EXPECT_EQ(v[3], 0x04);
}

TEST(Common_Reader, ReadLengthPrefixedString)
{
  std::vector<uint8_t> buf;
  putU8(buf, 5);
  putBytes(buf, reinterpret_cast<const uint8_t *>("hello"), 5);

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readLengthPrefixedString(), "hello");
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}

TEST(Common_Reader, ReadLengthPrefixedStringEmpty)
{
  std::vector<uint8_t> buf;
  putU8(buf, 0);

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readLengthPrefixedString(), "");
  EXPECT_TRUE(r.ok());
}

TEST(Common_Reader, SkipAdvancesCursor)
{
  std::vector<uint8_t> buf;
  putU8(buf, 0xAA);
  putU32(buf, 0xDEADBEEFu);
  putU8(buf, 0xBB);

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readU8(), 0xAA);
  EXPECT_TRUE(r.skip(4));
  EXPECT_EQ(r.readU8(), 0xBB);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}

// ============================================================================
//  Reader — failure modes
// ============================================================================

TEST(Common_Reader, EmptyBufferIsNotOkAfterRead)
{
  Reader r(nullptr, 0);
  EXPECT_TRUE(r.ok()); // no read yet
  EXPECT_EQ(r.remaining(), 0u);
  EXPECT_EQ(r.readU8(), 0);
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, TruncatedU16)
{
  const uint8_t buf[] = {0x01};
  Reader r(buf, 1);

  EXPECT_EQ(r.readU16(), 0);
  EXPECT_FALSE(r.ok());
  EXPECT_EQ(r.remaining(), 1u); // did not advance on failure
}

TEST(Common_Reader, TruncatedU32)
{
  const uint8_t buf[] = {0x01, 0x02, 0x03};
  Reader r(buf, 3);

  EXPECT_EQ(r.readU32(), 0);
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, TruncatedU64)
{
  const uint8_t buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  Reader r(buf, 7);

  EXPECT_EQ(r.readU64(), 0);
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, TruncatedBytes)
{
  const uint8_t buf[] = {0x01, 0x02};
  Reader r(buf, 2);

  uint8_t out[4] = {};
  r.readBytes(out, 4);
  EXPECT_FALSE(r.ok());

  // Output buffer was not written to on failure.
  EXPECT_EQ(out[0], 0);
  EXPECT_EQ(out[3], 0);
}

TEST(Common_Reader, TruncatedString)
{
  const uint8_t buf[] = {'a', 'b'};
  Reader r(buf, 2);

  EXPECT_EQ(r.readString(5), "");
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, ReadVectorChecksBeforeAllocating)
{
  // Ask for a vector larger than the buffer. The bounds check must
  // reject this without attempting to allocate the full size first.
  const uint8_t buf[] = {0x01, 0x02, 0x03};
  Reader r(buf, 3);

  auto v = r.readVector(1'000'000);
  EXPECT_TRUE(v.empty());
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, LengthPrefixedStringExceedsBuffer)
{
  // Length says 10, but only 3 bytes follow.
  std::vector<uint8_t> buf;
  putU8(buf, 10);
  putBytes(buf, reinterpret_cast<const uint8_t *>("abc"), 3);

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readLengthPrefixedString(), "");
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, LengthPrefixedStringEmptyBuffer)
{
  Reader r(nullptr, 0);
  EXPECT_EQ(r.readLengthPrefixedString(), "");
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, ErrorFlagIsSticky)
{
  const uint8_t buf[] = {0x01};
  Reader r(buf, 1);

  r.readU32(); // fails, sets error
  EXPECT_FALSE(r.ok());

  // A subsequent successful-looking read does not clear the error.
  r.readU8();
  EXPECT_FALSE(r.ok());
}

TEST(Common_Reader, SkipBeyondEnd)
{
  const uint8_t buf[] = {0x01, 0x02};
  Reader r(buf, 2);

  // shape A (returns bool) or shape B (void) — both must leave the
  // reader in the error state.
  r.skip(10);
  EXPECT_FALSE(r.ok());
}

// ============================================================================
//  Writer — happy path
// ============================================================================

TEST(Common_Writer, WritesFieldsInOrder)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeU8(0x01);
  w.writeU16(0x0203);
  w.writeU32(0x04050607u);
  w.writeU64(0x08090A0B0C0D0E0Full);

  ASSERT_EQ(buf.size(), 15u);
  EXPECT_EQ(buf[0], 0x01);
  EXPECT_EQ(buf[1], 0x03);
  EXPECT_EQ(buf[2], 0x02);
  EXPECT_EQ(buf[3], 0x07);
  EXPECT_EQ(buf[4], 0x06);
  EXPECT_EQ(buf[5], 0x05);
  EXPECT_EQ(buf[6], 0x04);
  EXPECT_EQ(buf[7], 0x0F);
  EXPECT_EQ(buf[14], 0x08);
  EXPECT_TRUE(w.ok());
}

TEST(Common_Writer, SizeTracksBuffer)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  EXPECT_EQ(w.size(), 0u);
  w.writeU32(0);
  EXPECT_EQ(w.size(), 4u);
  w.writeU64(0);
  EXPECT_EQ(w.size(), 12u);
}

TEST(Common_Writer, WriteBytes)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  const uint8_t src[] = {0x01, 0x02, 0x03, 0x04};
  w.writeBytes(src, 4);

  ASSERT_EQ(buf.size(), 4u);
  EXPECT_EQ(buf[0], 0x01);
  EXPECT_EQ(buf[3], 0x04);
}

TEST(Common_Writer, WriteBytesEmpty)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeBytes(nullptr, 0);
  EXPECT_TRUE(buf.empty());
  EXPECT_TRUE(w.ok());
}

TEST(Common_Writer, WriteString)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeString("hello");

  ASSERT_EQ(buf.size(), 5u);
  EXPECT_EQ(buf[0], 'h');
  EXPECT_EQ(buf[4], 'o');
}

TEST(Common_Writer, WriteVector)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  std::vector<uint8_t> src = {0xAA, 0xBB, 0xCC};
  w.writeVector(src);

  ASSERT_EQ(buf.size(), 3u);
  EXPECT_EQ(buf[0], 0xAA);
  EXPECT_EQ(buf[2], 0xCC);
}

TEST(Common_Writer, WriteI64Negative)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeI64(-1);
  ASSERT_EQ(buf.size(), 8u);
  for (uint8_t b : buf)
    EXPECT_EQ(b, 0xFF);
}

TEST(Common_Writer, WriteLengthPrefixedString)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeLengthPrefixedString("hello");

  ASSERT_EQ(buf.size(), 6u);
  EXPECT_EQ(buf[0], 5);
  EXPECT_EQ(buf[1], 'h');
  EXPECT_EQ(buf[5], 'o');
  EXPECT_TRUE(w.ok());
}

TEST(Common_Writer, WriteLengthPrefixedStringEmpty)
{
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeLengthPrefixedString("");
  ASSERT_EQ(buf.size(), 1u);
  EXPECT_EQ(buf[0], 0);
  EXPECT_TRUE(w.ok());
}

TEST(Common_Writer, WriteLengthPrefixedStringMax)
{
  // 255 bytes is the largest this format can represent.
  std::string s(255, 'x');
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeLengthPrefixedString(s);

  ASSERT_EQ(buf.size(), 256u);
  EXPECT_EQ(buf[0], 255);
  EXPECT_TRUE(w.ok());
}

TEST(Common_Writer, AppendToNonEmptyBuffer)
{
  std::vector<uint8_t> buf = {0xAA, 0xBB};
  Writer w(buf);

  w.writeU8(0xCC);

  ASSERT_EQ(buf.size(), 3u);
  EXPECT_EQ(buf[0], 0xAA);
  EXPECT_EQ(buf[1], 0xBB);
  EXPECT_EQ(buf[2], 0xCC);
}

// ============================================================================
//  Writer — failure modes
// ============================================================================

TEST(Common_Writer, LengthPrefixedStringOver255)
{
  // 256 bytes exceeds the u8 length prefix, must set error.
  std::string s(256, 'x');
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeLengthPrefixedString(s);

  EXPECT_FALSE(w.ok());
  EXPECT_TRUE(buf.empty()); // nothing written on failure
}

TEST(Common_Writer, ErrorFlagIsSticky)
{
  std::string s(256, 'x');
  std::vector<uint8_t> buf;
  Writer w(buf);

  w.writeLengthPrefixedString(s);
  EXPECT_FALSE(w.ok());

  // Subsequent successful-looking writes do not clear the error.
  w.writeU8(0x01);
  EXPECT_FALSE(w.ok());
}

// ============================================================================
//  Reader/Writer round trips
// ============================================================================

TEST(Common_Wire_RoundTrip, AllPrimitiveWidths)
{
  std::vector<uint8_t> buf;
  {
    Writer w(buf);
    w.writeU8(0x12);
    w.writeU16(0x3456);
    w.writeU32(0x789ABCDEu);
    w.writeU64(0xF0123456789ABCDEull);
  }

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readU8(), 0x12);
  EXPECT_EQ(r.readU16(), 0x3456);
  EXPECT_EQ(r.readU32(), 0x789ABCDEu);
  EXPECT_EQ(r.readU64(), 0xF0123456789ABCDEull);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}

TEST(Common_Wire_RoundTrip, LengthPrefixedString)
{
  const std::string original = "The quick brown fox";
  std::vector<uint8_t> buf;
  {
    Writer w(buf);
    w.writeLengthPrefixedString(original);
  }

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readLengthPrefixedString(), original);
  EXPECT_TRUE(r.ok());
}

TEST(Common_Wire_RoundTrip, BinaryBlob)
{
  std::vector<uint8_t> original;
  for (int i = 0; i < 256; ++i)
    original.push_back(static_cast<uint8_t>(i));

  std::vector<uint8_t> buf;
  {
    Writer w(buf);
    w.writeU32(static_cast<uint32_t>(original.size()));
    w.writeVector(original);
  }

  Reader r(buf.data(), buf.size());
  const uint32_t n = r.readU32();
  ASSERT_TRUE(r.ok());
  ASSERT_EQ(n, 256u);
  const auto decoded = r.readVector(n);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(decoded, original);
}

TEST(Common_Wire_RoundTrip, SignedI64)
{
  for (int64_t v : {int64_t(0), int64_t(1), int64_t(-1),
                    int64_t(0x7FFFFFFFFFFFFFFFll),
                    int64_t(-0x7FFFFFFFFFFFFFFFll - 1)})
  {
    std::vector<uint8_t> buf;
    {
      Writer w(buf);
      w.writeI64(v);
    }
    Reader r(buf.data(), buf.size());
    EXPECT_EQ(r.readI64(), v) << "value = " << v;
    EXPECT_TRUE(r.ok());
  }
}

TEST(Common_Wire_RoundTrip, MixedFields)
{
  const uint16_t version = 3;
  const uint64_t chain_id = 0x434C5247;
  const std::string label = "acct-1";
  const uint64_t balance = 1'000'000'000;
  const bool flag = true;

  std::vector<uint8_t> buf;
  {
    Writer w(buf);
    w.writeU16(version);
    w.writeU64(chain_id);
    w.writeLengthPrefixedString(label);
    w.writeU64(balance);
    w.writeU8(flag ? 1 : 0);
  }

  Reader r(buf.data(), buf.size());
  EXPECT_EQ(r.readU16(), version);
  EXPECT_EQ(r.readU64(), chain_id);
  EXPECT_EQ(r.readLengthPrefixedString(), label);
  EXPECT_EQ(r.readU64(), balance);
  EXPECT_EQ(r.readU8() != 0, flag);
  EXPECT_TRUE(r.ok());
  EXPECT_EQ(r.remaining(), 0u);
}

// ============================================================================
//  Independence — Reader and Writer do not share state across instances
// ============================================================================

TEST(Common_Wire, TwoReadersAreIndependent)
{
  const uint8_t buf_a[] = {0x01, 0x02};
  const uint8_t buf_b[] = {0xAA, 0xBB};

  Reader ra(buf_a, 2);
  Reader rb(buf_b, 2);

  EXPECT_EQ(ra.readU8(), 0x01);
  EXPECT_EQ(rb.readU8(), 0xAA);
  EXPECT_EQ(ra.readU8(), 0x02);
  EXPECT_EQ(rb.readU8(), 0xBB);
  EXPECT_TRUE(ra.ok());
  EXPECT_TRUE(rb.ok());
}

TEST(Common_Wire, TwoWritersAreIndependent)
{
  std::vector<uint8_t> buf_a;
  std::vector<uint8_t> buf_b;

  Writer wa(buf_a);
  Writer wb(buf_b);

  wa.writeU8(0x01);
  wb.writeU8(0xAA);
  wa.writeU8(0x02);
  wb.writeU8(0xBB);

  ASSERT_EQ(buf_a.size(), 2u);
  ASSERT_EQ(buf_b.size(), 2u);
  EXPECT_EQ(buf_a[0], 0x01);
  EXPECT_EQ(buf_a[1], 0x02);
  EXPECT_EQ(buf_b[0], 0xAA);
  EXPECT_EQ(buf_b[1], 0xBB);
}