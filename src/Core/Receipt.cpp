// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Receipt.h"

#include "Common/Wire.h"
#include "OrderBook.h"

#include <cstring>
#include <string>

namespace Core
{
  namespace
  {
    //  A single taker crosses at most MAX_BOOK_LEVELS_PER_TAKER
    //  resting orders (see Core/OrderBook.h). A receipt claiming
    //  more fills than that is malformed. Reject it before the
    //  decoder allocates anything, so a hostile 4-byte count cannot
    //  turn into a multi-megabyte allocation.
    //
    //  Cast through uint32_t so the constant lives in one place
    //  (OrderBook.h) and the receipt codec tracks it automatically
    //  if the matcher's cap ever changes.
    constexpr uint32_t MAX_FILLS_PER_RECEIPT =
        static_cast<uint32_t>(OrderBook::MAX_BOOK_LEVELS_PER_TAKER);

    //  The legacy receipt had no fills. A decoder that sees exactly
    //  STATE_SIZE bytes is reading a receipt from before the fills
    //  field existed; it must accept it and leave `out.fills` empty
    //  rather than reject it, or a replay of an old block fails.
    constexpr size_t STATE_SIZE_LEGACY = Receipt::STATE_SIZE;
  } // anonymous namespace

  // =================================================================
  //  State codec
  //
  //  Layout:
  //    [1]  status
  //    [8]  fee_paid
  //    [4]  fill_count (u32 LE)
  //    [N]  fills, each Fill::STATE_SIZE bytes
  //
  //  A receipt with no fills still writes the 4-byte zero count.
  //  The legacy form (no fill_count at all) is accepted on decode
  //  for backward compatibility; see deserializeState.
  // =================================================================

  std::vector<uint8_t> Receipt::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE + 4 + fills.size() * Fill::STATE_SIZE);

    out.push_back(static_cast<uint8_t>(status));

    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(fee_paid >> (i * 8)));

    //  Fill count, u32 LE.
    const uint32_t count = static_cast<uint32_t>(fills.size());
    out.push_back(uint8_t(count));
    out.push_back(uint8_t(count >> 8));
    out.push_back(uint8_t(count >> 16));
    out.push_back(uint8_t(count >> 24));

    //  Fills.
    for (const auto &f : fills)
    {
      const auto bytes = f.serializeState();
      out.insert(out.end(), bytes.begin(), bytes.end());
    }

    return out;
  }

  bool Receipt::deserializeState(const uint8_t *data, size_t len, Receipt &out)
  {
    out.fills.clear();

    //  Legacy form: exactly the fixed header, no fill section.
    if (len == STATE_SIZE_LEGACY)
    {
      out.status = static_cast<ReceiptStatus>(data[0]);

      uint64_t fee = 0;
      for (int i = 0; i < 8; ++i)
        fee |= uint64_t(data[1 + i]) << (i * 8);
      out.fee_paid = fee;

      return out.isValid();
    }

    //  Current form: header + 4-byte count + N * Fill::STATE_SIZE.
    if (len < STATE_SIZE_LEGACY + 4)
      return false;

    out.status = static_cast<ReceiptStatus>(data[0]);

    uint64_t fee = 0;
    for (int i = 0; i < 8; ++i)
      fee |= uint64_t(data[1 + i]) << (i * 8);
    out.fee_paid = fee;

    uint32_t count = uint32_t(data[9]) |
                     (uint32_t(data[10]) << 8) |
                     (uint32_t(data[11]) << 16) |
                     (uint32_t(data[12]) << 24);

    if (count > MAX_FILLS_PER_RECEIPT)
      return false;

    const size_t expected =
        STATE_SIZE_LEGACY + 4 + static_cast<size_t>(count) * Fill::STATE_SIZE;

    //  Strict length check: no trailing bytes. A receipt whose
    //  length is not exactly what its fill count implies is
    //  malformed; reject it rather than ignoring the surplus, so a
    //  future format extension cannot silently be read as a
    //  shorter receipt with garbage past the end.
    if (len != expected)
      return false;

    out.fills.reserve(count);

    size_t off = STATE_SIZE_LEGACY + 4;

    for (uint32_t i = 0; i < count; ++i)
    {
      Fill f;
      if (!Fill::deserializeState(data + off, Fill::STATE_SIZE, f))
        return false;
      out.fills.push_back(f);
      off += Fill::STATE_SIZE;
    }

    return out.isValid();
  }

  // =================================================================
  //  Framework serialization
  //
  //  The framework form is used by the mempool and by any node-local
  //  store that round-trips a Receipt through ISerializer. The
  //  consensus commitment is over serializeState(), not this — the
  //  two must stay in lockstep, and a test asserts it.
  // =================================================================

  void Receipt::serialize(Serialization::ISerializer &s)
  {
    uint8_t st = static_cast<uint8_t>(status);
    s(st, "status");
    s(fee_paid, "fee_paid");

    uint32_t count = static_cast<uint32_t>(fills.size());
    s(count, "fill_count");

    for (uint32_t i = 0; i < count; ++i)
    {
      //  The serializer is templated on concrete types; it does
      //  not know about Fill. Emit each fill's state bytes as an
      //  opaque blob with a per-index name, so the field names in
      //  a JSON dump are stable and greppable.
      auto bytes = fills[i].serializeState();
      std::string name = "fill_" + std::to_string(i);
      s(bytes, name);
    }
  }

  void Receipt::serialize(Serialization::ISerializer &s) const
  {
    uint8_t st = static_cast<uint8_t>(status);
    s(st, "status");
    s(fee_paid, "fee_paid");

    uint32_t count = static_cast<uint32_t>(fills.size());
    s(count, "fill_count");

    for (uint32_t i = 0; i < count; ++i)
    {
      auto bytes = fills[i].serializeState();
      std::string name = "fill_" + std::to_string(i);
      s(bytes, name);
    }
  }

} // namespace Core