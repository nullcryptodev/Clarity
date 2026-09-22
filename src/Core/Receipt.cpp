// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Receipt.h"

#include <cstring>

namespace Core
{

  std::vector<uint8_t> Receipt::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    out.push_back(static_cast<uint8_t>(status));

    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(fee_paid >> (i * 8)));

    return out;
  }

  bool Receipt::deserializeState(const uint8_t *data, size_t len, Receipt &out)
  {
    if (len < STATE_SIZE)
      return false;

    out.status = static_cast<ReceiptStatus>(data[0]);

    uint64_t fee = 0;
    for (int i = 0; i < 8; ++i)
      fee |= uint64_t(data[1 + i]) << (i * 8);
    out.fee_paid = fee;

    return out.isValid();
  }

  void Receipt::serialize(Serialization::ISerializer &s)
  {
    uint8_t st = static_cast<uint8_t>(status);
    s(st, "status");
    s(fee_paid, "fee_paid");
  }

  void Receipt::serialize(Serialization::ISerializer &s) const
  {
    s(status, "status");
    s(fee_paid, "fee_paid");
  }

} // namespace Core