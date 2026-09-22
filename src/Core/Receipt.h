// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Types.h"
#include "Serialization/ISerializer.h"

namespace Core
{
  //  Receipt
  //
  //  Result of executing a transaction. Committed to in the block via
  //  `receipts_root`, which is a Merkle tree over Blake2b(receipt data).
  //
  //  The consensus receipt is intentionally minimal: only the status and
  //  fee paid. Everything else (logs, gas, return data) is either
  //  derivable from the transaction or a future extension.
  //
  //  Node-local full receipts (with logs, etc.) are stored separately
  //  and are not part of consensus.
  //
  //  Status values:
  //    0 = Success  (transaction applied cleanly)
  //    1 = Failure  (rejected during execution; only fee charged)
  //
  //  Fee paid may differ from tx.fee in future versions if fee refunds
  //  are ever introduced. For now, fee_paid == tx.fee on success, and
  //  fee_paid == tx.fee on failure (fee is always fully charged).

  enum class ReceiptStatus : uint8_t
  {
    Success = 0,
    Failure = 1,
  };

  struct Receipt
  {
    ReceiptStatus status{ReceiptStatus::Success};
    uint64_t fee_paid{0};

    // ---- Validation ----
    bool isValid() const noexcept
    {
      return status == ReceiptStatus::Success || status == ReceiptStatus::Failure;
    }

    // ---- State serialization (fixed 9 bytes) ----
    //
    // Layout:
    //   [1]  status
    //   [8]  fee_paid

    std::vector<uint8_t> serializeState() const;

    static bool deserializeState(const uint8_t *data, size_t len,
                                 Receipt &out);

    static constexpr size_t STATE_SIZE = 1 + 8;

    // ---- Framework serialization ----

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core