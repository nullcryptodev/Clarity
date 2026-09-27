// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/Json.h"
#include "Core/Receipt.h"
#include "Core/Transaction.h"

namespace Rpc
{
  //  Transaction -> JSON
  //
  //  The Transaction struct's own `serialize(ISerializer&)` produces an
  //  opaque binary blob (see Transaction.h's free serialize functions
  //  and the Transaction::serialize overload that wraps it). We cannot
  //  reuse it for a structured JSON response, so this encoder
  //  hand-writes each field.
  //
  //  Fields:
  //    hash           (0x-prefixed; txid == signingHash)
  //    version        (number)
  //    chain_id       (hex string)
  //    type           (string name; "Transfer", "Swap", etc.)
  //    type_code      (0x-prefixed byte)
  //    nonce          (hex string)
  //    valid_until_height (hex string; 0 means "no expiry")
  //    from           (Bech32m)
  //    to             (Bech32m)
  //    token_id       (hex string)
  //    amount         (hex string)
  //    fee            (hex string)
  //    payload        (0x-prefixed hex)
  //    signature      (0x-prefixed hex)
  //
  //  `type_code` is included alongside the human-readable `type` so
  //  clients can switch on a stable numeric identifier without
  //  string-comparing. The two are always consistent.

  Common::Json encodeTransaction(const Core::Transaction &tx,
                                 const std::string &hrp);

  //  Receipt -> JSON
  //
  //  The consensus Receipt is 9 bytes: status + fee_paid. It has no
  //  logs, no gas, no return data. See Receipt.h. Node-local
  //  full receipts, if any, are stored separately and are not exposed
  //  through this encoder.
  //
  //  Fields:
  //    status      (string: "success" | "failure")
  //    status_code (number: 0 | 1)
  //    fee_paid    (hex string)

  Common::Json encodeReceipt(const Core::Receipt &r);
}