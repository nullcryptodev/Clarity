// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TxEncoder.h"

#include "Core/TransactionTypes.h"
#include "Encoding.h"

namespace Rpc
{

  Common::Json encodeTransaction(const Core::Transaction &tx,
                                 const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putHash(j, "hash", tx.txid());
    j["version"] = static_cast<uint32_t>(tx.version);
    putU64(j, "chain_id", tx.chain_id);

    // Type as a stable string and a stable number. The two must agree.
    j["type"] = std::string(Core::txTypeName(tx.tx_type));
    j["type_code"] = static_cast<uint32_t>(tx.tx_type);

    putU64(j, "nonce", tx.nonce);
    putU64(j, "valid_until_height", tx.valid_until_height);
    putAddress(j, "from", tx.from, hrp);
    putAddress(j, "to", tx.to, hrp);
    putU64(j, "token_id", tx.token_id);
    putU64(j, "amount", tx.amount);
    putU64(j, "fee", tx.fee);
    putBytes(j, "payload", tx.payload);
    putSignature(j, "signature", tx.signature);

    return j;
  }

  Common::Json encodeReceipt(const Core::Receipt &r)
  {
    Common::Json j = Common::Json::object();

    switch (r.status)
    {
    case Core::ReceiptStatus::Success:
      j["status"] = "success";
      break;
    case Core::ReceiptStatus::Failure:
      j["status"] = "failure";
      break;
    }
    j["status_code"] = static_cast<uint32_t>(r.status);
    putU64(j, "fee_paid", r.fee_paid);

    return j;
  }

} // namespace Rpc