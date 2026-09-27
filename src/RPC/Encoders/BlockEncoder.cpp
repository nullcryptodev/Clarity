// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BlockEncoder.h"
#include "Encoding.h"
#include "TxEncoder.h"

namespace Rpc
{

  Common::Json encodeBlockHeader(const Core::BlockHeader &header,
                                 const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putHash(j, "hash", header.hash());
    j["version"] = static_cast<uint32_t>(header.version);
    j["chain_id"] = static_cast<uint64_t>(header.chain_id);

    putU64(j, "height", header.height);
    putHash(j, "parent_hash", header.parent_hash);
    putU64(j, "timestamp_ms", header.timestamp_ms);
    putAddress(j, "proposer", header.proposer, hrp);

    putU64(j, "epoch", header.epoch);
    putU64(j, "rotation_index", header.rotation_index);
    putU64(j, "commit_round", header.commit_round);

    putHash(j, "state_root", header.state_root);
    putHash(j, "tx_root", header.tx_root);
    putHash(j, "receipts_root", header.receipts_root);
    putHash(j, "validator_set_root", header.validator_set_root);

    putU64(j, "total_fees", header.total_fees);
    j["tx_count"] = header.tx_count;
    j["active_validator_count"] = header.active_validator_count;

    return j;
  }

  Common::Json encodeBlock(const Core::Block &block,
                           bool include_transactions,
                           const std::string &hrp)
  {
    Common::Json j = encodeBlockHeader(block.header, hrp);

    Common::Json txs = Common::Json::array();
    if (include_transactions)
    {
      for (const auto &tx : block.transactions)
        txs.push_back(encodeTransaction(tx, hrp));
    }
    else
    {
      for (const auto &tx : block.transactions)
        txs.push_back(encodeHash(tx.txid()));
    }
    j["transactions"] = std::move(txs);

    Common::Json parts = Common::Json::array();
    for (Id vid : block.participants)
      parts.push_back(encodeU64Hex(vid));
    j["participants"] = std::move(parts);

    // Quorum signatures: exposed but not primary. Clients that need
    // them for verification get them; clients that don't, ignore them.
    Common::Json sigs = Common::Json::array();
    for (const auto &qs : block.quorum_signatures)
    {
      Common::Json s = Common::Json::object();
      s["signer_index"] = qs.signer_index;
      putSignature(s, "signature", qs.signature);
      sigs.push_back(std::move(s));
    }
    j["quorum_signatures"] = std::move(sigs);

    return j;
  }

} // namespace Rpc