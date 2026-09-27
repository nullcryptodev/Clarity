// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "MempoolMethods.h"

#include "Encoders/Encoding.h"
#include "Encoders/TxEncoder.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"

#include "Core/Mempool.h"
#include "Node/Node.h"

namespace Rpc
{

  namespace
  {
    // ---- clrty_getMempoolStats ----
    //
    // No params.
    //
    // Returns a snapshot of the mempool's size and fee distribution.
    // The `stats()` call takes the mempool's internal mutex and
    // iterates the pool; under a full mempool this is O(n). Callers
    // that poll this frequently should do so at a low rate.

    Common::Json method_getMempoolStats(Node::Node &node, const RpcConfig & /*config*/,
                                        const JsonRpcRequest &/*req*/)
    {
      Core::Mempool::Stats s = node.mempool().stats();

      Common::Json out = Common::Json::object();
      putU64(out, "total_txs", static_cast<uint64_t>(s.total_txs));
      putU64(out, "priority_txs", static_cast<uint64_t>(s.priority_txs));
      putU64(out, "standard_txs", static_cast<uint64_t>(s.standard_txs));
      putU64(out, "total_bytes", static_cast<uint64_t>(s.total_bytes));
      putU64(out, "min_fee_rate", s.min_fee_rate);
      putU64(out, "max_fee_rate", s.max_fee_rate);
      putU64(out, "avg_fee_rate", s.avg_fee_rate);
      return out;
    }

    // ---- clrty_getMempoolTx ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //
    // Returns the tx if it's in the mempool, or null if not. Unlike
    // clrty_getTransactionByHash, this does NOT fall back to the
    // chain — a miss means "not pending right now."

    Common::Json method_getMempoolTx(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");

      auto tx = node.mempool().get(hash);
      if (!tx.has_value())
      {
        return Common::Json(nullptr);
      }

      return encodeTransaction(*tx, hrpForNode(node));
    }

  } // anonymous namespace

  void registerMempoolMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_getMempoolStats", method_getMempoolStats);
    d.registerMethod("clrty_getMempoolTx", method_getMempoolTx);
  }

} // namespace Rpc