// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TxMethods.h"

#include "Encoders/Encoding.h"
#include "Encoders/TxEncoder.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"

#include "Core/Chain.h"
#include "Core/ChainDB.h"
#include "Core/StateView.h"
#include "Core/TransactionExecutor.h"
#include "Node/Node.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

namespace Rpc
{

  namespace
  {
    // ---- Helpers ----

    // Deserialize a hex-encoded transaction. Throws RpcMethodError on
    // any failure so every call site gets the same error semantics.
    Core::Transaction parseTxHex(const std::string &hex)
    {
      std::vector<uint8_t> bytes;
      if (!parseBytesHex(hex, bytes))
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'tx' must be 0x-prefixed even-length hex",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "tx"}}));
      }

      if (bytes.empty())
      {
        throw RpcMethodError(
            ErrorCode::TxMalformed,
            "transaction bytes are empty");
      }

      Core::Transaction tx;
      if (!Core::Transaction::deserialize(bytes.data(), bytes.size(), tx))
      {
        throw RpcMethodError(
            ErrorCode::TxMalformed,
            "transaction failed to deserialize");
      }

      return tx;
    }

    // Build the extra data for a mempool rejection. Includes the txid
    // so the client can correlate its submission with the error, even
    // though it could compute the hash itself.
    Common::Json rejectionData(const Core::Transaction &tx,
                               const std::string &error)
    {
      Common::Json d = Common::Json::object();
      d["tx_hash"] = encodeHash(tx.txid());
      if (!error.empty())
        d["reason"] = error;
      return d;
    }

    // ---- clrty_sendRawTransaction ----
    //
    // Params:
    //   tx  (required, 0x-prefixed hex of a serialized signed Transaction)
    //
    // Returns on success:
    //   { "tx_hash": "0x...", "accepted": true }
    //
    // On mempool rejection: throws RpcMethodError with the code
    // mapped from MempoolAddResult, and data = {tx_hash, reason}.

    Common::Json method_sendRawTransaction(Node::Node &node, const RpcConfig & /*config*/,
                                           const JsonRpcRequest &req)
    {
      const std::string tx_hex = requireString(req.params, "tx");
      Core::Transaction tx = parseTxHex(tx_hex);

      std::string error;
      Core::MempoolAddResult result = node.submitTransaction(tx, error);

      if (result != Core::MempoolAddResult::Accepted)
      {
        ErrorCode code = mempoolResultToErrorCode(result);
        throw RpcMethodError(
            code,
            error.empty() ? nullptr : error.c_str(),
            makeErrorData(code, rejectionData(tx, error)));
      }

      Common::Json out = Common::Json::object();
      putHash(out, "tx_hash", tx.txid());
      out["accepted"] = true;
      return out;
    }

    // ---- clrty_getTransactionByHash ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //
    // Returns the transaction with its location if it exists either
    // in the mempool or in a committed block. `status` is one of
    // "pending" or "confirmed". For pending txs, the block fields
    // are null.

    Common::Json method_getTransactionByHash(Node::Node &node, const RpcConfig & /*config*/,
                                             const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");
      const std::string hrp = hrpForNode(node);

      // ---- Mempool first ----
      auto pending = node.mempool().get(hash);
      if (pending.has_value())
      {
        Common::Json out = Common::Json::object();
        out["tx"] = encodeTransaction(*pending, hrp);
        out["status"] = "pending";
        out["block_hash"] = nullptr;
        out["block_height"] = nullptr;
        out["index"] = nullptr;
        return out;
      }

      // ---- Committed ----
      auto loc = node.chainDB().getTxLocation(hash);
      if (!loc.has_value())
      {
        throw RpcMethodError(
            ErrorCode::TransactionNotFound,
            "transaction not found in mempool or chain",
            makeErrorData(ErrorCode::TransactionNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      auto block = node.chain().getBlock(loc->block_hash);
      if (!block.has_value())
      {
        // Tx index points to a block we don't have. Chain and index
        // are out of sync — this is an internal inconsistency.
        throw RpcMethodError(
            ErrorCode::ChainReadInternal,
            "tx index references a block that is not stored",
            makeErrorData(ErrorCode::ChainReadInternal,
                          {{"block_hash", encodeHash(loc->block_hash)}}));
      }

      if (loc->tx_index >= block->transactions.size())
      {
        throw RpcMethodError(
            ErrorCode::ChainReadInternal,
            "tx index points past the end of the block",
            makeErrorData(ErrorCode::ChainReadInternal,
                          {{"index", loc->tx_index},
                           {"tx_count", block->transactions.size()}}));
      }

      const Core::Transaction &tx = block->transactions[loc->tx_index];

      Common::Json out = Common::Json::object();
      out["tx"] = encodeTransaction(tx, hrp);
      out["status"] = "confirmed";
      putHash(out, "block_hash", loc->block_hash);
      putU64(out, "block_height", loc->block_height);
      out["index"] = loc->tx_index;
      return out;
    }

    // ---- clrty_getTransactionReceipt ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //
    // Returns the consensus receipt (status + fee_paid) plus the
    // block position. This is NOT a full Ethereum-style receipt:
    // there are no logs, no gas, no return data. See Receipt.h.

    Common::Json method_getTransactionReceipt(Node::Node &node, const RpcConfig & /*config*/,
                                              const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");

      auto loc = node.chainDB().getTxLocation(hash);
      if (!loc.has_value())
      {
        throw RpcMethodError(
            ErrorCode::ReceiptNotFound,
            "no receipt: transaction is not confirmed",
            makeErrorData(ErrorCode::ReceiptNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      State::StateAccess state(node.stateDB(), loc->block_height);
      Core::Receipt receipt;
      if (!state.getReceipt(hash, receipt))
      {
        // Tx index says it's in this block, but no receipt exists.
        // This can happen if the block was committed before the
        // receipt was written. In practice they're written in the
        // same txn, so this is an internal inconsistency.
        throw RpcMethodError(
            ErrorCode::ReceiptNotFound,
            "tx index has the transaction but no receipt is stored",
            makeErrorData(ErrorCode::ReceiptNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      Common::Json out = encodeReceipt(receipt);
      putHash(out, "tx_hash", hash);
      putHash(out, "block_hash", loc->block_hash);
      putU64(out, "block_height", loc->block_height);
      out["index"] = loc->tx_index;
      return out;
    }

    // ---- clrty_simulateTransaction ----
    //
    // Params:
    //   tx  (required, 0x-prefixed hex)
    //
    // Executes the tx against a throwaway state txn and returns the
    // resulting receipt. Nothing is persisted. Useful for wallets
    // that want to check "would this succeed?" before broadcasting.
    //
    // Caveats:
    //   - Uses the chain head as the state context. No `height`
    //     parameter yet; add later if simulations need to run against
    //     a specific block.
    //   - Holds a write txn for the duration. Two concurrent calls
    //     will serialize — the second throws because beginWrite fails
    //     with MDBX_BUSY. The dispatcher maps that to InternalError.
    //   - The receipt reflects the executor's outcome, which includes
    //     the fee charge before dispatch. On success, fee_paid equals
    //     tx.fee. On failure, it usually still equals tx.fee (the
    //     executor always charges the fee).

    Common::Json method_simulateTransaction(Node::Node &node, const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const std::string tx_hex = requireString(req.params, "tx");
      Core::Transaction tx = parseTxHex(tx_hex);

      const uint64_t height = node.chain().height();
      const uint64_t chain_id = node.status().chain_id;

      // The throwaway txn. Everything inside is discarded by abort().
      State::StateDB::Txn txn = node.stateDB().beginWrite();

      Core::Receipt receipt;
      try
      {
        State::StateAccess state(node.stateDB(), txn, height);

        Core::TxExecutionContext ctx;
        ctx.current_height = height;
        ctx.chain_id = chain_id;
        ctx.tx_index_in_block = 0;

        receipt = Core::TransactionExecutor::execute(state, tx, ctx);

        // Whether we throw or not, we never commit.
        txn.abort();
      }
      catch (...)
      {
        // Ensure the txn is discarded even if execute threw.
        txn.abort();
        throw;
      }

      Common::Json out = encodeReceipt(receipt);
      putHash(out, "tx_hash", tx.txid());
      putU64(out, "height", height);
      return out;
    }

  } // anonymous namespace

  void registerTxMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_sendRawTransaction", method_sendRawTransaction);
    d.registerMethod("clrty_getTransactionByHash", method_getTransactionByHash);
    d.registerMethod("clrty_getTransactionReceipt", method_getTransactionReceipt);
    d.registerMethod("clrty_simulateTransaction", method_simulateTransaction);
  }

} // namespace Rpc