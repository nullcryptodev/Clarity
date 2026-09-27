// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ChainMethods.h"
#include "Methods.h"

#include "Encoders/BlockEncoder.h"
#include "Encoders/Encoding.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"

#include "Core/Chain.h"
#include "Core/ChainDB.h"
#include "Node/Node.h"

namespace Rpc
{

  namespace
  {
    // ---- clrty_chainId ----

    Common::Json method_chainId(Node::Node &node, const RpcConfig & /*config*/,
                                const JsonRpcRequest &req)
    {
      Common::Json j = Common::Json::object();
      putU64(j, "chain_id", node.status().chain_id);
      return j;
    }

    // ---- clrty_blockNumber ----

    Common::Json method_blockNumber(Node::Node &node, const RpcConfig & /*config*/,
                                    const JsonRpcRequest &req)
    {
      Common::Json j = Common::Json::object();
      putU64(j, "height", node.chain().height());
      return j;
    }

    // ---- clrty_getBlockByNumber ----
    //
    // Params:
    //   height  (required, hex or decimal)
    //   full    (optional, bool, default false)

    Common::Json method_getBlockByNumber(Node::Node &node, const RpcConfig & /*config*/,
                                         const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");
      const bool full = optionalBool(req.params, "full").value_or(false);

      auto block = node.chain().getBlockByHeight(height);
      if (!block)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no block at height " + encodeU64Hex(height),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"height", encodeU64Hex(height)}}));
      }

      return encodeBlock(*block, full, hrpForNode(node));
    }

    // ---- clrty_getBlockByHash ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //   full  (optional, bool, default false)

    Common::Json method_getBlockByHash(Node::Node &node, const RpcConfig & /*config*/,
                                       const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");
      const bool full = optionalBool(req.params, "full").value_or(false);

      auto block = node.chain().getBlock(hash);
      if (!block)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no block with hash " + encodeHash(hash),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      return encodeBlock(*block, full, hrpForNode(node));
    }

    // ---- clrty_getBlockHeaderByNumber ----

    Common::Json method_getBlockHeaderByNumber(Node::Node &node, const RpcConfig & /*config*/,
                                               const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

      auto header = node.chainDB().getHeaderByHeight(height);
      if (!header)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no header at height " + encodeU64Hex(height),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"height", encodeU64Hex(height)}}));
      }

      return encodeBlockHeader(*header, hrpForNode(node));
    }

    // ---- clrty_getStateRoot ----
    //
    // Returns the state root at a given height. Uses the SMT's
    // rootAtVersion, which stores roots keyed by height. Only roots
    // that were committed with `save(version)` are retrievable; the
    // node commits a root per block, so this works for any height
    // that has been processed.
    //
    // NOTE: does NOT return the state *at* that height in the sense of
    // querying accounts as of then. Historical state reads are not
    // supported (see ErrorCode::HistoricalQueryNotSupported). This
    // method returns the root only, for proof verification.

    Common::Json method_getStateRoot(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

      // Open a throwaway StateAccess to read the historical root.
      // We don't need a txn — this is a read.
      State::StateAccess access(node.stateDB(), height);
      auto root = access.smtRootAtVersion(height);

      Common::Json j = Common::Json::object();
      putU64(j, "height", height);

      if (!root)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no committed state root at height " + encodeU64Hex(height),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"height", encodeU64Hex(height)}}));
      }

      putHash(j, "state_root", *root);
      return j;
    }
  } // anonymous namespace

  //  Registration

  void registerChainMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_chainId", method_chainId);
    d.registerMethod("clrty_blockNumber", method_blockNumber);
    d.registerMethod("clrty_getBlockByNumber", method_getBlockByNumber);
    d.registerMethod("clrty_getBlockByHash", method_getBlockByHash);
    d.registerMethod("clrty_getBlockHeaderByNumber", method_getBlockHeaderByNumber);
    d.registerMethod("clrty_getStateRoot", method_getStateRoot);
  }

} // namespace Rpc