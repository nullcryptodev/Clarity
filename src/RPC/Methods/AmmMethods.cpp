// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AmmMethods.h"

#include "Encoders/AmmEncoder.h"
#include "Encoders/Encoding.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"

#include "Core/Chain.h"
#include "Node/Node.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

namespace Rpc
{

  namespace
  {
    // ---- clrty_getPool ----
    //
    // Params:
    //   pool_id  (required, hex)
    //
    // Returns the pool record.

    Common::Json method_getPool(Node::Node &node, const RpcConfig & /*config*/,
                                const JsonRpcRequest &req)
    {
      const Id pool_id = requireU64(req.params, "pool_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::AmmPool pool;
      if (!state.getAmmPool(pool_id, pool))
      {
        throw RpcMethodError(
            ErrorCode::PoolNotFound,
            "no pool with id " + encodeU64Hex(pool_id),
            makeErrorData(ErrorCode::PoolNotFound,
                          {{"pool_id", encodeU64Hex(pool_id)}}));
      }

      return encodeAmmPool(pool, hrp);
    }

    // ---- clrty_getPosition ----
    //
    // Params:
    //   position_id  (required, hex)
    //
    // Returns the position record plus the owning pool's share
    // calculation.

    Common::Json method_getPosition(Node::Node &node, const RpcConfig & /*config*/,
                                    const JsonRpcRequest &req)
    {
      const Id pos_id = requireU64(req.params, "position_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::AmmPosition pos;
      if (!state.getAmmPosition(pos_id, pos))
      {
        throw RpcMethodError(
            ErrorCode::PoolNotFound,
            "no position with id " + encodeU64Hex(pos_id),
            makeErrorData(ErrorCode::PoolNotFound,
                          {{"position_id", encodeU64Hex(pos_id)}}));
      }

      // Load the pool for share computation. Not fatal if missing.
      Core::AmmPool pool;
      bool have_pool = state.getAmmPool(pos.pool_id, pool);

      return encodeAmmPosition(pos, have_pool ? &pool : nullptr, hrp);
    }

    // ---- clrty_getPositionByOwner ----
    //
    // Params:
    //   address  (required, Bech32m or hex)
    //   pool_id  (required, hex)
    //
    // Returns the position owned by `address` in `pool_id`, if any.
    // Uses the (owner, pool_id) index, which enforces one position
    // per (owner, pool).

    Common::Json method_getPositionByOwner(Node::Node &node, const RpcConfig & /*config*/,
                                           const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address owner = requireAddress(req.params, "address", hrp);
      const Id pool_id = requireU64(req.params, "pool_id");
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      uint64_t pos_id = 0;
      if (!state.getPositionIndex(owner, pool_id, pos_id))
      {
        throw RpcMethodError(
            ErrorCode::PoolNotFound,
            "no position for this address in this pool",
            makeErrorData(ErrorCode::PoolNotFound,
                          {{"address", encodeAddress(owner, hrp)},
                           {"pool_id", encodeU64Hex(pool_id)}}));
      }

      Core::AmmPosition pos;
      if (!state.getAmmPosition(pos_id, pos))
      {
        // Index points at a position that doesn't exist. Internal
        // inconsistency.
        throw RpcMethodError(
            ErrorCode::StateReadInternal,
            "position index references a missing position",
            makeErrorData(ErrorCode::StateReadInternal,
                          {{"position_id", encodeU64Hex(pos_id)}}));
      }

      Core::AmmPool pool;
      bool have_pool = state.getAmmPool(pos.pool_id, pool);

      return encodeAmmPosition(pos, have_pool ? &pool : nullptr, hrp);
    }

  } // anonymous namespace

  void registerAmmMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_getPool", method_getPool);
    d.registerMethod("clrty_getPosition", method_getPosition);
    d.registerMethod("clrty_getPositionByOwner", method_getPositionByOwner);
  }

} // namespace Rpc