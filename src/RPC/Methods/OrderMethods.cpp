// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "OrderMethods.h"

#include "Encoders/Encoding.h"
#include "Encoders/OrderEncoder.h"
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
    // ---- clrty_getOrder ----
    //
    // Params:
    //   order_id  (required, hex)
    //
    // Returns the order record.

    Common::Json method_getOrder(Node::Node &node, const RpcConfig & /*config*/,
                                 const JsonRpcRequest &req)
    {
      const Id order_id = requireU64(req.params, "order_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::Order order;
      if (!state.getOrder(order_id, order))
      {
        throw RpcMethodError(
            ErrorCode::OrderNotFound,
            "no order with id " + encodeU64Hex(order_id),
            makeErrorData(ErrorCode::OrderNotFound,
                          {{"order_id", encodeU64Hex(order_id)}}));
      }

      return encodeOrder(order, hrp);
    }

    // ---- clrty_getOrdersExpiringAt ----
    //
    // Params:
    //   height  (required, hex or decimal)
    //
    // Returns the list of order ids that have an expiry condition
    // registered at the given height. This is the raw index entry,
    // not the full orders — clients can fetch each one with
    // clrty_getOrder if they need details.
    //
    // Most clients won't call this; it's mostly useful for debugging
    // order expiry behavior.

    Common::Json method_getOrdersExpiringAt(Node::Node &node, const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

      State::StateAccess state(node.stateDB(), node.chain().height());

      std::vector<uint64_t> ids = state.getOrdersExpiringAt(height);

      Common::Json arr = Common::Json::array();
      for (Id id : ids)
        arr.push_back(encodeU64Hex(id));

      Common::Json out = Common::Json::object();
      putU64(out, "height", height);
      putU64(out, "count", static_cast<uint64_t>(ids.size()));
      out["order_ids"] = std::move(arr);
      return out;
    }

  } // anonymous namespace

  void registerOrderMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_getOrder", method_getOrder);
    d.registerMethod("clrty_getOrdersExpiringAt", method_getOrdersExpiringAt);
  }

} // namespace Rpc