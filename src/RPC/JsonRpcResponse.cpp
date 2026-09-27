// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "JsonRpcResponse.h"

namespace Rpc
{

  //  Factories

  JsonRpcResponse JsonRpcResponse::success(Common::Json id,
                                           Common::Json result)
  {
    JsonRpcResponse r;
    r.is_success_ = true;
    r.id_ = std::move(id);
    r.result_ = std::move(result);
    return r;
  }

  JsonRpcResponse JsonRpcResponse::error(Common::Json id,
                                         Common::Json error)
  {
    JsonRpcResponse r;
    r.is_success_ = false;
    r.id_ = std::move(id);
    r.error_ = std::move(error);
    return r;
  }

  //  Serialization

  Common::Json JsonRpcResponse::toJson() const
  {
    Common::Json j = Common::Json::object();
    j["jsonrpc"] = "2.0";

    if (is_success_)
    {
      // `result` is always present on success, even if null.
      // `std::move` would leave result_ unusable for a second
      // serialization; we want toString() to be callable more than
      // once on the same response.
      j["result"] = result_;
    }
    else
    {
      j["error"] = error_;
    }

    // `id` is always present. It may be null (a request with an
    // explicit null id, or a parse error where the id couldn't be
    // recovered), which is distinct from absent.
    j["id"] = id_;

    return j;
  }

  std::string JsonRpcResponse::toString() const
  {
    return toJson().dump();
  }

  std::string JsonRpcResponse::toStringPretty() const
  {
    return toJson().dump(4);
  }

  //  Batch

  Common::Json serializeBatch(const std::vector<JsonRpcResponse> &responses)
  {
    if (responses.empty())
    {
      // Caller bug: JSON-RPC 2.0 has no valid representation for an
      // empty batch response. Returning null here surfaces the bug
      // rather than emitting `[]`, which clients would misinterpret.
      return Common::Json();
    }

    Common::Json arr = Common::Json::array();
    for (const auto &r : responses)
    {
      arr.push_back(r.toJson());
    }
    return arr;
  }

} // namespace Rpc