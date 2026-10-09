// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "Common/Json.h"
#include "IHttpHandler.h"
#include "JsonRpcError.h"
#include "JsonRpcRequest.h"
#include "JsonRpcResponse.h"
#include "Config.h"

namespace Node
{
  class Node;
}

namespace Rpc
{
  //  RpcMethodError
  //
  //  Thrown by a method handler to signal an expected failure. The
  //  dispatcher catches it and converts it to a JSON-RPC error
  //  response. Anything else thrown by a handler is treated as a bug
  //  and mapped to InternalError.
  //
  //  Handlers should throw this for every failure mode they can name:
  //  missing account, bad params, insufficient funds, etc. They should
  //  NOT throw it for programmer errors (null deref, assertion) — let
  //  those propagate as std::exception subclasses so the dispatcher
  //  logs them at a higher level.

  class RpcMethodError : public std::exception
  {
  public:
    RpcMethodError(ErrorCode code,
                   std::string message_override = {},
                   Common::Json data = Common::Json())
        : code_(code),
          message_override_(std::move(message_override)),
          data_(std::move(data))
    {
      // Precompute the what() string so it outlives the exception
      // object's lifetime if anything calls what() after the object
      // is destroyed (rare but legal).
      what_ = std::string("RpcMethodError: ") +
              errorCodeName(code_) +
              (message_override_.empty()
                   ? std::string()
                   : " (" + message_override_ + ")");
    }

    const char *what() const noexcept override { return what_.c_str(); }

    ErrorCode code() const noexcept { return code_; }
    const std::string &message_override() const noexcept { return message_override_; }
    const Common::Json &data() const noexcept { return data_; }

  private:
    ErrorCode code_;
    std::string message_override_;
    Common::Json data_;
    std::string what_;
  };

  //  Handler
  //
  //  A method handler. Takes a reference to the Node (which owns the
  //  chain, mempool, DBs, and consensus) and the parsed request
  //  (whose `params` field it reads).
  //
  //  Returns a JSON value which becomes the `result` field of the
  //  success response. May throw RpcMethodError for expected
  //  failures.
  //
  //  Handlers must be thread-safe with respect to each other. The
  //  dispatcher does not serialize calls.

  using Handler = std::function<Common::Json(
      Node::Node &node,
      const RpcConfig &config,
      const JsonRpcRequest &request)>;

  //  JsonRpcDispatcher
  //
  //  Maps method names to handlers, parses request objects, invokes
  //  handlers, and assembles responses. Handles both single requests
  //  and batches.
  //
  //  Implements IHttpHandler: `handle()` takes an HttpRequest,
  //  validates that it targets one of the paths the RPC endpoint
  //  serves, parses the JSON-RPC body, dispatches, and returns an
  //  HttpResponse. The dispatcher still exposes `dispatch()` and
  //  `dispatchJson()` for tests and for any caller that wants to
  //  bypass the HTTP framing.
  //
  //  Thread safety: the dispatch methods are const and thread-safe
  //  after construction. The internal map is immutable post-init.

  class JsonRpcDispatcher : public IHttpHandler
  {
  public:
    JsonRpcDispatcher(Node::Node &node, const RpcConfig &config);

    ~JsonRpcDispatcher() override = default;

    JsonRpcDispatcher(const JsonRpcDispatcher &) = delete;
    JsonRpcDispatcher &operator=(const JsonRpcDispatcher &) = delete;

    // ---- IHttpHandler ----

    // Serves the RPC endpoint. Paths accepted: "/" and "/rpc".
    // Methods accepted: POST (with a JSON-RPC body). A GET on "/"
    // returns a friendly banner, matching the previous behavior.
    //
    // Never throws (IHttpHandler contract). Any exception that
    // escapes from a handler is caught at the JSON-RPC layer and
    // turned into a JSON-RPC InternalError response, which is
    // returned with HTTP 200 (JSON-RPC errors do not use HTTP
    // status codes to convey their nature). If the exception
    // escapes from the JSON parsing itself, that's a different
    // path — see the try/catch in `handle`.
    HttpResponse handle(const HttpRequest &request) override;

    // ---- Method registration ----  (unchanged)
    void registerMethod(const std::string &name, Handler handler);
    void registerBuiltinMethods();
    bool hasMethod(const std::string &name) const;
    size_t methodCount() const noexcept { return handlers_.size(); }
    std::vector<std::string> methodNames() const;

    // ---- Dispatch ----  (unchanged)
    JsonRpcResponse dispatch(const JsonRpcRequest &request);

    struct DispatchResult
    {
      Common::Json response;
      bool is_batch{false};
      bool is_empty{false};
    };

    DispatchResult dispatchJson(const Common::Json &input);

  private:
    std::optional<JsonRpcResponse> dispatchOne(const JsonRpcRequest &request);

    Node::Node &node_;
    RpcConfig config_;
    std::unordered_map<std::string, Handler> handlers_;
  };

} // namespace Rpc