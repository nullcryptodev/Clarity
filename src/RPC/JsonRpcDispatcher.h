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
  //  Thread safety: the dispatch methods are const and thread-safe
  //  after construction. The internal map is immutable post-init.

  class JsonRpcDispatcher
  {
  public:
    // Construct with a node reference. The node must outlive the
    // dispatcher. Registers all known methods (see registerMethods).
    JsonRpcDispatcher(Node::Node &node, const RpcConfig &config);

    ~JsonRpcDispatcher() = default;

    JsonRpcDispatcher(const JsonRpcDispatcher &) = delete;
    JsonRpcDispatcher &operator=(const JsonRpcDispatcher &) = delete;

    // ---- Method registration ----

    // Register a handler under `name`. If the name is already
    // registered, the previous handler is replaced. Registering the
    // same name twice is usually a bug; the dispatcher does not
    // detect it, but tests do.
    void registerMethod(const std::string &name, Handler handler);

    // Register all built-in clrty_* methods. Called once by the
    // constructor. Split into a separate function so tests can
    // construct a dispatcher without the full method set if needed.
    void registerBuiltinMethods();

    // Whether a method is registered.
    bool hasMethod(const std::string &name) const;

    // The number of registered methods. Useful for tests and for the
    // clrty_methods introspection method.
    size_t methodCount() const noexcept { return handlers_.size(); }

    // The sorted list of registered method names. Used by
    // clrty_methods and by tests that assert on the API surface.
    std::vector<std::string> methodNames() const;

    // ---- Dispatch ----

    // Dispatch a single pre-parsed request. Never throws.
    //
    // On success, returns a success response with the handler's
    // result and the request's id.
    //
    // On failure, returns an error response with the appropriate
    // error code and the request's id.
    //
    // If the request is a notification, the caller should check
    // `request.is_notification` and skip calling this method — or
    // call it and discard the result. The dispatcher always produces
    // a response; whether it's sent is the caller's decision.
    JsonRpcResponse dispatch(const JsonRpcRequest &request);

    // Dispatch an arbitrary JSON value: could be a single request
    // object, a batch (array of requests), or malformed input.
    //
    // Returns:
    //   - a single JsonRpcResponse, if the input was a single request
    //   - a JSON array (from serializeBatch), if the input was a batch
    //   - a single error response, if the input was neither
    //
    // The return is `Common::Json` rather than a variant because the
    // three cases serialize differently and the HTTP layer just writes
    // the bytes. The `is_batch` out-parameter tells the caller which
    // case was hit, if it cares.
    struct DispatchResult
    {
      Common::Json response;
      bool is_batch{false};
      bool is_empty{false}; // true if all entries were notifications
    };

    DispatchResult dispatchJson(const Common::Json &input);

  private:
    // Dispatch a single request that was extracted from a batch or
    // arrived as a top-level object. Same as `dispatch` but returns
    // an optional — nullopt if the request was a notification.
    std::optional<JsonRpcResponse> dispatchOne(const JsonRpcRequest &request);

    Node::Node &node_;
    RpcConfig config_;
    std::unordered_map<std::string, Handler> handlers_;
  };

} // namespace Rpc