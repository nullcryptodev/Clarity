// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AdminMethods.h"

#include "Encoders/Encoding.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"
#include "Config.h"

#include "Node/Node.h"

#include <chrono>
#include <cstring>
#include <thread>

namespace Rpc
{

  namespace
  {
    //  Admin auth

    // Constant-time string comparison. The lengths must match
    // exactly; anything else returns false immediately. This is not
    // perfectly constant-time (it short-circuits on length) but
    // matches the token length to the request's, which is the
    // standard practice.
    bool constantTimeEq(const std::string &a, const std::string &b) noexcept
    {
      if (a.size() != b.size())
        return false;
      unsigned char diff = 0;
      for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
      return diff == 0;
    }

    void requireAdmin(const RpcConfig &config,
                      const std::string &authorization_header)
    {
      if (config.admin_token.empty())
      {
        // No token configured → admin methods don't exist.
        throw RpcMethodError(
            ErrorCode::MethodNotFound,
            "admin methods are disabled (no admin token configured)");
      }

      // Expect "Bearer <token>". Case-insensitive on "Bearer ".
      const std::string prefix = "Bearer ";
      if (authorization_header.size() < prefix.size() ||
          strncasecmp(authorization_header.c_str(),
                      prefix.c_str(), prefix.size()) != 0)
      {
        throw RpcMethodError(
            ErrorCode::Unauthorized,
            "missing or malformed Authorization header");
      }

      const std::string presented = authorization_header.substr(prefix.size());
      if (!constantTimeEq(presented, config.admin_token))
      {
        throw RpcMethodError(
            ErrorCode::Unauthorized,
            "invalid admin token");
      }
    }

    // ---- clrty_shutdown ----

    Common::Json method_shutdown(Node::Node &node,
                                 const RpcConfig &config,
                                 const JsonRpcRequest &)
    {
      requireAdmin(config, getCurrentAuthorization());

      // Trigger a graceful stop. Node::stop is documented as safe
      // from any thread and idempotent.
      //
      // The response is sent before the node actually stops because
      // the RPC worker thread returns from this handler and writes
      // the response, then the main thread observes the stop flag and
      // shuts down. If we blocked on node.stop() the RPC response
      // would never be delivered.
      //
      // We dispatch the stop call on a detached thread so the
      // handler can return immediately. This is the one case where a
      // detached thread is appropriate — it runs exactly once, has
      // no caller to report to, and the process is about to exit.
      std::thread([&node]()
                  {
        // Small delay so the HTTP response has time to flush.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        node.stop(); })
          .detach();

      Common::Json j = Common::Json::object();
      j["shutting_down"] = true;
      return j;
    }

    // ---- clrty_setLogLevel ----
    //
    // Params:
    //   level  (required, string: "debug"|"info"|"warn"|"error")
    //
    // Adjusts the log level at runtime. The ILogger interface would
    // need a setLevel() method for this to work; without one, we
    // return a "not supported" error. I've written this handler to
    // assume setLevel exists — if not, remove it and register
    // nothing for now.

    Common::Json method_setLogLevel(Node::Node &, const RpcConfig &config,
                                    const JsonRpcRequest &req)
    {
      requireAdmin(config, getCurrentAuthorization());

      const std::string level = requireString(req.params, "level");
      if (level != "debug" && level != "info" &&
          level != "warn" && level != "error")
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "level must be one of: debug, info, warn, error",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"level", level}}));
      }

      // TODO: call the node's logger to set the level. The ILogger
      // interface doesn't currently expose setLevel; add it when
      // this becomes a priority. For now, return a not-supported
      // error so clients know the endpoint exists but isn't wired.
      throw RpcMethodError(
          ErrorCode::InternalError,
          "runtime log level changes are not yet supported");
    }

  } // anonymous namespace

  void registerAdminMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_shutdown", method_shutdown);
    d.registerMethod("clrty_setLogLevel", method_setLogLevel);
  }

} // namespace Rpc