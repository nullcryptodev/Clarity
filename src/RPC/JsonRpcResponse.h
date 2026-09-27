// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <vector>

#include "Common/Json.h"
#include "JsonRpcError.h"

namespace Rpc
{
  //  JsonRpcResponse
  //
  //  A JSON-RPC 2.0 response. Either success or error, never both,
  //  never neither. The `id` is echoed from the request.
  //
  //  Construct via the two static factories:
  //
  //    JsonRpcResponse::success(id, result)
  //    JsonRpcResponse::error(id, error_object)
  //
  //  The error object must be a JSON object with at least `code` and
  //  `message`. Use Rpc::makeError() to build one; the factory does
  //  not validate the error object because that would duplicate the
  //  error-builder's logic and drift.
  //
  //  Serialization:
  //
  //    Success:  {"jsonrpc":"2.0", "result":<value>, "id":<id>}
  //    Error:    {"jsonrpc":"2.0", "error":<object>, "id":<id>}
  //
  //  A success with a null result emits `"result": null`, not an
  //  omitted field. The spec requires `result` to be present on
  //  success, even when it's null.
  //
  //  The `id` is stored as Common::Json because JSON-RPC 2.0 allows
  //  string, integer, or null ids. Floats were rejected at parse time.
  //
  //  Notifications (requests with no id) do NOT produce responses.
  //  The dispatcher decides that; this type has no representation for
  //  "no response".

  class JsonRpcResponse
  {
  public:
    // ---- Factories ----

    // Build a success response.
    //
    // `result` may be any JSON value, including null. It is moved into
    // the response.
    static JsonRpcResponse success(Common::Json id, Common::Json result);

    // Build an error response.
    //
    // `error` must be an object containing at least `code` and
    // `message`. Build it with Rpc::makeError() unless you have a
    // reason not to.
    static JsonRpcResponse error(Common::Json id, Common::Json error);

    // ---- Inspection ----

    bool isSuccess() const noexcept { return is_success_; }
    bool isError() const noexcept { return !is_success_; }

    // The id, echoed from the request. Never modified.
    const Common::Json &id() const noexcept { return id_; }

    // The result value. Only valid when isSuccess() is true.
    // Calling this when isError() is true is a programming error.
    const Common::Json &result() const noexcept { return result_; }

    // The error object. Only valid when isError() is true.
    // Calling this when isSuccess() is true is a programming error.
    const Common::Json &error() const noexcept { return error_; }

    // ---- Serialization ----

    // Serialize to a JSON value with the full envelope.
    Common::Json toJson() const;

    // Serialize to a compact JSON string (no whitespace).
    std::string toString() const;

    // Serialize to a pretty JSON string (4-space indent).
    // Used by tests and log output; not used on the wire.
    std::string toStringPretty() const;

  private:
    JsonRpcResponse() = default;

    bool is_success_{true};
    Common::Json id_;
    Common::Json result_;
    Common::Json error_;
  };

  //  serializeBatch
  //
  //  Serialize a vector of responses as a JSON array, preserving order.
  //
  //  The dispatcher is responsible for ensuring `responses` is not
  //  empty. If it is empty, this returns `null`, which the HTTP layer
  //  will reject as a bug — this function does not silently produce
  //  `[]`, because an empty array is not a valid JSON-RPC 2.0 response.
  Common::Json serializeBatch(const std::vector<JsonRpcResponse> &responses);

} // namespace Rpc