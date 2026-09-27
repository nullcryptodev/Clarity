// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "Common/Json.h"
#include "JsonRpcError.h"

namespace Rpc
{
  //  JsonRpcRequest
  //
  //  A parsed, validated JSON-RPC 2.0 request object.
  //
  //  Construct via parseRequest(), never directly. The parse function
  //  enforces the invariants documented here.
  //
  //  Fields:
  //
  //    method  — the method name, e.g. "clrty_getBalance". Non-empty.
  //    params  — the params object. Always an object (may be empty).
  //              Array params are rejected by the parser.
  //    id      — the request id, echoed back in the response.
  //              Absent → null (a notification). Present and non-null
  //              → must be a string or a number.
  //    is_notification
  //            — true if the request had no id field. Notifications
  //              get no response, even on error.
  //
  //  We deliberately do NOT support the "reserved rpc. namespace" from
  //  the JSON-RPC 2.0 spec. Any field outside the four we know about is
  //  rejected, which catches typos in method names and parameter keys.

  struct JsonRpcRequest
  {
    std::string method;
    Common::Json params; // object; empty object if absent
    Common::Json id;     // null, string, or number
    bool is_notification{false};
  };

  //  ParseResult
  //
  //  Tagged union of {parsed request} | {parse error}. Modeled as a
  //  struct with two optional-ish fields rather than std::variant
  //  because the error path carries both a code and a message, and
  //  the success path carries the request.
  //
  //  Invariants:
  //    - exactly one of `ok` and `error` is engaged
  //    - if ok: `request` is engaged
  //    - if !ok: `error_code` and `error_message` are set;
  //              `error_data` may or may not be engaged
  //
  //  Callers should check `ok` first, then either use `request` or
  //  build an error response from the three error fields.
  struct ParseResult
  {
    bool ok{false};

    // On success:
    JsonRpcRequest request;

    // On failure:
    ErrorCode error_code{ErrorCode::InvalidRequest};
    std::string error_message;
    Common::Json error_data; // may be null

    static ParseResult success(JsonRpcRequest req);
    static ParseResult failure(ErrorCode code,
                               std::string message,
                               Common::Json data = Common::Json());
  };

  //  parseRequest
  //
  //  Parse a single JSON value as a JSON-RPC 2.0 request object.
  //
  //  The input is expected to be the *result* of `nlohmann::json::parse`
  //  on the request body, or the equivalent value from a batch array.
  //  It must be an object; non-object inputs return a failure with
  //  InvalidRequest.
  //
  //  Errors:
  //
  //    InvalidRequest  — the value is not an object; a required field
  //                      is missing; a field has the wrong type; an
  //                      unknown field is present; `jsonrpc` is not
  //                      the exact string "2.0"
  //
  //    InvalidParams   — `params` is present and is an array (array
  //                      params are not supported); `params` is present
  //                      and is neither object nor null
  //
  //  Note: MethodNotFound is NOT a parse error. The parser does not
  //  know which methods exist; the dispatcher checks that after a
  //  successful parse.
  //
  //  Never throws.
  ParseResult parseRequest(const Common::Json &value);

} // namespace Rpc