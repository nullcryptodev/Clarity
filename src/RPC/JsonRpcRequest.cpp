// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "JsonRpcRequest.h"

namespace Rpc
{

  //  ParseResult

  ParseResult ParseResult::success(JsonRpcRequest req)
  {
    ParseResult r;
    r.ok = true;
    r.request = std::move(req);
    return r;
  }

  ParseResult ParseResult::failure(ErrorCode code,
                                   std::string message,
                                   Common::Json data)
  {
    ParseResult r;
    r.ok = false;
    r.error_code = code;
    r.error_message = std::move(message);
    r.error_data = std::move(data);
    return r;
  }

  //  parseRequest

  namespace
  {
    // Fields we accept at the top level of a request object.
    //
    // JSON-RPC 2.0 permits implementations to define their own
    // extension fields in the "rpc." namespace, but we deliberately
    // reject anything unknown to catch typos. If we ever need
    // extensions, add them here explicitly.
    bool isKnownField(const std::string &key) noexcept
    {
      return key == "jsonrpc" ||
             key == "method" ||
             key == "params" ||
             key == "id";
    }

    // Build a diagnostic when a field is missing or has the wrong
    // type. The message format is stable — clients don't parse it,
    // but tests assert on it, so keep it predictable.
    std::string fieldTypeError(const std::string &field,
                               const char *expected)
    {
      return "field '" + field + "' must be " + std::string(expected);
    }
  } // anonymous namespace

  ParseResult parseRequest(const Common::Json &value)
  {
    using Common::Json;

    // ---- Top-level shape ----

    if (!value.is_object())
    {
      return ParseResult::failure(
          ErrorCode::InvalidRequest,
          "request must be a JSON object",
          makeErrorData(ErrorCode::InvalidRequest,
                        {{"got", value.type_name()}}));
    }

    // ---- Unknown fields ----

    for (auto it = value.begin(); it != value.end(); ++it)
    {
      if (!isKnownField(it.key()))
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            "unknown field '" + it.key() + "'",
            makeErrorData(ErrorCode::InvalidRequest,
                          {{"field", it.key()}}));
      }
    }

    // ---- jsonrpc ----
    //
    // Must be present and must be exactly the string "2.0".
    // A missing field, a numeric 2.0, or "2" all fail here.

    {
      auto it = value.find("jsonrpc");
      if (it == value.end())
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            fieldTypeError("jsonrpc", "the string \"2.0\""));
      }
      if (!it->is_string())
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            fieldTypeError("jsonrpc", "a string"),
            makeErrorData(ErrorCode::InvalidRequest,
                          {{"got", it->type_name()}}));
      }
      if (it->get<std::string>() != "2.0")
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            "jsonrpc must be exactly \"2.0\"",
            makeErrorData(ErrorCode::InvalidRequest,
                          {{"got", it->get<std::string>()}}));
      }
    }

    // ---- method ----

    {
      auto it = value.find("method");
      if (it == value.end())
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            fieldTypeError("method", "a string"));
      }
      if (!it->is_string())
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            fieldTypeError("method", "a string"),
            makeErrorData(ErrorCode::InvalidRequest,
                          {{"got", it->type_name()}}));
      }
      // Empty method name is not a valid identifier. Reject early
      // rather than letting the dispatcher fail to find "".
      if (it->get<std::string>().empty())
      {
        return ParseResult::failure(
            ErrorCode::InvalidRequest,
            "field 'method' must not be empty");
      }
    }

    // ---- params ----
    //
    // Accepted forms:
    //   absent              → empty object
    //   null                → empty object
    //   object              → that object
    //   anything else       → InvalidParams
    //
    // We explicitly reject array params because they force positional
    // argument passing, which is fragile to method signature changes.
    // Every method in this RPC takes named params.

    Json params = Json::object();
    {
      auto it = value.find("params");
      if (it != value.end() && !it->is_null())
      {
        if (it->is_object())
        {
          params = *it;
        }
        else if (it->is_array())
        {
          return ParseResult::failure(
              ErrorCode::InvalidParams,
              "array params are not supported; use an object with named fields",
              makeErrorData(ErrorCode::InvalidParams,
                            {{"got", it->type_name()}}));
        }
        else
        {
          return ParseResult::failure(
              ErrorCode::InvalidParams,
              fieldTypeError("params", "an object or null"),
              makeErrorData(ErrorCode::InvalidParams,
                            {{"got", it->type_name()}}));
        }
      }
    }

    // ---- id ----
    //
    // Accepted forms:
    //   absent              → null, is_notification = true
    //   null                → null, is_notification = true
    //   string              → the string, is_notification = false
    //   number (int/uint)   → the number, is_notification = false
    //   anything else       → InvalidRequest
    //
    // The spec discourages fractional-number ids; we reject them
    // explicitly because two floats can compare equal as JSON but
    // stringify differently, which breaks echo-back matching.

    Json id = nullptr;
    bool is_notification = true;
    {
      auto it = value.find("id");
      if (it != value.end() && !it->is_null())
      {
        if (it->is_string())
        {
          id = *it;
          is_notification = false;
        }
        else if (it->is_number_integer() || it->is_number_unsigned())
        {
          id = *it;
          is_notification = false;
        }
        else if (it->is_number_float())
        {
          return ParseResult::failure(
              ErrorCode::InvalidRequest,
              "field 'id' must not be a fractional number",
              makeErrorData(ErrorCode::InvalidRequest,
                            {{"got", it->dump()}}));
        }
        else
        {
          return ParseResult::failure(
              ErrorCode::InvalidRequest,
              fieldTypeError("id", "a string, a number, or null"),
              makeErrorData(ErrorCode::InvalidRequest,
                            {{"got", it->type_name()}}));
        }
      }
    }

    // ---- Assemble ----

    JsonRpcRequest req;
    req.method = value.at("method").get<std::string>();
    req.params = std::move(params);
    req.id = std::move(id);
    req.is_notification = is_notification;

    return ParseResult::success(std::move(req));
  }

} // namespace Rpc