// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include "JsonRpcDispatcher.h"
#include "Methods.h"

namespace Rpc
{
  namespace
  {
    std::string toLower(std::string_view s)
    {
      std::string out;
      out.reserve(s.size());
      for (char c : s)
        out.push_back(char(std::tolower(static_cast<unsigned char>(c))));
      return out;
    }

    std::string trim(std::string_view s)
    {
      size_t start = 0;
      while (start < s.size() && (s[start] == ' ' || s[start] == '\t'))
        ++start;
      size_t end = s.size();
      while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        --end;
      return std::string(s.substr(start, end - start));
    }

    bool contentTypeIsJson(const std::string &ct)
    {
      std::string lower = toLower(ct);
      auto semi = lower.find(';');
      std::string base = semi == std::string::npos ? lower : lower.substr(0, semi);
      base = trim(base);
      return base == "application/json" ||
             base == "application/json-rpc" ||
             base == "application/jsonrequest" ||
             base == "text/plain";
    }
  }

  //  Construction

  JsonRpcDispatcher::JsonRpcDispatcher(Node::Node &node, const RpcConfig &config)
      : node_(node), config_(config)
  {
    registerBuiltinMethods();
  }

  //  Registration
  void JsonRpcDispatcher::registerBuiltinMethods()
  {
    registerChainMethods(*this);
    registerTxMethods(*this);
    registerStateMethods(*this);
    registerMempoolMethods(*this);
    registerConsensusMethods(*this);
    registerAmmMethods(*this);
    registerOrderMethods(*this);
    registerNodeMethods(*this);
    registerAdminMethods(*this);

    // methods is registered last so its handler can capture
    // `this` and read the dispatcher's full method list, including
    // every method registered above. The placeholder registered by
    // registerChainMethods is shadowed by this one — registerMethod
    // replaces on duplicate names, and that's intentional: the
    // chain group owns the *documentation* of the method, while the
    // dispatcher owns its *implementation*.
    registerMethod("methods",
                   [this](Node::Node &, const RpcConfig &,
                          const JsonRpcRequest &) -> Common::Json
                   {
                     Common::Json j = Common::Json::object();
                     Common::Json arr = Common::Json::array();
                     for (const auto &name : methodNames())
                       arr.push_back(name);
                     j["methods"] = std::move(arr);
                     return j;
                   });
  }

  void JsonRpcDispatcher::registerMethod(const std::string &name,
                                         Handler handler)
  {
    handlers_[name] = std::move(handler);
  }

  bool JsonRpcDispatcher::hasMethod(const std::string &name) const
  {
    return handlers_.find(name) != handlers_.end();
  }

  std::vector<std::string> JsonRpcDispatcher::methodNames() const
  {
    std::vector<std::string> names;
    names.reserve(handlers_.size());
    for (const auto &[name, _] : handlers_)
    {
      names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    return names;
  }

  //  Dispatch: single

  JsonRpcResponse JsonRpcDispatcher::dispatch(const JsonRpcRequest &request)
  {
    auto result = dispatchOne(request);
    if (result.has_value())
    {
      return std::move(*result);
    }

    // Notification: the request had no id. The caller should not send
    // this response, but we return a well-formed one anyway so that
    // "dispatch always returns a response" is a real invariant and
    // callers that don't check is_notification don't crash.
    //
    // The id is null (per spec, that's the id a notification would
    // have if it produced a response).
    return JsonRpcResponse::success(Common::Json(nullptr),
                                    Common::Json(nullptr));
  }

  std::optional<JsonRpcResponse> JsonRpcDispatcher::dispatchOne(
      const JsonRpcRequest &request)
  {
    // ---- Method lookup ----

    auto it = handlers_.find(request.method);
    if (it == handlers_.end())
    {
      return JsonRpcResponse::error(
          request.id,
          makeError(ErrorCode::MethodNotFound, nullptr,
                    makeErrorData(ErrorCode::MethodNotFound,
                                  {{"method", request.method}})));
    }

    // ---- Invoke ----

    try
    {
      Common::Json result = it->second(node_, config_, request);

      // Notifications get no response even on success.
      if (request.is_notification)
      {
        return std::nullopt;
      }

      return JsonRpcResponse::success(request.id, std::move(result));
    }
    catch (const RpcMethodError &e)
    {
      // Expected failure. The handler has told us exactly what to
      // report.
      if (request.is_notification)
      {
        return std::nullopt;
      }

      return JsonRpcResponse::error(
          request.id,
          makeError(e.code(),
                    e.message_override().empty()
                        ? nullptr
                        : e.message_override().c_str(),
                    e.data()));
    }
    catch (const std::exception &e)
    {
      // Unexpected failure. Log the real message, return a generic
      // one to the client. `verbose_errors` is not consulted here
      // because that would require the dispatcher to know the
      // RpcConfig, and I'd rather keep the dispatcher stateless.
      //
      // TODO: plumb RpcConfig through if verbose_errors is ever
      // needed. For v1, no internal exception text leaves the
      // process.
      (void)e;

      if (request.is_notification)
      {
        return std::nullopt;
      }

      return JsonRpcResponse::error(
          request.id,
          makeError(ErrorCode::InternalError));
    }
  }

  //  Dispatch: JSON entry point

  JsonRpcDispatcher::DispatchResult
  JsonRpcDispatcher::dispatchJson(const Common::Json &input)
  {
    DispatchResult out;

    // ---- Single request ----

    if (input.is_object())
    {
      out.is_batch = false;

      ParseResult parsed = parseRequest(input);
      if (!parsed.ok)
      {
        // Parse errors always produce a response, even for what
        // looked like a notification, because we can't trust the
        // notification-ness of a malformed request.
        out.response = JsonRpcResponse::error(
                           Common::Json(nullptr),
                           makeError(parsed.error_code,
                                     parsed.error_message.c_str(),
                                     parsed.error_data))
                           .toJson();
        return out;
      }

      if (parsed.request.is_notification)
      {
        // Notification: no response. The caller will write an empty
        // body and 204.
        out.response = Common::Json(nullptr);
        out.is_empty = true;
        return out;
      }

      out.response = dispatch(parsed.request).toJson();
      return out;
    }

    // ---- Batch ----

    if (input.is_array())
    {
      out.is_batch = true;

      if (input.empty())
      {
        // Empty batch: per spec, this is invalid.
        out.response = JsonRpcResponse::error(
                           Common::Json(nullptr),
                           makeError(ErrorCode::InvalidRequest,
                                     "batch must not be empty"))
                           .toJson();
        // Note: not `is_batch = true` semantically — a single error
        // response is the correct output. Reset the flag.
        out.is_batch = false;
        return out;
      }

      std::vector<JsonRpcResponse> responses;
      responses.reserve(input.size());

      for (const auto &item : input)
      {
        ParseResult parsed = parseRequest(item);
        if (!parsed.ok)
        {
          responses.push_back(JsonRpcResponse::error(
              Common::Json(nullptr),
              makeError(parsed.error_code,
                        parsed.error_message.c_str(),
                        parsed.error_data)));
          continue;
        }

        auto one = dispatchOne(parsed.request);
        if (one.has_value())
        {
          responses.push_back(std::move(*one));
        }
        // else: notification within a batch. No response.
      }

      if (responses.empty())
      {
        // Every entry in the batch was a notification.
        out.response = Common::Json(nullptr);
        out.is_empty = true;
        return out;
      }

      // Preserve request order. serializeBatch does not reorder.
      out.response = serializeBatch(responses);
      return out;
    }

    // ---- Neither object nor array ----

    out.response = JsonRpcResponse::error(
                       Common::Json(nullptr),
                       makeError(ErrorCode::InvalidRequest,
                                 "request must be an object or an array"))
                       .toJson();
    return out;
  }

  //  IHttpHandler implementation

  HttpResponse JsonRpcDispatcher::handle(const HttpRequest &request)
  {
    HttpResponse out;

    // ---- Path routing ----

    if (request.path != "/" && request.path != "/rpc")
    {
      out.status = 404;
      out.content_type = "text/plain";
      out.body = "path must be / or /rpc\n";
      return out;
    }

    // ---- GET: friendly banner ----

    if (request.method == "GET")
    {
      out.status = 200;
      out.content_type = "text/plain";
      out.body = "Clarity RPC. Send POST /rpc with a JSON-RPC 2.0 request.\n";
      return out;
    }

    // ---- POST framing checks ----
    //
    //  These checks used to live in HttpConnection::handleRequest,
    //  where they applied to every POST that reached the transport
    //  layer. That was wrong when the metrics handler was added:
    //  POST /metrics is a request that targets the wrong handler,
    //  and the right response is 405 "use GET for metrics" from
    //  that handler, not 400 "Content-Length is required" from
    //  the transport. Moving the checks here lets each handler
    //  own its own method and framing contract.
    //
    //  For the RPC handler specifically: a POST is required to
    //  carry a body (Content-Length), and the body is required to
    //  be JSON (or a content-type the client library uses to mean
    //  JSON-RPC). If either is missing, reject with the specific
    //  error before attempting to parse.

    if (!request.content_type.empty() &&
        !contentTypeIsJson(request.content_type))
    {
      out.status = 415;
      out.content_type = "text/plain";
      out.body = "Content-Type must be application/json\n";
      return out;
    }

    if (!request.has_content_length)
    {
      out.status = 400;
      out.content_type = "text/plain";
      out.body = "Content-Length is required\n";
      return out;
    }

    // ---- POST: parse body as JSON, then dispatch ----
    //
    // Content-Type and Content-Length were validated above; by the
    // time we're here, the body is present and non-empty for any
    // request that had a Content-Length.

    Common::Json input;
    try
    {
      input = Common::Json::parse(request.body);
    }
    catch (const std::exception &)
    {
      // JSON parse failure: emit a JSON-RPC ParseError response
      // with HTTP 200. JSON-RPC errors do not use HTTP status
      // codes to convey their nature.
      Common::Json err = Common::Json::object();
      err["jsonrpc"] = "2.0";
      err["error"] = makeError(ErrorCode::ParseError);
      err["id"] = nullptr;

      out.status = 200;
      out.content_type = "application/json";
      out.body = err.dump();
      return out;
    }

    // ---- Dispatch ----

    // Set the auth context so admin methods can read the header.
    // The thread-local is set here because the dispatcher's method
    // handlers don't take the request headers — they only take the
    // JsonRpcRequest. Clearing it after dispatch keeps the
    // thread-local scoped to this call.
    Rpc::setCurrentAuthorization(request.authorization);
    auto result = dispatchJson(input);
    Rpc::setCurrentAuthorization({});

    if (result.is_empty)
    {
      // Notification-only request or batch. 204 with no body.
      out.status = 204;
      out.content_type = "text/plain";
      out.body.clear();
      return out;
    }

    out.status = 200;
    out.content_type = "application/json";
    out.body = result.response.dump();
    return out;
  }

} // namespace Rpc