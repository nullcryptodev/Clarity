// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>

#include "Common/Json.h"
#include "Core/Mempool.h"

namespace Rpc
{
  //  JSON-RPC 2.0 error codes
  //
  //  The spec reserves the range -32768..-32000 for protocol-level
  //  errors. Anything outside that range is application-defined.
  //
  //  We use two blocks:
  //
  //    -32000..-32099   Server-defined reserved (per spec)
  //    -32000            Reserved by us for "server" class errors
  //
  //    1000..1299        Clarity application errors
  //      1000..1049      Transaction submission
  //      1050..1099      State lookup
  //      1100..1149      Chain lookup
  //      1150..1199      Consensus / validator lookup
  //      1200..1249      AMM / order lookup
  //      1250..1299      Reserved
  //
  //  Codes are stable forever. If a method gains a new failure mode,
  //  it gets a new code. Never reuse.
  //
  //  The `message` field of a JSON-RPC error is a short, human-readable
  //  string suitable for display in a client's log. It is NOT parsed by
  //  clients; clients switch on `code`.
  //
  //  The optional `data` field carries structured detail. Its shape is
  //  method-specific and documented per method. We use it for things
  //  like the current nonce when rejecting Rejected_NonceTooLow, or
  //  the required fee when rejecting Rejected_LowFee.

  enum class ErrorCode : int32_t
  {
    // ---- JSON-RPC 2.0 reserved ----

    ParseError = -32700,     // Invalid JSON
    InvalidRequest = -32600, // Valid JSON, not a valid Request object
    MethodNotFound = -32601, // Method does not exist / is not available
    InvalidParams = -32602,  // Invalid method parameters
    InternalError = -32603,  // Internal JSON-RPC error

    // ---- Server-defined reserved ----

    ServerError = -32000, // Generic server error (e.g. shutting down)

    // ---- Application: transaction submission (1000..1049) ----

    TxMalformed = 1000,
    TxTooLarge = 1001,
    TxBadSignature = 1002,
    TxWrongChain = 1003,
    TxExpired = 1004,
    TxNonceTooLow = 1005,
    TxNonceConflict = 1006,
    TxFeeTooLow = 1007,
    TxFeeTooHigh = 1008,
    TxInsufficientFunds = 1009,
    TxPoolFull = 1010,
    TxSubmitInternal = 1011, // Node::submitTransaction returned an
                             // unclassified failure

    // ---- Application: state lookup (1050..1099) ----

    AccountNotFound = 1050,
    TokenNotFound = 1051,
    ValidatorNotFound = 1052,
    PoolNotFound = 1053,
    OrderNotFound = 1054,
    ReceiptNotFound = 1055,
    StateReadInternal = 1056,

    // ---- Application: chain lookup (1100..1149) ----

    BlockNotFound = 1100,
    TransactionNotFound = 1101,
    HistoricalQueryNotSupported = 1102,
    ChainReadInternal = 1103,

    // ---- Application: consensus / validator (1150..1199) ----

    ConsensusReadInternal = 1150,

    // ---- Application: AMM / order (1200..1249) ----

    AmmPoolEmpty = 1200,
    AmmSlippageTooHigh = 1201,

    // ---- Application: admin / auth (1250..1299) ----

    Unauthorized = 1250,
    RateLimited = 1251,
  };

  //  errorCodeName
  //
  //  Short stable identifier used in logs and in the `data.name` field
  //  of an error response. Clients should switch on `code`, not on
  //  this string, but logging benefits from having one.
  const char *errorCodeName(ErrorCode code) noexcept;

  //  errorCodeMessage
  //
  //  Human-readable default message for a code. Handlers may override
  //  with a more specific message (e.g. including the current nonce),
  //  but this is the fallback.
  const char *errorCodeMessage(ErrorCode code) noexcept;

  //  mempoolResultToErrorCode
  //
  //  Map a Core::MempoolAddResult to an RPC error code. The Accepted
  //  value has no error mapping and must never be passed here; doing
  //  so returns InternalError as a defensive fallback.
  ErrorCode mempoolResultToErrorCode(Core::MempoolAddResult result) noexcept;

  //  makeError
  //
  //  Build a JSON-RPC error object.
  //
  //    {
  //      "code":    <int>,
  //      "message": <string>,
  //      "data":    <object>     // optional
  //    }
  //
  //  If `data` is null, the field is omitted. If `message_override`
  //  is null, the default message for the code is used.
  //
  //  `data` is passed by value because it is typically built
  //  inline at the call site; the function moves it into the object.
  Common::Json makeError(
      ErrorCode code,
      const char *message_override = nullptr,
      Common::Json data = Common::Json());

  //  makeErrorData
  //
  //  Helper for the common pattern of "error code + a few named
  //  fields". Produces a `data` object with a `name` field (from
  //  errorCodeName) plus whatever the caller provides.
  //
  //  Example:
  //
  //    makeError(ErrorCode::TxNonceTooLow, nullptr,
  //              makeErrorData(ErrorCode::TxNonceTooLow,
  //                            {{"expected", "0x5"},
  //                             {"got",      "0x3"}}));
  Common::Json makeErrorData(
      ErrorCode code,
      Common::Json fields = Common::Json::object());

  // The Authorization header for the current request, if any. Set by
  // HttpConnection before dispatch, cleared after. Read by
  // AdminMethods. This is a thread_local so concurrent RPC workers
  // don't see each other's headers.
  //
  // This is a pragmatic workaround for the fact that JsonRpcRequest
  // doesn't carry HTTP headers. If we ever plumb the full HTTP request
  // through the dispatcher, remove this.
  const std::string &getCurrentAuthorization() noexcept;
  void setCurrentAuthorization(std::string value) noexcept;
} // namespace Rpc