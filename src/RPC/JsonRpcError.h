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
  //      1000..1299      Clarity application errors
  //      1000..1049      Transaction submission
  //      1050..1099      State lookup
  //      1100..1149      Chain lookup
  //      1050..1060      Account, token, validator, pool, order,
  //                      receipt, proof, NFT
  //      1061..1070      Bridge
  //      1065            BridgeDepositNotFound
  //      1071..1099      Reserved
  //
  //  Codes are stable forever. If a method gains a new failure mode,
  //  it gets a new code. Never reuse. A code that is retired — for
  //  example because the model that produced it was replaced — keeps
  //  its slot reserved and stops being emitted. The name and message
  //  strings stay so an old log parser or an old client that switches
  //  on the numeric code still gets something meaningful back.
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
    //  The transaction is well-formed and correctly signed, but its
    //  type-specific preconditions cannot be satisfied at the current
    //  chain tip: minting a token that does not exist, minting or
    //  updating a token the sender did not create, exceeding the
    //  supply cap, burning a token that does not exist, or a bridge
    //  transaction whose signature block does not verify against the
    //  current active validator set. Distinct from TxMalformed (the
    //  bytes are fine) and from TxInsufficientFunds (the fee and
    //  amount are covered).
    TxPrecondition = 1012,

    // ---- Application: state lookup (1050..1099) ----

    AccountNotFound = 1050,
    TokenNotFound = 1051,
    ValidatorNotFound = 1052,
    PoolNotFound = 1053,
    OrderNotFound = 1054,
    ReceiptNotFound = 1055,
    StateReadInternal = 1056,
    ProofVersionUnavailable = 1057,
    ProofNotAvailable = 1058,
    NftNotFound = 1059,
    NftCollectionNotFound = 1060,

    //  ---- Application: bridge (1061..1070) ----
    //
    //  Grouped with state lookup because they all read bridge state
    //  that lives in the StateAccess. A future bridge-write error
    //  block (submission rejection, etc.) would go after these.
    //
    //  Under the validator-is-watcher model there is no per-chain
    //  watcher record. Every active validator is a bridge watcher,
    //  and the operational signer set is the active validator set
    //  at the height of the operation. As a consequence:
    //
    //    - There is no "watcher not found" condition (an address
    //      either maps to a validator or it does not; that is
    //      ValidatorNotFound, and it lives in the state block).
    //    - There is no per-watcher read that could fail
    //      independently of a general bridge read.
    //
    //  BridgeWatcherNotFound (1063) and BridgeReadInternal (1064)
    //  are therefore reserved. They are kept in the enum so that
    //  an older client or log parser that switches on the numeric
    //  code does not misinterpret a future error that happens to
    //  land on 1063/1064, and so that a future, unrelated error
    //  cannot reuse the slot. Nothing in the current tree emits
    //  either code.

    BridgeChainNotRegistered = 1061,
    BridgeWithdrawalNotFound = 1062,
    BridgeWatcherNotFound = 1063, // reserved; not emitted
    BridgeReadInternal = 1064,    // reserved; not emitted

    //  No deposit-destination record at the requested
    //  (source_chain_id, index). Emitted by
    //  getBridgeDepositDestination when the chain is
    //  registered but no registration exists at that index.
    //
    //  Distinct from BridgeChainNotRegistered, which means
    //  the chain itself is unregistered. A client that
    //  branches on the code needs the distinction: "you're
    //  asking about a chain that doesn't exist" and "you're
    //  asking about an index on a chain that does exist"
    //  have different remedies.
    BridgeDepositNotFound = 1065,

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
    AmmFarmNotFound = 1202,
    //  Reserved. Not emitted by the current node: getAmmFarmAccrual
    //  reports an absent companion with `exists: false` and computes
    //  the accrued amount as if last_rps were 0, which is the
    //  correct semantic. A future strict-mode variant of the method
    //  could emit this; the slot is reserved so that a future error
    //  that wants it doesn't collide with an older protocol version.
    AmmFarmAccrualNotFound = 1203,

    // ---- Application: admin / auth (1250..1299) ----

    Unauthorized = 1250,
    RateLimited = 1251,
  };

  //  errorCodeName
  //
  //  Short stable identifier used in logs and in the `data.name` field
  //  of an error response. Clients should switch on `code`, not on
  //  this string, but logging benefits from having one. A reserved
  //  code returns its historical name; no handler emits it.
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
  //
  //  The bridge rejections map onto the existing tx codes:
  //
  //    Rejected_BridgePayloadMalformed -> TxMalformed
  //    Rejected_BridgeSignature        -> TxPrecondition
  //
  //  A malformed bridge payload is structurally wrong at the byte
  //  level (a declared count that overruns the buffer, a field
  //  missing from the fixed prefix), which is what TxMalformed
  //  means everywhere else. A signature block that does not verify
  //  against the current active validator set is well-formed and
  //  correctly signed but cannot apply at the tip, which is what
  //  TxPrecondition means. Neither is given a dedicated code: from
  //  the client's perspective the remedy in both cases is "fix the
  //  bridge transaction and resubmit", and the distinction is
  //  already available to a caller that wants it via the receipt
  //  or the mempool rejection reason.
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