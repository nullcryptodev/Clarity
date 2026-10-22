// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "JsonRpcError.h"

namespace Rpc
{

  //  errorCodeName

  const char *errorCodeName(ErrorCode code) noexcept
  {
    switch (code)
    {
    // ---- JSON-RPC 2.0 ----
    case ErrorCode::ParseError:
      return "ParseError";
    case ErrorCode::InvalidRequest:
      return "InvalidRequest";
    case ErrorCode::MethodNotFound:
      return "MethodNotFound";
    case ErrorCode::InvalidParams:
      return "InvalidParams";
    case ErrorCode::InternalError:
      return "InternalError";

    // ---- Server ----
    case ErrorCode::ServerError:
      return "ServerError";

    // ---- Tx submission ----
    case ErrorCode::TxMalformed:
      return "TxMalformed";
    case ErrorCode::TxTooLarge:
      return "TxTooLarge";
    case ErrorCode::TxBadSignature:
      return "TxBadSignature";
    case ErrorCode::TxWrongChain:
      return "TxWrongChain";
    case ErrorCode::TxExpired:
      return "TxExpired";
    case ErrorCode::TxNonceTooLow:
      return "TxNonceTooLow";
    case ErrorCode::TxNonceConflict:
      return "TxNonceConflict";
    case ErrorCode::TxFeeTooLow:
      return "TxFeeTooLow";
    case ErrorCode::TxFeeTooHigh:
      return "TxFeeTooHigh";
    case ErrorCode::TxInsufficientFunds:
      return "TxInsufficientFunds";
    case ErrorCode::TxPoolFull:
      return "TxPoolFull";
    case ErrorCode::TxSubmitInternal:
      return "TxSubmitInternal";
    case ErrorCode::TxPrecondition:
      return "TxPrecondition";

    // ---- State ----
    case ErrorCode::AccountNotFound:
      return "AccountNotFound";
    case ErrorCode::TokenNotFound:
      return "TokenNotFound";
    case ErrorCode::ValidatorNotFound:
      return "ValidatorNotFound";
    case ErrorCode::PoolNotFound:
      return "PoolNotFound";
    case ErrorCode::OrderNotFound:
      return "OrderNotFound";
    case ErrorCode::ReceiptNotFound:
      return "ReceiptNotFound";
    case ErrorCode::StateReadInternal:
      return "StateReadInternal";
    case ErrorCode::ProofVersionUnavailable:
      return "ProofVersionUnavailable";
    case ErrorCode::ProofNotAvailable:
      return "ProofNotAvailable";
    case ErrorCode::NftNotFound:
      return "NftNotFound";
    case ErrorCode::NftCollectionNotFound:
      return "NftCollectionNotFound";
    case ErrorCode::BridgeChainNotRegistered:
      return "BridgeChainNotRegistered";
    case ErrorCode::BridgeWithdrawalNotFound:
      return "BridgeWithdrawalNotFound";
    //  Reserved: never emitted by the current node. The name is
    //  kept so an older client or log parser that switches on the
    //  numeric code gets something meaningful back.
    case ErrorCode::BridgeWatcherNotFound:
      return "BridgeWatcherNotFound";
    case ErrorCode::BridgeReadInternal:
      return "BridgeReadInternal";

    // ---- Chain ----
    case ErrorCode::BlockNotFound:
      return "BlockNotFound";
    case ErrorCode::TransactionNotFound:
      return "TransactionNotFound";
    case ErrorCode::HistoricalQueryNotSupported:
      return "HistoricalQueryNotSupported";
    case ErrorCode::ChainReadInternal:
      return "ChainReadInternal";

    // ---- Consensus ----
    case ErrorCode::ConsensusReadInternal:
      return "ConsensusReadInternal";

    // ---- AMM / order ----
    case ErrorCode::AmmPoolEmpty:
      return "AmmPoolEmpty";
    case ErrorCode::AmmSlippageTooHigh:
      return "AmmSlippageTooHigh";

    // ---- Admin ----
    case ErrorCode::Unauthorized:
      return "Unauthorized";
    case ErrorCode::RateLimited:
      return "RateLimited";
    }

    return "Unknown";
  }

  //  errorCodeMessage

  const char *errorCodeMessage(ErrorCode code) noexcept
  {
    switch (code)
    {
    case ErrorCode::ParseError:
      return "Invalid JSON";
    case ErrorCode::InvalidRequest:
      return "Not a valid JSON-RPC 2.0 request";
    case ErrorCode::MethodNotFound:
      return "Method not found";
    case ErrorCode::InvalidParams:
      return "Invalid method parameters";
    case ErrorCode::InternalError:
      return "Internal error";
    case ErrorCode::ServerError:
      return "Server error";

    case ErrorCode::TxMalformed:
      return "Transaction is malformed";
    case ErrorCode::TxTooLarge:
      return "Transaction exceeds the maximum size";
    case ErrorCode::TxBadSignature:
      return "Transaction signature is invalid";
    case ErrorCode::TxWrongChain:
      return "Transaction is for a different chain";
    case ErrorCode::TxExpired:
      return "Transaction has expired";
    case ErrorCode::TxNonceTooLow:
      return "Transaction nonce is below the account nonce";
    case ErrorCode::TxNonceConflict:
      return "A transaction with this nonce is already in the mempool";
    case ErrorCode::TxFeeTooLow:
      return "Transaction fee rate is below the minimum";
    case ErrorCode::TxFeeTooHigh:
      return "Transaction fee rate is above the maximum";
    case ErrorCode::TxInsufficientFunds:
      return "Insufficient funds for amount plus fee";
    case ErrorCode::TxPoolFull:
      return "Mempool is full and the transaction was not competitive";
    case ErrorCode::TxSubmitInternal:
      return "Transaction submission failed";
    case ErrorCode::TxPrecondition:
      return "Transaction cannot apply at the current chain tip";

    case ErrorCode::AccountNotFound:
      return "Account not found";
    case ErrorCode::TokenNotFound:
      return "Token not found";
    case ErrorCode::ValidatorNotFound:
      return "Validator not found";
    case ErrorCode::PoolNotFound:
      return "AMM pool not found";
    case ErrorCode::OrderNotFound:
      return "Order not found";
    case ErrorCode::ReceiptNotFound:
      return "Receipt not found";
    case ErrorCode::StateReadInternal:
      return "State read failed";
    case ErrorCode::ProofVersionUnavailable:
      return "No committed state root at the requested version";
    case ErrorCode::ProofNotAvailable:
      return "Proof could not be produced for this key";
    case ErrorCode::NftNotFound:
      return "NFT not found";
    case ErrorCode::NftCollectionNotFound:
      return "NFT collection not found";
    case ErrorCode::BridgeChainNotRegistered:
      return "No bridge registration for this source chain";
    case ErrorCode::BridgeWithdrawalNotFound:
      return "Bridge withdrawal not found";
    //  Reserved: never emitted by the current node. The message
    //  says so, so an operator who sees one in a log from an
    //  older binary does not chase a condition the current
    //  protocol model cannot produce.
    case ErrorCode::BridgeWatcherNotFound:
      return "No bridge watcher registered for this address "
             "(reserved; not emitted by the current node)";
    case ErrorCode::BridgeReadInternal:
      return "Bridge state read failed "
             "(reserved; not emitted by the current node)";

    case ErrorCode::BlockNotFound:
      return "Block not found";
    case ErrorCode::TransactionNotFound:
      return "Transaction not found";
    case ErrorCode::HistoricalQueryNotSupported:
      return "Historical state queries are not supported";
    case ErrorCode::ChainReadInternal:
      return "Chain read failed";

    case ErrorCode::ConsensusReadInternal:
      return "Consensus state read failed";

    case ErrorCode::AmmPoolEmpty:
      return "AMM pool has no liquidity";
    case ErrorCode::AmmSlippageTooHigh:
      return "Swap slippage exceeds the tolerance";

    case ErrorCode::Unauthorized:
      return "Admin token missing or invalid";
    case ErrorCode::RateLimited:
      return "Rate limit exceeded";
    }

    return "Unknown error";
  }

  //  mempoolResultToErrorCode

  ErrorCode mempoolResultToErrorCode(Core::MempoolAddResult result) noexcept
  {
    switch (result)
    {
    case Core::MempoolAddResult::Accepted:
      // Caller bug. Map to internal rather than crashing; better a
      // 500 to the client than an abort in production.
      return ErrorCode::InternalError;

    case Core::MempoolAddResult::Rejected_Malformed:
      return ErrorCode::TxMalformed;
    case Core::MempoolAddResult::Rejected_TooLarge:
      return ErrorCode::TxTooLarge;
    case Core::MempoolAddResult::Rejected_BadSignature:
      return ErrorCode::TxBadSignature;
    case Core::MempoolAddResult::Rejected_WrongChain:
      return ErrorCode::TxWrongChain;
    case Core::MempoolAddResult::Rejected_Expired:
      return ErrorCode::TxExpired;
    case Core::MempoolAddResult::Rejected_NonceTooLow:
      return ErrorCode::TxNonceTooLow;
    case Core::MempoolAddResult::Rejected_NonceConflict:
      return ErrorCode::TxNonceConflict;
    case Core::MempoolAddResult::Rejected_LowFee:
      return ErrorCode::TxFeeTooLow;
    case Core::MempoolAddResult::Rejected_HighFee:
      return ErrorCode::TxFeeTooHigh;
    case Core::MempoolAddResult::Rejected_InsufficientFunds:
      return ErrorCode::TxInsufficientFunds;
    case Core::MempoolAddResult::Rejected_PoolFull:
      return ErrorCode::TxPoolFull;

    //  The order-specific rejections already existed in the enum but
    //  had no mapping here, so they fell through to InternalError and
    //  the client saw "Internal error" for what was really a
    //  well-formed but invalid order. Map them to TxMalformed: the
    //  transaction's *payload* is the problem, and from the client's
    //  perspective that is a malformed transaction.
    case Core::MempoolAddResult::Rejected_OrderMalformed:
      return ErrorCode::TxMalformed;
    case Core::MempoolAddResult::Rejected_OrderPriceOverflow:
      return ErrorCode::TxMalformed;

    case Core::MempoolAddResult::Rejected_TokenPrecondition:
      return ErrorCode::TxPrecondition;

    //  Bridge rejections. The mempool runs the same signature
    //  checks the executor runs at apply time (see
    //  Node::verifyBridgeAttestationTxAtAdmission and
    //  Node::verifyGovernanceTxAtAdmission), against the same
    //  active validator set. A tx that fails them is well-formed
    //  at the byte level but cannot apply against the current tip,
    //  which is exactly what TxPrecondition means.
    //
    //  Rejected_BridgePayloadMalformed is structurally different:
    //  the payload bytes are in the wrong shape (wrong length, a
    //  declared count that overruns the buffer, a missing fixed
    //  field), so it maps to TxMalformed like every other
    //  malformed-payload rejection.
    //
    //  Neither gets a dedicated bridge-specific code. From the
    //  client's perspective the remedy is the same in both cases:
    //  fix the bridge transaction and resubmit. A future bridge
    //  failure that a client could act on differently — for
    //  example "quorum not yet reached, retry later" — would
    //  warrant a new code; these do not.
    case Core::MempoolAddResult::Rejected_BridgePayloadMalformed:
      return ErrorCode::TxMalformed;
    case Core::MempoolAddResult::Rejected_BridgeSignature:
      return ErrorCode::TxPrecondition;
    }

    return ErrorCode::InternalError;
  }

  //  makeError

  Common::Json makeError(ErrorCode code,
                         const char *message_override,
                         Common::Json data)
  {
    Common::Json err = Common::Json::object();
    err["code"] = static_cast<int32_t>(code);
    err["message"] = message_override != nullptr
                         ? std::string(message_override)
                         : std::string(errorCodeMessage(code));

    if (!data.is_null())
    {
      err["data"] = std::move(data);
    }

    return err;
  }

  //  makeErrorData

  Common::Json makeErrorData(ErrorCode code, Common::Json fields)
  {
    if (fields.is_null())
    {
      fields = Common::Json::object();
    }
    else if (!fields.is_object())
    {
      // Defensive: a caller passed a non-object (number, string).
      // Wrap it under "value" rather than silently dropping it.
      Common::Json wrapped = Common::Json::object();
      wrapped["value"] = std::move(fields);
      fields = std::move(wrapped);
    }

    // Insert `name` without overwriting a caller-provided one, on the
    // theory that a caller who passed `name` knows what they're doing.
    if (!fields.contains("name"))
    {
      fields["name"] = errorCodeName(code);
    }

    return fields;
  }

  namespace
  {
    thread_local std::string t_authorization;
  }

  const std::string &getCurrentAuthorization() noexcept
  {
    return t_authorization;
  }

  void setCurrentAuthorization(std::string value) noexcept
  {
    t_authorization = std::move(value);
  }
} // namespace Rpc