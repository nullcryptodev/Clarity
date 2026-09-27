// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Mempool.h"
#include "RPC/JsonRpcError.h"

using Common::Json;
using Rpc::ErrorCode;
using Rpc::errorCodeMessage;
using Rpc::errorCodeName;
using Rpc::makeError;
using Rpc::makeErrorData;
using Rpc::mempoolResultToErrorCode;

// ============================================================================
//  Name and message lookup
// ============================================================================

TEST(RPC_JsonRpcError, NamesAreStable)
{
  // These strings appear in logs and possibly in client code. If
  // any of them changes, it's a breaking change.
  EXPECT_STREQ(errorCodeName(ErrorCode::ParseError), "ParseError");
  EXPECT_STREQ(errorCodeName(ErrorCode::InvalidRequest), "InvalidRequest");
  EXPECT_STREQ(errorCodeName(ErrorCode::MethodNotFound), "MethodNotFound");
  EXPECT_STREQ(errorCodeName(ErrorCode::InvalidParams), "InvalidParams");
  EXPECT_STREQ(errorCodeName(ErrorCode::InternalError), "InternalError");
  EXPECT_STREQ(errorCodeName(ErrorCode::TxNonceTooLow), "TxNonceTooLow");
  EXPECT_STREQ(errorCodeName(ErrorCode::BlockNotFound), "BlockNotFound");
  EXPECT_STREQ(errorCodeName(ErrorCode::Unauthorized), "Unauthorized");
}

TEST(RPC_JsonRpcError, MessagesAreNonEmpty)
{
  // Every reserved code should have a human-readable message.
  for (auto code : {
           ErrorCode::ParseError,
           ErrorCode::InvalidRequest,
           ErrorCode::MethodNotFound,
           ErrorCode::InvalidParams,
           ErrorCode::InternalError,
           ErrorCode::TxNonceTooLow,
           ErrorCode::BlockNotFound,
           ErrorCode::Unauthorized})
  {
    EXPECT_GT(std::string(errorCodeMessage(code)).size(), 0u)
        << "empty message for code " << errorCodeName(code);
  }
}

// ============================================================================
//  MempoolAddResult mapping
// ============================================================================

TEST(RPC_JsonRpcError, EveryMempoolResultMaps)
{
  using Core::MempoolAddResult;

  // Every rejection reason must map to a distinct error code, and
  // none may map to Accepted's fallback (InternalError).
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_Malformed),
            ErrorCode::TxMalformed);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_TooLarge),
            ErrorCode::TxTooLarge);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_BadSignature),
            ErrorCode::TxBadSignature);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_WrongChain),
            ErrorCode::TxWrongChain);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_Expired),
            ErrorCode::TxExpired);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_NonceTooLow),
            ErrorCode::TxNonceTooLow);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_NonceConflict),
            ErrorCode::TxNonceConflict);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_LowFee),
            ErrorCode::TxFeeTooLow);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_HighFee),
            ErrorCode::TxFeeTooHigh);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_InsufficientFunds),
            ErrorCode::TxInsufficientFunds);
  EXPECT_EQ(mempoolResultToErrorCode(MempoolAddResult::Rejected_PoolFull),
            ErrorCode::TxPoolFull);
}

TEST(RPC_JsonRpcError, AcceptedMapsToInternalErrorAsFallback)
{
  // Passing Accepted to the mapper is a caller bug. We map it to
  // InternalError so a stray call shows up as a 500 rather than
  // silently succeeding.
  EXPECT_EQ(mempoolResultToErrorCode(Core::MempoolAddResult::Accepted),
            ErrorCode::InternalError);
}

// ============================================================================
//  Error object building
// ============================================================================

TEST(RPC_JsonRpcError, MakeErrorDefaultMessage)
{
  Json err = makeError(ErrorCode::InvalidParams);
  EXPECT_EQ(err["code"], static_cast<int32_t>(ErrorCode::InvalidParams));
  EXPECT_EQ(err["message"],
            std::string(errorCodeMessage(ErrorCode::InvalidParams)));
  EXPECT_FALSE(err.contains("data"));
}

TEST(RPC_JsonRpcError, MakeErrorOverrideMessage)
{
  Json err = makeError(ErrorCode::InvalidParams, "custom text");
  EXPECT_EQ(err["message"], "custom text");
}

TEST(RPC_JsonRpcError, MakeErrorWithData)
{
  Json data = {{"field", "address"}};
  Json err = makeError(ErrorCode::InvalidParams, nullptr, data);
  ASSERT_TRUE(err.contains("data"));
  EXPECT_EQ(err["data"]["field"], "address");
}

// ============================================================================
//  makeErrorData
// ============================================================================

TEST(RPC_JsonRpcError, MakeErrorDataAddsName)
{
  Json d = makeErrorData(ErrorCode::TxNonceTooLow);
  ASSERT_TRUE(d.is_object());
  EXPECT_EQ(d["name"], "TxNonceTooLow");
}

TEST(RPC_JsonRpcError, MakeErrorDataPreservesCallerName)
{
  Json d = makeErrorData(ErrorCode::TxNonceTooLow, {{"name", "custom"}});
  EXPECT_EQ(d["name"], "custom");
}

TEST(RPC_JsonRpcError, MakeErrorDataWrapsNonObject)
{
  // A caller who accidentally passed a scalar gets it wrapped under
  // "value" rather than dropped.
  Json d = makeErrorData(ErrorCode::TxNonceTooLow, Json(42));
  ASSERT_TRUE(d.is_object());
  EXPECT_EQ(d["value"], 42);
  EXPECT_EQ(d["name"], "TxNonceTooLow");
}

TEST(RPC_JsonRpcError, MakeErrorDataPreservesFields)
{
  Json d = makeErrorData(ErrorCode::TxFeeTooLow, {
                                                     {"expected", "0x5"},
                                                     {"got", "0x1"},
                                                 });
  EXPECT_EQ(d["expected"], "0x5");
  EXPECT_EQ(d["got"], "0x1");
  EXPECT_EQ(d["name"], "TxFeeTooLow");
}