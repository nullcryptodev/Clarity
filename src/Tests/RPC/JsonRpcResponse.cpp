// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/Json.h"
#include "RPC/JsonRpcError.h"
#include "RPC/JsonRpcResponse.h"

using Common::Json;
using Rpc::ErrorCode;
using Rpc::JsonRpcResponse;
using Rpc::makeError;
using Rpc::serializeBatch;

TEST(RPC_JsonRpcResponse, SuccessEnvelope)
{
  Json result = {{"ok", true}};
  auto r = JsonRpcResponse::success(Json(1), result);

  Json j = r.toJson();
  EXPECT_EQ(j["jsonrpc"], "2.0");
  EXPECT_EQ(j["id"], 1);
  EXPECT_TRUE(j.contains("result"));
  EXPECT_FALSE(j.contains("error"));
  EXPECT_EQ(j["result"]["ok"], true);
}

TEST(RPC_JsonRpcResponse, SuccessWithNullResult)
{
  auto r = JsonRpcResponse::success(Json(1), Json(nullptr));

  Json j = r.toJson();
  // `result` is always present on success, even if null.
  EXPECT_TRUE(j.contains("result"));
  EXPECT_TRUE(j["result"].is_null());
  EXPECT_FALSE(j.contains("error"));
}

TEST(RPC_JsonRpcResponse, SuccessWithNullId)
{
  auto r = JsonRpcResponse::success(Json(nullptr), Json(42));

  Json j = r.toJson();
  EXPECT_TRUE(j.contains("id"));
  EXPECT_TRUE(j["id"].is_null());
}

TEST(RPC_JsonRpcResponse, ErrorEnvelope)
{
  Json err = makeError(ErrorCode::InvalidParams, "bad field");
  auto r = JsonRpcResponse::error(Json(7), err);

  Json j = r.toJson();
  EXPECT_EQ(j["jsonrpc"], "2.0");
  EXPECT_EQ(j["id"], 7);
  EXPECT_FALSE(j.contains("result"));
  EXPECT_TRUE(j.contains("error"));
  EXPECT_EQ(j["error"]["code"],
            static_cast<int32_t>(ErrorCode::InvalidParams));
  EXPECT_EQ(j["error"]["message"], "bad field");
}

TEST(RPC_JsonRpcResponse, IsSuccessAndIsErrorAreOpposite)
{
  auto ok = JsonRpcResponse::success(Json(1), Json(nullptr));
  EXPECT_TRUE(ok.isSuccess());
  EXPECT_FALSE(ok.isError());

  auto err = JsonRpcResponse::error(Json(1), makeError(ErrorCode::ParseError));
  EXPECT_FALSE(err.isSuccess());
  EXPECT_TRUE(err.isError());
}

TEST(RPC_JsonRpcResponse, ToStringIsCompact)
{
  auto r = JsonRpcResponse::success(Json(1), Json(nullptr));
  std::string s = r.toString();

  // No newlines. No spaces after `:` or `,`. Exact format is an
  // implementation detail of nlohmann::json but the compactness is
  // contractual for the wire.
  EXPECT_EQ(s.find('\n'), std::string::npos);
}

TEST(RPC_JsonRpcResponse, ToStringPrettyHasNewlines)
{
  auto r = JsonRpcResponse::success(Json(1), Json(nullptr));
  std::string s = r.toStringPretty();
  EXPECT_NE(s.find('\n'), std::string::npos);
}

TEST(RPC_JsonRpcResponse, SerializeBatchPreservesOrder)
{
  std::vector<JsonRpcResponse> batch;
  batch.push_back(JsonRpcResponse::success(Json(1), Json("a")));
  batch.push_back(JsonRpcResponse::success(Json(2), Json("b")));
  batch.push_back(JsonRpcResponse::success(Json(3), Json("c")));

  Json arr = serializeBatch(batch);
  ASSERT_TRUE(arr.is_array());
  ASSERT_EQ(arr.size(), 3u);
  EXPECT_EQ(arr[0]["id"], 1);
  EXPECT_EQ(arr[1]["id"], 2);
  EXPECT_EQ(arr[2]["id"], 3);
}

TEST(RPC_JsonRpcResponse, SerializeBatchEmptyReturnsNull)
{
  // A caller bug, but we return a sentinel rather than an invalid
  // empty array.
  Json arr = serializeBatch({});
  EXPECT_TRUE(arr.is_null());
}

TEST(RPC_JsonRpcResponse, SerializeBatchMixedSuccessError)
{
  std::vector<JsonRpcResponse> batch;
  batch.push_back(JsonRpcResponse::success(Json(1), Json("ok")));
  batch.push_back(JsonRpcResponse::error(
      Json(2), makeError(ErrorCode::MethodNotFound)));
  batch.push_back(JsonRpcResponse::success(Json(3), Json("also-ok")));

  Json arr = serializeBatch(batch);
  ASSERT_EQ(arr.size(), 3u);
  EXPECT_TRUE(arr[0].contains("result"));
  EXPECT_TRUE(arr[1].contains("error"));
  EXPECT_TRUE(arr[2].contains("result"));
}