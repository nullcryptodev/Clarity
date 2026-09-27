// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/Json.h"
#include "RPC/JsonRpcError.h"
#include "RPC/JsonRpcRequest.h"

using Common::Json;
using Rpc::ErrorCode;
using Rpc::JsonRpcRequest;
using Rpc::parseRequest;
using Rpc::ParseResult;

namespace
{
  // Convenience: parse a request, assert success, return the request.
  // Fails the test if parsing fails.
  JsonRpcRequest mustParse(const Json &j)
  {
    ParseResult r = parseRequest(j);
    EXPECT_TRUE(r.ok) << "parse failed: " << r.error_message;
    return r.request;
  }

  // Convenience: parse a request, assert failure, return the result.
  ParseResult mustFail(const Json &j)
  {
    ParseResult r = parseRequest(j);
    EXPECT_FALSE(r.ok) << "expected parse to fail";
    return r;
  }
} // namespace

// ============================================================================
//  Valid requests
// ============================================================================

TEST(RPC_JsonRpcRequest, MinimalValidRequest)
{
  Json j = {{"jsonrpc", "2.0"}, {"method", "clrty_ping"}};

  auto req = mustParse(j);
  EXPECT_EQ(req.method, "clrty_ping");
  EXPECT_TRUE(req.params.is_object());
  EXPECT_TRUE(req.params.empty());
  EXPECT_TRUE(req.is_notification);
  EXPECT_TRUE(req.id.is_null());
}

TEST(RPC_JsonRpcRequest, FullRequestWithObjectParams)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_getBalance"},
      {"params", {{"address", "abc"}}},
      {"id", 42}};

  auto req = mustParse(j);
  EXPECT_EQ(req.method, "clrty_getBalance");
  EXPECT_FALSE(req.is_notification);
  EXPECT_EQ(req.id, 42);
  ASSERT_TRUE(req.params.contains("address"));
  EXPECT_EQ(req.params["address"], "abc");
}

TEST(RPC_JsonRpcRequest, StringId)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"id", "req-1"}};

  auto req = mustParse(j);
  EXPECT_FALSE(req.is_notification);
  EXPECT_EQ(req.id, "req-1");
}

TEST(RPC_JsonRpcRequest, NullIdIsNotification)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"id", nullptr}};

  auto req = mustParse(j);
  EXPECT_TRUE(req.is_notification);
  EXPECT_TRUE(req.id.is_null());
}

TEST(RPC_JsonRpcRequest, NullParamsTreatedAsEmpty)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"params", nullptr},
      {"id", 1}};

  auto req = mustParse(j);
  EXPECT_TRUE(req.params.is_object());
  EXPECT_TRUE(req.params.empty());
}

TEST(RPC_JsonRpcRequest, LargeIntegerIdAccepted)
{
  // 64-bit ids are legal. Only fractional numbers are rejected.
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"id", uint64_t(0xFFFFFFFFFFFFFFFFULL)}};

  auto req = mustParse(j);
  EXPECT_FALSE(req.is_notification);
  EXPECT_EQ(req.id.get<uint64_t>(), 0xFFFFFFFFFFFFFFFFULL);
}

// ============================================================================
//  Invalid: top-level shape
// ============================================================================

TEST(RPC_JsonRpcRequest, RejectsNonObject)
{
  EXPECT_FALSE(parseRequest(Json(42)).ok);
  EXPECT_FALSE(parseRequest(Json("hi")).ok);
  EXPECT_FALSE(parseRequest(Json::array({1, 2})).ok);
  EXPECT_FALSE(parseRequest(Json(nullptr)).ok);
}

TEST(RPC_JsonRpcRequest, RejectsUnknownTopLevelField)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"extra", "nope"}};

  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
  EXPECT_NE(r.error_message.find("extra"), std::string::npos);
}

// ============================================================================
//  Invalid: jsonrpc field
// ============================================================================

TEST(RPC_JsonRpcRequest, RejectsMissingJsonrpc)
{
  Json j = {{"method", "clrty_ping"}};
  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

TEST(RPC_JsonRpcRequest, RejectsNonStringJsonrpc)
{
  Json j = {{"jsonrpc", 2.0}, {"method", "clrty_ping"}};
  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

TEST(RPC_JsonRpcRequest, RejectsWrongJsonrpcVersion)
{
  for (const char *v : {"2", "2.1", "1.0", ""})
  {
    Json j = {{"jsonrpc", v}, {"method", "clrty_ping"}};
    auto r = mustFail(j);
    EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest) << "version=" << v;
  }
}

// ============================================================================
//  Invalid: method field
// ============================================================================

TEST(RPC_JsonRpcRequest, RejectsMissingMethod)
{
  Json j = {{"jsonrpc", "2.0"}};
  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

TEST(RPC_JsonRpcRequest, RejectsNonStringMethod)
{
  Json j = {{"jsonrpc", "2.0"}, {"method", 42}};
  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

TEST(RPC_JsonRpcRequest, RejectsEmptyMethod)
{
  Json j = {{"jsonrpc", "2.0"}, {"method", ""}};
  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

// ============================================================================
//  Invalid: params field
// ============================================================================

TEST(RPC_JsonRpcRequest, RejectsArrayParams)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"params", Json::array({1, 2, 3})}};

  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidParams);
  EXPECT_NE(r.error_message.find("array"), std::string::npos);
}

TEST(RPC_JsonRpcRequest, RejectsScalarParams)
{
  for (const auto &p : {Json(42), Json("hi"), Json(true)})
  {
    Json j = {
        {"jsonrpc", "2.0"},
        {"method", "clrty_ping"},
        {"params", p}};

    auto r = mustFail(j);
    EXPECT_EQ(r.error_code, ErrorCode::InvalidParams);
  }
}

// ============================================================================
//  Invalid: id field
// ============================================================================

TEST(RPC_JsonRpcRequest, RejectsFloatId)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"id", 1.5}};

  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

TEST(RPC_JsonRpcRequest, RejectsArrayId)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"id", Json::array({1, 2})}};

  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}

TEST(RPC_JsonRpcRequest, RejectsObjectId)
{
  Json j = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_ping"},
      {"id", {{"nested", 1}}}};

  auto r = mustFail(j);
  EXPECT_EQ(r.error_code, ErrorCode::InvalidRequest);
}