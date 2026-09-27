// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <filesystem>
#include <stdexcept>
#include <string>

#include "Fixtures.h"
#include "Tests/Logger.h"

#include "Common/Json.h"
#include "Node/Node.h"
#include "Node/NodeConfig.h"
#include "RPC/JsonRpcDispatcher.h"
#include "RPC/JsonRpcError.h"
#include "RPC/JsonRpcRequest.h"
#include "RPC/JsonRpcResponse.h"
#include "RPC/Config.h"

using Common::Json;
using Rpc::ErrorCode;
using Rpc::JsonRpcDispatcher;
using Rpc::JsonRpcRequest;
using Rpc::RpcConfig;
using Rpc::RpcMethodError;

using namespace Tests;

// ============================================================================
//  Dispatch: single valid requests
// ============================================================================

TEST_F(RPC_DispatcherFixture, DispatchReturnsHandlerResult)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_constant"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  EXPECT_EQ(j["id"], 1);
  EXPECT_EQ(j["result"], "hello");
}

TEST_F(RPC_DispatcherFixture, DispatchEchoesParams)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_echo"},
      {"params", {{"foo", "bar"}, {"n", 42}}},
      {"id", "abc"}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  EXPECT_EQ(j["id"], "abc");
  EXPECT_EQ(j["result"]["foo"], "bar");
  EXPECT_EQ(j["result"]["n"], 42);
}

TEST_F(RPC_DispatcherFixture, NullResultIsPresent)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_null_result"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  EXPECT_TRUE(j.contains("result"));
  EXPECT_TRUE(j["result"].is_null());
  EXPECT_FALSE(j.contains("error"));
}

// ============================================================================
//  Dispatch: errors
// ============================================================================

TEST_F(RPC_DispatcherFixture, UnknownMethodReturnsMethodNotFound)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_nonexistent"},
      {"id", 5}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  EXPECT_TRUE(j.contains("error"));
  EXPECT_EQ(j["error"]["code"],
            static_cast<int32_t>(ErrorCode::MethodNotFound));
  EXPECT_EQ(j["id"], 5);
}

TEST_F(RPC_DispatcherFixture, RpcMethodErrorIsConverted)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_method_error"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  ASSERT_TRUE(j.contains("error"));
  EXPECT_EQ(j["error"]["code"],
            static_cast<int32_t>(ErrorCode::TxNonceTooLow));
  EXPECT_EQ(j["error"]["message"], "expected 5, got 3");
  ASSERT_TRUE(j["error"].contains("data"));
  EXPECT_EQ(j["error"]["data"]["expected"], "0x5");
}

TEST_F(RPC_DispatcherFixture, RpcMethodErrorWithoutMessageUsesDefault)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_method_error_no_message"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  ASSERT_TRUE(j.contains("error"));
  EXPECT_EQ(j["error"]["code"],
            static_cast<int32_t>(ErrorCode::BlockNotFound));
  // Message is the default for the code, not empty.
  EXPECT_FALSE(j["error"]["message"].get<std::string>().empty());
}

TEST_F(RPC_DispatcherFixture, StdExceptionBecomesInternalError)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_std_exception"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  ASSERT_TRUE(j.contains("error"));
  EXPECT_EQ(j["error"]["code"],
            static_cast<int32_t>(ErrorCode::InternalError));
  // The internal message must NOT leak to the client.
  std::string msg = j["error"]["message"].get<std::string>();
  EXPECT_EQ(msg.find("something went wrong"), std::string::npos);
}

// ============================================================================
//  Config plumbing
// ============================================================================

TEST_F(RPC_DispatcherFixture, HandlersReceiveConfig)
{
  // No admin token: admin_enabled should be false.
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_config_seen"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  EXPECT_EQ(j["result"]["admin_enabled"], false);
}

// ============================================================================
//  Notifications
// ============================================================================

TEST_F(RPC_DispatcherFixture, NotificationProducesNoResponse)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_constant"}}; // no id

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);
  ASSERT_TRUE(parsed.request.is_notification);

  auto result = dispatcher_->dispatchJson(req);
  EXPECT_TRUE(result.is_empty);
  EXPECT_FALSE(result.is_batch);
}

TEST_F(RPC_DispatcherFixture, NotificationWithBadMethodStillProducesNothing)
{
  // Per the spec, a notification never gets a response, even on
  // error. The client has explicitly opted out of receiving one.
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_nonexistent"}};

  auto result = dispatcher_->dispatchJson(req);
  EXPECT_TRUE(result.is_empty);
}

// ============================================================================
//  dispatchJson: single requests
// ============================================================================

TEST_F(RPC_DispatcherFixture, DispatchJsonSingleSuccess)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "test_constant"},
      {"id", 42}};

  auto result = dispatcher_->dispatchJson(req);
  EXPECT_FALSE(result.is_batch);
  EXPECT_FALSE(result.is_empty);
  ASSERT_TRUE(result.response.is_object());
  EXPECT_EQ(result.response["id"], 42);
  EXPECT_EQ(result.response["result"], "hello");
}

TEST_F(RPC_DispatcherFixture, DispatchJsonParseErrorProducesErrorResponse)
{
  // Missing jsonrpc field.
  Json req = {{"method", "test_constant"}, {"id", 1}};

  auto result = dispatcher_->dispatchJson(req);
  EXPECT_FALSE(result.is_empty);
  ASSERT_TRUE(result.response.is_object());
  ASSERT_TRUE(result.response.contains("error"));
  EXPECT_EQ(result.response["error"]["code"],
            static_cast<int32_t>(ErrorCode::InvalidRequest));
  // The id couldn't be trusted (the request was malformed), so it's
  // echoed as null.
  EXPECT_TRUE(result.response["id"].is_null());
}

TEST_F(RPC_DispatcherFixture, DispatchJsonNonObjectNonArray)
{
  auto result = dispatcher_->dispatchJson(Json(42));
  EXPECT_FALSE(result.is_empty);
  ASSERT_TRUE(result.response.is_object());
  ASSERT_TRUE(result.response.contains("error"));
  EXPECT_EQ(result.response["error"]["code"],
            static_cast<int32_t>(ErrorCode::InvalidRequest));
}

// ============================================================================
//  dispatchJson: batches
// ============================================================================

TEST_F(RPC_DispatcherFixture, BatchPreservesOrder)
{
  Json batch = Json::array({
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}, {"id", 1}},
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}, {"id", 2}},
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}, {"id", 3}},
  });

  auto result = dispatcher_->dispatchJson(batch);
  EXPECT_TRUE(result.is_batch);
  ASSERT_TRUE(result.response.is_array());
  ASSERT_EQ(result.response.size(), 3u);
  EXPECT_EQ(result.response[0]["id"], 1);
  EXPECT_EQ(result.response[1]["id"], 2);
  EXPECT_EQ(result.response[2]["id"], 3);
}

TEST_F(RPC_DispatcherFixture, BatchMixedValidAndInvalid)
{
  Json batch = Json::array({
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}, {"id", 1}},
      Json{{"method", "test_constant"}, {"id", 2}}, // malformed
      Json{{"jsonrpc", "2.0"}, {"method", "test_nope"}, {"id", 3}},
  });

  auto result = dispatcher_->dispatchJson(batch);
  EXPECT_TRUE(result.is_batch);
  ASSERT_EQ(result.response.size(), 3u);

  // First: success.
  EXPECT_TRUE(result.response[0].contains("result"));
  EXPECT_EQ(result.response[0]["id"], 1);

  // Second: invalid request (jsonrpc missing), id null.
  EXPECT_TRUE(result.response[1].contains("error"));
  EXPECT_TRUE(result.response[1]["id"].is_null());

  // Third: method not found.
  EXPECT_TRUE(result.response[2].contains("error"));
  EXPECT_EQ(result.response[2]["id"], 3);
  EXPECT_EQ(result.response[2]["error"]["code"],
            static_cast<int32_t>(ErrorCode::MethodNotFound));
}

TEST_F(RPC_DispatcherFixture, BatchOfNotificationsIsEmpty)
{
  Json batch = Json::array({
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}},
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}},
  });

  auto result = dispatcher_->dispatchJson(batch);
  EXPECT_TRUE(result.is_batch);
  EXPECT_TRUE(result.is_empty);
}

TEST_F(RPC_DispatcherFixture, BatchSomeNotifications)
{
  // A batch with one valid request and one notification should
  // produce a single-element array.
  Json batch = Json::array({
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}, {"id", 7}},
      Json{{"jsonrpc", "2.0"}, {"method", "test_constant"}},
  });

  auto result = dispatcher_->dispatchJson(batch);
  EXPECT_TRUE(result.is_batch);
  EXPECT_FALSE(result.is_empty);
  ASSERT_TRUE(result.response.is_array());
  EXPECT_EQ(result.response.size(), 1u);
  EXPECT_EQ(result.response[0]["id"], 7);
}

TEST_F(RPC_DispatcherFixture, EmptyBatchIsInvalidRequest)
{
  Json batch = Json::array();
  auto result = dispatcher_->dispatchJson(batch);
  EXPECT_FALSE(result.is_batch);
  ASSERT_TRUE(result.response.is_object());
  ASSERT_TRUE(result.response.contains("error"));
  EXPECT_EQ(result.response["error"]["code"],
            static_cast<int32_t>(ErrorCode::InvalidRequest));
}

// ============================================================================
//  Introspection
// ============================================================================

TEST_F(RPC_DispatcherFixture, MethodNamesIncludesRegisteredAndBuiltins)
{
  auto names = dispatcher_->methodNames();

  // test methods
  EXPECT_NE(std::find(names.begin(), names.end(), "test_constant"), names.end());
  EXPECT_NE(std::find(names.begin(), names.end(), "test_echo"), names.end());

  // built-in clrty_methods is registered by the dispatcher itself
  EXPECT_NE(std::find(names.begin(), names.end(), "clrty_methods"), names.end());

  // sorted
  EXPECT_TRUE(std::is_sorted(names.begin(), names.end()));
}

TEST_F(RPC_DispatcherFixture, HasMethod)
{
  EXPECT_TRUE(dispatcher_->hasMethod("test_constant"));
  EXPECT_TRUE(dispatcher_->hasMethod("clrty_methods"));
  EXPECT_FALSE(dispatcher_->hasMethod("no_such_method"));
}

TEST_F(RPC_DispatcherFixture, ClrtyMethodsListsItself)
{
  Json req = {
      {"jsonrpc", "2.0"},
      {"method", "clrty_methods"},
      {"id", 1}};

  auto parsed = Rpc::parseRequest(req);
  ASSERT_TRUE(parsed.ok);

  auto resp = dispatcher_->dispatch(parsed.request);
  Json j = resp.toJson();
  ASSERT_TRUE(j.contains("result"));
  ASSERT_TRUE(j["result"].contains("methods"));
  ASSERT_TRUE(j["result"]["methods"].is_array());

  // Every name is a string.
  for (const auto &m : j["result"]["methods"])
    EXPECT_TRUE(m.is_string());
}