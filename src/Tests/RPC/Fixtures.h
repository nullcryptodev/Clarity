// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#pragma once

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <string>

#include "Tests/Utils.h"

#include "Common/Json.h"
#include "Crypto/Types.h"
#include "Node/Node.h"
#include "Node/NodeConfig.h"
#include "RPC/JsonRpcDispatcher.h"
#include "RPC/Methods.h"
#include "RPC/Encoding.h"

namespace Tests
{
  //  One Node + one JsonRpcDispatcher, shared by every test in the
  //  suite via SetUpTestSuite. Individual tests are expected to be
  //  read-only against node state, or to reset any state they touch.
  //
  //  For tests that need a clean node per case, use
  //  RPC_MethodIsolatedFixture below.

  class RPC_MethodTestFixture : public ::testing::Test
  {
  protected:
    static void SetUpTestSuite()
    {
      static std::atomic<uint64_t> counter{0};
      s_data_dir = std::filesystem::temp_directory_path() /
                   ("rpc_shared_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(s_data_dir);

      s_node = std::make_unique<Node::Node>(
          makeNodeConfig(s_data_dir.string()), s_logger);
      s_node->start();

      Rpc::RpcConfig rpc_cfg = makeRpcConfig();
      s_dispatcher = std::make_unique<Rpc::JsonRpcDispatcher>(*s_node, rpc_cfg);
      registerAllNonAdminMethods(*s_dispatcher);
    };
    static void TearDownTestSuite()
    {
      s_dispatcher.reset();
      if (s_node)
      {
        s_node->stop();
        s_node.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(s_data_dir, ec);
    };

    // Per-test hooks. The shared fixture doesn't use them, but they
    // exist so a test can opt into its own node if needed.
    void SetUp() override
    {
      // Most tests use the shared node. This hook exists so a test can
      // set up its own instance if it needs one.
      node_ = nullptr;
      dispatcher_ = nullptr;
    };
    void TearDown() override
    {
      if (dispatcher_)
        dispatcher_.reset();
      if (node_)
      {
        node_->stop();
        node_.reset();
      }
    };

    // --- Dispatch helpers ---

    // Send a JSON-RPC request and return the full response envelope.
    Common::Json callRaw(const std::string &method,
                         const Common::Json &params = Common::Json::object(),
                         const Common::Json &id = 1)

    {
      Common::Json req = {
          {"jsonrpc", "2.0"},
          {"method", method},
          {"params", params},
          {"id", id},
      };

      Rpc::JsonRpcDispatcher &d = dispatcher_ ? *dispatcher_ : *s_dispatcher;
      auto dr = d.dispatchJson(req);
      return dr.response;
    };

    // Send a request, assert it succeeded, return the `result` field.
    // Fails the test via ADD_FAILURE if the response contains an error.
    Common::Json call(const std::string &method,
                      const Common::Json &params = Common::Json::object())
    {
      Common::Json resp = callRaw(method, params);
      if (resp.contains("error"))
      {
        ADD_FAILURE() << "unexpected error from " << method
                      << ": " << resp["error"].dump();
        return Common::Json{};
      }
      return resp.contains("result") ? resp["result"] : Common::Json{};
    };

    // Send a raw body directly to the dispatcher. Use this for
    // malformed-request tests where the body is deliberately not a
    // valid envelope.
    Common::Json dispatchRaw(const std::string &body)
    {
      Rpc::JsonRpcDispatcher &d = dispatcher_ ? *dispatcher_ : *s_dispatcher;
      auto dr = d.dispatchJson(Common::Json::parse(body));
      return dr.response;
    };

    // --- Address helpers ---

    // Encode a Crypto::Address as Bech32m for the node's network.
    std::string encodeAddr(const Crypto::Address &a) const
    {
      return Rpc::encodeAddress(a, GlobalConfig::REGTEST_HRP);
    };

    // Build a deterministic address from a single byte (repeated).
    static Crypto::Address addrFromByte(uint8_t b)
    {
      Crypto::Address a;
      std::fill(a.data.begin(), a.data.end(), b);
      return a;
    };

    // Build a deterministic address from an 8-byte big-endian value.
    static Crypto::Address addrFromU64(uint64_t v)
    {
      Crypto::Address a;
      std::fill(a.data.begin(), a.data.end(), 0);
      for (int i = 0; i < 8; ++i)
        a.data[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
      return a;
    };

    // --- Node accessors (for tests that need to poke state directly) ---

    Node::Node &node() { return *node_; }

    // --- Static shared state ---

    static std::unique_ptr<Node::Node> s_node;
    static std::unique_ptr<Rpc::JsonRpcDispatcher> s_dispatcher;
    static NoopLogger s_logger;
    static std::filesystem::path s_data_dir;

    // Per-test state (empty unless SetUp/TearDown are used).
    std::unique_ptr<Node::Node> node_;
    std::unique_ptr<Rpc::JsonRpcDispatcher> dispatcher_;
  };

  // ============================================================================
  //  RPC_MethodIsolatedFixture
  //
  //  Same interface, but creates a *fresh* node for every test. Use
  //  this for tests that mutate the node (submit txs, set config,
  //  shutdown) so they can't interfere with the shared node.
  //
  //  Slower than the shared fixture (~3-8s per test), so use sparingly.
  // ============================================================================

  class RPC_MethodIsolatedFixture : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      static std::atomic<uint64_t> counter{0};
      data_dir_ = std::filesystem::temp_directory_path() /
                  ("rpc_iso_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(data_dir_);

      node_ = std::make_unique<Node::Node>(
          makeNodeConfig(data_dir_.string()), logger_);
      node_->start();

      Rpc::RpcConfig rpc_cfg = makeRpcConfig();
      dispatcher_ = std::make_unique<Rpc::JsonRpcDispatcher>(*node_, rpc_cfg);
      registerAllNonAdminMethods(*dispatcher_);
    };
    void TearDown() override
    {
      dispatcher_.reset();
      if (node_)
      {
        node_->stop();
        node_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(data_dir_, ec);
    };

    Common::Json callRaw(const std::string &method,
                         const Common::Json &params = Common::Json::object(),
                         const Common::Json &id = 1)
    {
      Common::Json req = {
          {"jsonrpc", "2.0"},
          {"method", method},
          {"params", params},
          {"id", id},
      };
      auto dr = dispatcher_->dispatchJson(req);
      return dr.response;
    };

    Common::Json call(const std::string &method,
                      const Common::Json &params = Common::Json::object())
    {
      Common::Json resp = callRaw(method, params);
      if (resp.contains("error"))
      {
        ADD_FAILURE() << "unexpected error from " << method
                      << ": " << resp["error"].dump();
        return Common::Json{};
      }
      return resp.contains("result") ? resp["result"] : Common::Json{};
    };

    Common::Json dispatchRaw(const std::string &body)
    {
      auto dr = dispatcher_->dispatchJson(Common::Json::parse(body));
      return dr.response;
    };

    std::string encodeAddr(const Crypto::Address &a) const
    {
      return Rpc::encodeAddress(a, GlobalConfig::REGTEST_HRP);
    };

    static Crypto::Address addrFromByte(uint8_t b)
    {
      Crypto::Address a;
      std::fill(a.data.begin(), a.data.end(), b);
      return a;
    };
    static Crypto::Address addrFromU64(uint64_t v)
    {
      Crypto::Address a;
      std::fill(a.data.begin(), a.data.end(), 0);
      for (int i = 0; i < 8; ++i)
        a.data[i] = static_cast<uint8_t>((v >> (i * 8)) & 0xff);
      return a;
    };

    Node::Node &node() { return *node_; }

    NoopLogger logger_;
    std::filesystem::path data_dir_;
    std::unique_ptr<Node::Node> node_;
    std::unique_ptr<Rpc::JsonRpcDispatcher> dispatcher_;
  };

  class RPC_DispatcherFixture : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      // Unique temp dir per test. Node's constructor validates the
      // config and creates the data dir; we just need a valid path.
      tmp_dir_ = std::filesystem::temp_directory_path() /
                 ("rpc_dispatch_test_" +
                  std::to_string(::getpid()) + "_" +
                  std::to_string(reinterpret_cast<uintptr_t>(this)));

      std::filesystem::create_directories(tmp_dir_);

      Node::NodeConfig cfg;
      cfg.data_dir = tmp_dir_.string();
      cfg.network = Node::Network::Regtest;
      cfg.chain_id = 0x434C5247; // 'CLRG'
      cfg.enable_p2p = false;

      node_ = std::make_unique<Node::Node>(cfg, logger_);

      // Default config: RPC enabled, but nothing here actually opens a
      // socket — the dispatcher doesn't touch the HTTP layer.
      rpc_cfg_.enabled = true;

      dispatcher_ = std::make_unique<Rpc::JsonRpcDispatcher>(*node_, rpc_cfg_);

      registerTestMethods();
    }

    void TearDown() override
    {
      dispatcher_.reset();
      node_.reset();
      std::error_code ec;
      std::filesystem::remove_all(tmp_dir_, ec);
    }

    // ---- Test method registration ----
    //
    // We use names that don't clash with the real clrty_* methods.

    void registerTestMethods()
    {
      dispatcher_->registerMethod(
          "test_echo",
          [](Node::Node &, const Rpc::RpcConfig &, const Rpc::JsonRpcRequest &req) -> Common::Json
          {
            return req.params;
          });

      dispatcher_->registerMethod(
          "test_constant",
          [](Node::Node &, const Rpc::RpcConfig &, const Rpc::JsonRpcRequest &) -> Common::Json
          {
            return Common::Json("hello");
          });

      dispatcher_->registerMethod(
          "test_null_result",
          [](Node::Node &, const Rpc::RpcConfig &, const Rpc::JsonRpcRequest &) -> Common::Json
          {
            return Common::Json(nullptr);
          });

      dispatcher_->registerMethod(
          "test_method_error",
          [](Node::Node &, const Rpc::RpcConfig &, const Rpc::JsonRpcRequest &) -> Common::Json
          {
            throw Rpc::RpcMethodError(Rpc::ErrorCode::TxNonceTooLow, "expected 5, got 3",
                                      Common::Json({{"expected", "0x5"}}));
          });

      dispatcher_->registerMethod(
          "test_method_error_no_message",
          [](Node::Node &, const Rpc::RpcConfig &, const Rpc::JsonRpcRequest &) -> Common::Json
          {
            throw Rpc::RpcMethodError(Rpc::ErrorCode::BlockNotFound);
          });

      dispatcher_->registerMethod(
          "test_std_exception",
          [](Node::Node &, const Rpc::RpcConfig &, const Rpc::JsonRpcRequest &) -> Common::Json
          {
            throw std::runtime_error("something went wrong");
          });

      dispatcher_->registerMethod(
          "test_config_seen",
          [](Node::Node &, const Rpc::RpcConfig &cfg, const Rpc::JsonRpcRequest &) -> Common::Json
          {
            // Verify the config makes it through to the handler.
            return Common::Json({{"admin_enabled", !cfg.admin_token.empty()}});
          });
    }

    std::filesystem::path tmp_dir_;
    Tests::NoopLogger logger_;
    std::unique_ptr<Node::Node> node_;
    Rpc::RpcConfig rpc_cfg_;
    std::unique_ptr<Rpc::JsonRpcDispatcher> dispatcher_;
  };
} // namespace Tests