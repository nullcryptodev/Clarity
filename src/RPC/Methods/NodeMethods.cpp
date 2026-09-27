// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "NodeMethods.h"

#include "Encoders/Encoding.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"
#include "Config.h"

#include "Core/Chain.h"
#include "Node/Node.h"
#include "P2P/P2PManager.h"

#include <chrono>

namespace Rpc
{

  namespace
  {
    constexpr const char *CLIENT_VERSION = "clrty/v1.0.0";

    // ---- clrty_ping ----
    //
    // No params. Returns "pong". Useful for smoke-testing the HTTP
    // layer before any state exists.

    Common::Json method_ping(Node::Node &, const RpcConfig &,
                             const JsonRpcRequest &)
    {
      return Common::Json("pong");
    }

    // ---- clrty_status ----
    //
    // No params. Returns the full Node::Status as JSON. This is the
    // primary "what's going on" endpoint.

    Common::Json method_status(Node::Node &node, const RpcConfig &,
                               const JsonRpcRequest &)
    {
      Node::Node::Status s = node.status();

      Common::Json j = Common::Json::object();
      putU64(j, "height", s.height);
      putU64(j, "best_peer_height", s.best_peer_height);
      putU64(j, "peer_count", static_cast<uint64_t>(s.peer_count));
      putU64(j, "mempool_size", static_cast<uint64_t>(s.mempool_size));
      putU64(j, "mempool_bytes", static_cast<uint64_t>(s.mempool_bytes));
      j["is_validator"] = s.is_validator;
      putU64(j, "validator_id", s.validator_id);
      putU64(j, "consensus_height", s.consensus_height);
      putU64(j, "consensus_round", s.consensus_round);
      j["consensus_step"] = s.consensus_step;
      j["network"] = Node::networkName(s.network);
      putU64(j, "chain_id", s.chain_id);
      j["running"] = s.running;

      // Extra fields computed on demand. These are cheap and every
      // operator wants them.
      putHash(j, "state_root", node.stateRoot());
      return j;
    }

    // ---- clrty_health ----
    //
    // No params. Lighter than clrty_status — just the fields a
    // health-check system needs.

    Common::Json method_health(Node::Node &node, const RpcConfig &,
                               const JsonRpcRequest &)
    {
      Node::Node::Status s = node.status();

      Common::Json j = Common::Json::object();
      j["ok"] = s.running;
      putU64(j, "height", s.height);
      putU64(j, "peers", static_cast<uint64_t>(s.peer_count));
      j["is_validator"] = s.is_validator;
      return j;
    }

    // ---- clrty_getPeers ----
    //
    // No params. Returns the list of known peers with per-peer
    // details. Uses P2PManager::peerList(), which posts to the P2P
    // event loop and blocks for the result.

    Common::Json method_getPeers(Node::Node &node, const RpcConfig &,
                                 const JsonRpcRequest &)
    {
      // node.p2p() isn't exposed — we go through status().peer_count
      // to decide whether to even try. If peer_count is 0, we can
      // short-circuit to an empty array without touching P2P.
      //
      // But we DO need the peerList API. Since Node doesn't expose
      // its P2PManager, this method can't be implemented directly.
      //
      // Options:
      //   (A) Add Node::p2pPeerList() forwarding to p2p_->peerList().
      //   (B) Add Node::p2p() returning P2PManager&.
      //
      // For v1 we use (A): a narrow forwarding method. See the
      // accompanying Node.cpp change.
      auto peers = node.p2pPeerList();

      Common::Json arr = Common::Json::array();
      for (const auto &p : peers)
      {
        Common::Json e = Common::Json::object();
        putU64(e, "id", p.id);
        e["ip"] = p.ip;
        e["port"] = p.port;
        e["direction"] = p.inbound ? "inbound" : "outbound";
        e["state"] = p.state;
        putU64(e, "best_height", p.best_height);
        e["agent"] = p.agent;
        putU64(e, "connected_at_ms", p.connected_at_ms);
        putU64(e, "last_recv_ms", p.last_recv_ms);
        putU64(e, "last_send_ms", p.last_send_ms);
        putU64(e, "misbehaviors", static_cast<uint64_t>(p.misbehaviors));
        arr.push_back(std::move(e));
      }

      Common::Json out = Common::Json::object();
      putU64(out, "count", static_cast<uint64_t>(peers.size()));
      out["peers"] = std::move(arr);
      return out;
    }

    // ---- clrty_getConfig ----
    //
    // No params. Returns a redacted view of the RPC configuration.
    // Does NOT return the admin token, even to an authenticated
    // caller — the token is a secret and never appears on the wire.

    Common::Json method_getConfig(Node::Node &, const RpcConfig &config,
                                  const JsonRpcRequest &)
    {
      Common::Json j = Common::Json::object();
      j["enabled"] = config.enabled;
      j["bind_address"] = config.bind_address;
      j["port"] = config.port;
      j["worker_threads"] = config.worker_threads;
      j["max_queued_connections"] = config.max_queued_connections;
      j["max_request_bytes"] = config.max_request_bytes;
      j["socket_timeout_seconds"] = config.socket_timeout_seconds;
      j["rate_limit_burst"] = config.rate_limit_burst;
      j["rate_limit_per_second"] = config.rate_limit_per_second;
      j["admin_enabled"] = !config.admin_token.empty();
      j["verbose_errors"] = config.verbose_errors;
      return j;
    }

    // ---- Compatibility shims ----

    Common::Json method_web3_clientVersion(Node::Node &, const RpcConfig &,
                                           const JsonRpcRequest &)
    {
      return Common::Json(CLIENT_VERSION);
    }

    Common::Json method_net_version(Node::Node &node, const RpcConfig &,
                                    const JsonRpcRequest &)
    {
      // Ethereum convention: decimal string of the chain id.
      std::string s = std::to_string(node.status().chain_id);
      return Common::Json(s);
    }

    Common::Json method_net_peerCount(Node::Node &node, const RpcConfig &,
                                      const JsonRpcRequest &)
    {
      // Ethereum convention: hex string.
      return Common::Json(encodeU64Hex(node.status().peer_count));
    }

    Common::Json method_net_listening(Node::Node &node, const RpcConfig &,
                                      const JsonRpcRequest &)
    {
      return Common::Json(node.status().peer_count > 0);
    }

  } // anonymous namespace

  void registerNodeMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_ping", method_ping);
    d.registerMethod("clrty_status", method_status);
    d.registerMethod("clrty_health", method_health);
    d.registerMethod("clrty_getPeers", method_getPeers);
    d.registerMethod("clrty_getConfig", method_getConfig);

    // Ethereum-style shims. Just enough for tooling that probes
    // these before deciding whether the endpoint is a chain.
    d.registerMethod("web3_clientVersion", method_web3_clientVersion);
    d.registerMethod("net_version", method_net_version);
    d.registerMethod("net_peerCount", method_net_peerCount);
    d.registerMethod("net_listening", method_net_listening);
  }

} // namespace Rpc