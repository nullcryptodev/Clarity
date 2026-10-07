#include <string>
#include <thread>

#include "Methods.h"
#include "Config.h"
#include "JsonRpcDispatcher.h"
#include "Encoding.h"
#include "Encoders.h"

#include "Core/TransactionExecutor.h"

#include "Node/Node.h"

#include "State/ProofKeys.h"

namespace Rpc
{
  namespace
  {
    constexpr const char *CLIENT_VERSION = "clrty/v1.0.0";

    // Helpers

    // Constant-time string comparison. The lengths must match
    // exactly; anything else returns false immediately. This is not
    // perfectly constant-time (it short-circuits on length) but
    // matches the token length to the request's, which is the
    // standard practice.
    bool constantTimeEq(const std::string &a, const std::string &b) noexcept
    {
      if (a.size() != b.size())
        return false;
      unsigned char diff = 0;
      for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
      return diff == 0;
    }

    void requireAdmin(const RpcConfig &config,
                      const std::string &authorization_header)
    {
      if (config.admin_token.empty())
      {
        // No token configured → admin methods don't exist.
        throw RpcMethodError(
            ErrorCode::MethodNotFound,
            "admin methods are disabled (no admin token configured)");
      }

      // Expect "Bearer <token>". Case-insensitive on "Bearer ".
      const std::string prefix = "Bearer ";
      if (authorization_header.size() < prefix.size() ||
          strncasecmp(authorization_header.c_str(),
                      prefix.c_str(), prefix.size()) != 0)
      {
        throw RpcMethodError(
            ErrorCode::Unauthorized,
            "missing or malformed Authorization header");
      }

      const std::string presented = authorization_header.substr(prefix.size());
      if (!constantTimeEq(presented, config.admin_token))
      {
        throw RpcMethodError(
            ErrorCode::Unauthorized,
            "invalid admin token");
      }
    }

    // Collect all validators into a vector via the index table.
    std::vector<Core::ValidatorInfo> loadAllValidators(
        State::StateAccess &state)
    {
      std::vector<Core::ValidatorInfo> out;
      state.forEachValidator([&out](const Core::ValidatorInfo &v)
                             { out.push_back(v); });
      return out;
    }

    // Load the active set as validator records. Missing ids are
    // silently skipped — the active set is only meaningful for ids
    // that have a live validator record.
    std::vector<Core::ValidatorInfo> loadActiveValidators(
        State::StateAccess &state)
    {
      std::vector<uint8_t> set_bytes;
      if (!state.getGlobal("active_set", set_bytes))
        return {};

      std::vector<Core::ValidatorInfo> out;
      size_t count = set_bytes.size() / 8;
      for (size_t i = 0; i < count; ++i)
      {
        uint64_t id = 0;
        for (int j = 0; j < 8; ++j)
          id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);

        Core::ValidatorInfo v;
        if (state.getValidator(id, v))
          out.push_back(v);
      }
      return out;
    }

    // Read the current chain height. Every state method opens its
    // StateAccess at this height. Historical reads are not supported
    // (see SparseMerkleTree::getAtVersion) so no height parameter is
    // accepted.
    uint64_t headHeight(Node::Node &node)
    {
      return node.chain().height();
    }

    // Parse an optional token_id param. Defaults to NATIVE_TOKEN_ID
    // (0) if absent.
    Id optionalTokenId(const Common::Json &params)
    {
      auto v = optionalU64(params, "token_id");
      return v.value_or(NATIVE_TOKEN_ID);
    }

    // Deserialize a hex-encoded transaction. Throws RpcMethodError on
    // any failure so every call site gets the same error semantics.
    Core::Transaction parseTxHex(const std::string &hex)
    {
      std::vector<uint8_t> bytes;
      if (!parseBytesHex(hex, bytes))
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'tx' must be 0x-prefixed even-length hex",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "tx"}}));
      }

      if (bytes.empty())
      {
        throw RpcMethodError(
            ErrorCode::TxMalformed,
            "transaction bytes are empty");
      }

      Core::Transaction tx;
      if (!Core::Transaction::deserialize(bytes.data(), bytes.size(), tx))
      {
        throw RpcMethodError(
            ErrorCode::TxMalformed,
            "transaction failed to deserialize");
      }

      return tx;
    }

    // Build the extra data for a mempool rejection. Includes the txid
    // so the client can correlate its submission with the error, even
    // though it could compute the hash itself.
    Common::Json rejectionData(const Core::Transaction &tx,
                               const std::string &error)
    {
      Common::Json d = Common::Json::object();
      d["tx_hash"] = encodeHash(tx.txid());
      if (!error.empty())
        d["reason"] = error;
      return d;
    }

    // Methods

    Common::Json method_shutdown(Node::Node &node,
                                 const RpcConfig &config,
                                 const JsonRpcRequest &)
    {
      requireAdmin(config, getCurrentAuthorization());

      // Trigger a graceful stop. Node::stop is documented as safe
      // from any thread and idempotent.
      //
      // The response is sent before the node actually stops because
      // the RPC worker thread returns from this handler and writes
      // the response, then the main thread observes the stop flag and
      // shuts down. If we blocked on node.stop() the RPC response
      // would never be delivered.
      //
      // We dispatch the stop call on a detached thread so the
      // handler can return immediately. This is the one case where a
      // detached thread is appropriate — it runs exactly once, has
      // no caller to report to, and the process is about to exit.
      std::thread([&node]()
                  {
        // Small delay so the HTTP response has time to flush.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        node.stop(); })
          .detach();

      Common::Json j = Common::Json::object();
      j["shutting_down"] = true;
      return j;
    }

    // ---- clrty_setLogLevel ----
    //
    // Params:
    //   level  (required, string: "debug"|"info"|"warn"|"error")
    //
    // Adjusts the log level at runtime. The ILogger interface would
    // need a setLevel() method for this to work; without one, we
    // return a "not supported" error. I've written this handler to
    // assume setLevel exists — if not, remove it and register
    // nothing for now.

    Common::Json method_setLogLevel(Node::Node &, const RpcConfig &config,
                                    const JsonRpcRequest &req)
    {
      requireAdmin(config, getCurrentAuthorization());

      const std::string level = requireString(req.params, "level");
      if (level != "debug" && level != "info" &&
          level != "warn" && level != "error")
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "level must be one of: debug, info, warn, error",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"level", level}}));
      }

      // TODO: call the node's logger to set the level. The ILogger
      // interface doesn't currently expose setLevel; add it when
      // this becomes a priority. For now, return a not-supported
      // error so clients know the endpoint exists but isn't wired.
      throw RpcMethodError(
          ErrorCode::InternalError,
          "runtime log level changes are not yet supported");
    }

    Common::Json method_getPool(Node::Node &node, const RpcConfig & /*config*/,
                                const JsonRpcRequest &req)
    {
      const Id pool_id = requireU64(req.params, "pool_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::AmmPool pool;
      if (!state.getAmmPool(pool_id, pool))
      {
        throw RpcMethodError(
            ErrorCode::PoolNotFound,
            "no pool with id " + encodeU64Hex(pool_id),
            makeErrorData(ErrorCode::PoolNotFound,
                          {{"pool_id", encodeU64Hex(pool_id)}}));
      }

      return encodeAmmPool(pool, hrp);
    }

    // ---- clrty_getPosition ----
    //
    // Params:
    //   position_id  (required, hex)
    //
    // Returns the position record plus the owning pool's share
    // calculation.

    Common::Json method_getPosition(Node::Node &node, const RpcConfig & /*config*/,
                                    const JsonRpcRequest &req)
    {
      const Id pos_id = requireU64(req.params, "position_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::AmmPosition pos;
      if (!state.getAmmPosition(pos_id, pos))
      {
        throw RpcMethodError(
            ErrorCode::PoolNotFound,
            "no position with id " + encodeU64Hex(pos_id),
            makeErrorData(ErrorCode::PoolNotFound,
                          {{"position_id", encodeU64Hex(pos_id)}}));
      }

      // Load the pool for share computation. Not fatal if missing.
      Core::AmmPool pool;
      bool have_pool = state.getAmmPool(pos.pool_id, pool);

      return encodeAmmPosition(pos, have_pool ? &pool : nullptr, hrp);
    }

    // ---- clrty_getPositionByOwner ----
    //
    // Params:
    //   address  (required, Bech32m or hex)
    //   pool_id  (required, hex)
    //
    // Returns the position owned by `address` in `pool_id`, if any.
    // Uses the (owner, pool_id) index, which enforces one position
    // per (owner, pool).

    Common::Json method_getPositionByOwner(Node::Node &node, const RpcConfig & /*config*/,
                                           const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address owner = requireAddress(req.params, "address", hrp);
      const Id pool_id = requireU64(req.params, "pool_id");
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      uint64_t pos_id = 0;
      if (!state.getPositionIndex(owner, pool_id, pos_id))
      {
        throw RpcMethodError(
            ErrorCode::PoolNotFound,
            "no position for this address in this pool",
            makeErrorData(ErrorCode::PoolNotFound,
                          {{"address", encodeAddress(owner, hrp)},
                           {"pool_id", encodeU64Hex(pool_id)}}));
      }

      Core::AmmPosition pos;
      if (!state.getAmmPosition(pos_id, pos))
      {
        // Index points at a position that doesn't exist. Internal
        // inconsistency.
        throw RpcMethodError(
            ErrorCode::StateReadInternal,
            "position index references a missing position",
            makeErrorData(ErrorCode::StateReadInternal,
                          {{"position_id", encodeU64Hex(pos_id)}}));
      }

      Core::AmmPool pool;
      bool have_pool = state.getAmmPool(pos.pool_id, pool);

      return encodeAmmPosition(pos, have_pool ? &pool : nullptr, hrp);
    }

    // ---- clrty_chainId ----

    Common::Json method_chainId(Node::Node &node, const RpcConfig & /*config*/,
                                const JsonRpcRequest &req)
    {
      Common::Json j = Common::Json::object();
      putU64(j, "chain_id", node.status().chain_id);
      return j;
    }

    // ---- clrty_blockNumber ----

    Common::Json method_blockNumber(Node::Node &node, const RpcConfig & /*config*/,
                                    const JsonRpcRequest &req)
    {
      Common::Json j = Common::Json::object();
      putU64(j, "height", node.chain().height());
      return j;
    }

    // ---- clrty_getBlockByNumber ----
    //
    // Params:
    //   height  (required, hex or decimal)
    //   full    (optional, bool, default false)

    Common::Json method_getBlockByNumber(Node::Node &node, const RpcConfig & /*config*/,
                                         const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");
      const bool full = optionalBool(req.params, "full").value_or(false);

      auto block = node.chain().getBlockByHeight(height);
      if (!block)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no block at height " + encodeU64Hex(height),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"height", encodeU64Hex(height)}}));
      }

      return encodeBlock(*block, full, hrpForNode(node));
    }

    // ---- clrty_getBlockByHash ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //   full  (optional, bool, default false)

    Common::Json method_getBlockByHash(Node::Node &node, const RpcConfig & /*config*/,
                                       const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");
      const bool full = optionalBool(req.params, "full").value_or(false);

      auto block = node.chain().getBlock(hash);
      if (!block)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no block with hash " + encodeHash(hash),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      return encodeBlock(*block, full, hrpForNode(node));
    }

    // ---- clrty_getBlockHeaderByNumber ----

    Common::Json method_getBlockHeaderByNumber(Node::Node &node, const RpcConfig & /*config*/,
                                               const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

      auto header = node.chainDB().getHeaderByHeight(height);
      if (!header)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no header at height " + encodeU64Hex(height),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"height", encodeU64Hex(height)}}));
      }

      return encodeBlockHeader(*header, hrpForNode(node));
    }

    // ---- clrty_getStateRoot ----
    //
    // Returns the state root at a given height. Uses the SMT's
    // rootAtVersion, which stores roots keyed by height. Only roots
    // that were committed with `save(version)` are retrievable; the
    // node commits a root per block, so this works for any height
    // that has been processed.
    //
    // NOTE: does NOT return the state *at* that height in the sense of
    // querying accounts as of then. Historical state reads are not
    // supported (see ErrorCode::HistoricalQueryNotSupported). This
    // method returns the root only, for proof verification.

    Common::Json method_getStateRoot(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

      // Open a throwaway StateAccess to read the historical root.
      // We don't need a txn — this is a read.
      State::StateAccess access(node.stateDB(), height);
      auto root = access.smtRootAtVersion(height);

      Common::Json j = Common::Json::object();
      putU64(j, "height", height);

      if (!root)
      {
        throw RpcMethodError(
            ErrorCode::BlockNotFound,
            "no committed state root at height " + encodeU64Hex(height),
            makeErrorData(ErrorCode::BlockNotFound,
                          {{"height", encodeU64Hex(height)}}));
      }

      putHash(j, "state_root", *root);
      return j;
    }

    // ---- clrty_getValidators ----
    //
    // Params:
    //   active_only  (optional, bool; default false)
    //
    // Returns the validator pool. With active_only=true, returns
    // only validators in the current active set. Both are sorted by
    // id for stable output.

    Common::Json method_getValidators(Node::Node &node, const RpcConfig & /*config*/,
                                      const JsonRpcRequest &req)
    {
      const bool active_only =
          optionalBool(req.params, "active_only").value_or(false);
      const std::string hrp = hrpForNode(node);
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      std::vector<Core::ValidatorInfo> validators =
          active_only ? loadActiveValidators(state)
                      : loadAllValidators(state);

      return encodeValidatorList(validators, height, hrp);
    }

    // ---- clrty_getValidator ----
    //
    // Params:
    //   id  (required, hex)
    //
    // Returns a single validator.

    Common::Json method_getValidator(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const Id id = requireU64(req.params, "id");
      const std::string hrp = hrpForNode(node);
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);
      Core::ValidatorInfo v;
      if (!state.getValidator(id, v))
      {
        throw RpcMethodError(
            ErrorCode::ValidatorNotFound,
            "no validator with id " + encodeU64Hex(id),
            makeErrorData(ErrorCode::ValidatorNotFound,
                          {{"id", encodeU64Hex(id)}}));
      }

      return encodeValidator(v, height, hrp);
    }

    // ---- clrty_getActiveSet ----
    //
    // No params.
    //
    // Returns just the active validator ids, plus the derived quorum
    // count. Lighter than clrty_getValidators when a client only
    // needs the set itself.

    Common::Json method_getActiveSet(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      std::vector<uint8_t> set_bytes;
      if (!state.getGlobal("active_set", set_bytes))
      {
        // No active set: empty response, but not an error. A node at
        // genesis has a set; an uninitialized node has none.
        Common::Json out = Common::Json::object();
        out["ids"] = Common::Json::array();
        putU64(out, "size", 0);
        putU64(out, "quorum", 0);
        return out;
      }

      Common::Json arr = Common::Json::array();
      size_t count = set_bytes.size() / 8;
      for (size_t i = 0; i < count; ++i)
      {
        uint64_t id = 0;
        for (int j = 0; j < 8; ++j)
          id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
        arr.push_back(encodeU64Hex(id));
      }

      Common::Json out = Common::Json::object();
      out["ids"] = std::move(arr);
      putU64(out, "size", static_cast<uint64_t>(count));
      putU64(out, "quorum", Core::bftQuorum(count));
      return out;
    }

    // ---- clrty_getValidatorByAddress ----
    //
    // Params:
    //   address  (required, Bech32m or hex)
    //
    // Returns the validator record whose reward_address matches the
    // given address, or throws ValidatorNotFound. This is a convenience
    // for clients that know an account address but not the validator ID.
    //
    // Uses the validator-by-address index, which is written at
    // registration and updated by UpdateRewardAddress.

    Common::Json method_getValidatorByAddress(
        Node::Node &node, const RpcConfig & /*config*/,
        const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      uint64_t validator_id = 0;
      if (!state.getValidatorByAddress(address, validator_id))
      {
        throw RpcMethodError(
            ErrorCode::ValidatorNotFound,
            "no validator registered for this address",
            makeErrorData(ErrorCode::ValidatorNotFound,
                          {{"address", encodeAddress(address, hrp)}}));
      }

      Core::ValidatorInfo v;
      if (!state.getValidator(validator_id, v))
      {
        //  Index points at a missing record. Internal inconsistency.
        throw RpcMethodError(
            ErrorCode::ConsensusReadInternal,
            "validator index references a missing record",
            makeErrorData(ErrorCode::ConsensusReadInternal,
                          {{"validator_id", encodeU64Hex(validator_id)}}));
      }

      return encodeValidator(v, height, hrp);
    }

    // ---- clrty_getConsensusState ----
    //
    // No params.
    //
    // Returns the current consensus progress: height, round, step,
    // and whether the node is a validator. Reads Node::Status, which
    // takes the status mutex.

    Common::Json method_getConsensusState(Node::Node &node, const RpcConfig & /*config*/,
                                          const JsonRpcRequest & /*req*/)
    {
      Node::Node::Status s = node.status();

      Common::Json out = Common::Json::object();
      putU64(out, "height", s.consensus_height);
      putU64(out, "round", s.consensus_round);
      out["step"] = s.consensus_step;
      out["is_validator"] = s.is_validator;
      putU64(out, "validator_id", s.validator_id);
      putU64(out, "chain_height", s.height);
      putU64(out, "best_peer_height", s.best_peer_height);
      return out;
    }

    // ---- clrty_getMempoolStats ----
    //
    // No params.
    //
    // Returns a snapshot of the mempool's size and fee distribution.
    // The `stats()` call takes the mempool's internal mutex and
    // iterates the pool; under a full mempool this is O(n). Callers
    // that poll this frequently should do so at a low rate.

    Common::Json method_getMempoolStats(Node::Node &node, const RpcConfig & /*config*/,
                                        const JsonRpcRequest & /*req*/)
    {
      Core::Mempool::Stats s = node.mempool().stats();

      Common::Json out = Common::Json::object();
      putU64(out, "total_txs", static_cast<uint64_t>(s.total_txs));
      putU64(out, "priority_txs", static_cast<uint64_t>(s.priority_txs));
      putU64(out, "standard_txs", static_cast<uint64_t>(s.standard_txs));
      putU64(out, "total_bytes", static_cast<uint64_t>(s.total_bytes));
      putU64(out, "min_fee_rate", s.min_fee_rate);
      putU64(out, "max_fee_rate", s.max_fee_rate);
      putU64(out, "avg_fee_rate", s.avg_fee_rate);
      return out;
    }

    // ---- clrty_getMempoolTx ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //
    // Returns the tx if it's in the mempool, or null if not. Unlike
    // clrty_getTransactionByHash, this does NOT fall back to the
    // chain — a miss means "not pending right now."

    Common::Json method_getMempoolTx(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");

      auto tx = node.mempool().get(hash);
      if (!tx.has_value())
      {
        return Common::Json(nullptr);
      }

      return encodeTransaction(*tx, hrpForNode(node));
    }

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

    // ---- clrty_getOrder ----
    //
    // Params:
    //   order_id  (required, hex)
    //
    // Returns the order record.

    Common::Json method_getOrder(Node::Node &node, const RpcConfig & /*config*/,
                                 const JsonRpcRequest &req)
    {
      const Id order_id = requireU64(req.params, "order_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::Order order;
      if (!state.getOrder(order_id, order))
      {
        throw RpcMethodError(
            ErrorCode::OrderNotFound,
            "no order with id " + encodeU64Hex(order_id),
            makeErrorData(ErrorCode::OrderNotFound,
                          {{"order_id", encodeU64Hex(order_id)}}));
      }

      return encodeOrder(order, hrp);
    }

    // ---- clrty_getOrdersExpiringAt ----
    //
    // Params:
    //   height  (required, hex or decimal)
    //
    // Returns the list of order ids that have an expiry condition
    // registered at the given height. This is the raw index entry,
    // not the full orders — clients can fetch each one with
    // clrty_getOrder if they need details.
    //
    // Most clients won't call this; it's mostly useful for debugging
    // order expiry behavior.

    Common::Json method_getOrdersExpiringAt(Node::Node &node, const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

      State::StateAccess state(node.stateDB(), node.chain().height());

      std::vector<uint64_t> ids = state.getOrdersExpiringAt(height);

      Common::Json arr = Common::Json::array();
      for (Id id : ids)
        arr.push_back(encodeU64Hex(id));

      Common::Json out = Common::Json::object();
      putU64(out, "height", height);
      putU64(out, "count", static_cast<uint64_t>(ids.size()));
      out["order_ids"] = std::move(arr);
      return out;
    }

    // ---- clrty_getBalance ----
    //
    // Params:
    //   address   (required, Bech32m or hex)
    //   token_id  (optional, hex; default 0 = native CLRTY)
    //
    // Returns:
    //   { "address": <Bech32m>, "token_id": "0x0", "balance": "0x..." }
    //
    // For the native token, balance is Account.balance. For a custom
    // token, it's the token-balance SMT entry.

    Common::Json method_getBalance(Node::Node &node, const RpcConfig & /*config*/,
                                   const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);
      const Id token_id = optionalTokenId(req.params);

      State::StateAccess state(node.stateDB(), headHeight(node));

      uint64_t balance = 0;
      if (token_id == NATIVE_TOKEN_ID)
      {
        balance = state.getAccount(address).balance;
      }
      else
      {
        balance = state.getTokenBalance(address, token_id);
      }

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "token_id", token_id);
      putU64(out, "balance", balance);
      return out;
    }

    // ---- clrty_getProof ----
    //
    // Params:
    //   key_type    (required, integer 0..4)
    //   key_bytes   (required, 0x-prefixed hex; layout per key_type)
    //   version     (optional, hex or "current"; default "current")
    //
    // Returns:
    //   {
    //     "status":      "ok" | "key_not_found" | "version_unavailable" | "malformed",
    //     "state_root":  "0x...",
    //     "version":     "0x...",
    //     "proof":       "0x..."        // present only when status == "ok"
    //   }
    //
    //  The proof is the serialized SmtProof, hex-encoded. A client
    //  verifies it with State::verifyProof(state_root, proof) after
    //  deserializing.
    //
    //  This is a *trusting* query from the server's perspective: the
    //  server returns whatever proof it can produce, and the client
    //  decides whether to believe it by verifying against a root it
    //  trusts. A client that doesn't trust the server's root should
    //  obtain the root from an independent source and verify the
    //  proof itself.
    //
    //  The P2P GetProof message provides the same functionality over
    //  the peer-to-peer layer. This method is the RPC-facing
    //  counterpart, intended for tooling that already trusts its RPC
    //  endpoint (or verifies the proof against a separately-obtained
    //  root).

    Common::Json method_getProof(Node::Node &node, const RpcConfig & /*config*/,
                                 const JsonRpcRequest &req)
    {
      //  key_type: required integer 0..4.
      auto key_type_u64 = optionalU64(req.params, "key_type");
      if (!key_type_u64.has_value())
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'key_type' is required",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "key_type"}}));
      }
      if (*key_type_u64 > 4)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'key_type' must be 0..4",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "key_type"},
                           {"value", encodeU64Hex(*key_type_u64)}}));
      }
      const auto key_type = static_cast<State::ProofKeyType>(*key_type_u64);

      //  key_bytes: required hex.
      const std::string key_hex = requireString(req.params, "key_bytes");
      std::vector<uint8_t> key_bytes;
      if (!parseBytesHex(key_hex, key_bytes))
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'key_bytes' must be 0x-prefixed even-length hex",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "key_bytes"}}));
      }

      //  Resolve the key. A malformed descriptor is a client bug and
      //  the client should not retry it — we report it as InvalidParams
      //  rather than a status field, since the message shape is wrong
      //  before the server can even ask the tree.
      auto key = State::resolveProofKey(key_type, key_bytes);
      if (!key.has_value())
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "key_bytes does not match the layout for key_type",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"key_type", encodeU64Hex(*key_type_u64)}}));
      }

      //  version: optional. "current" or the sentinel means "the head
      //  height". A 0x-prefixed hex integer means that exact version.
      uint64_t version = State::PROOF_VERSION_CURRENT;
      if (req.params.contains("version") && !req.params["version"].is_null())
      {
        const auto &v = req.params["version"];
        if (!v.is_string())
        {
          throw RpcMethodError(
              ErrorCode::InvalidParams,
              "field 'version' must be a string",
              makeErrorData(ErrorCode::InvalidParams,
                            {{"field", "version"}}));
        }

        const std::string s = v.get<std::string>();
        if (s == "current")
        {
          version = State::PROOF_VERSION_CURRENT;
        }
        else
        {
          //  parseHexU64 in RPC/Encoding.h takes an out-parameter and
          //  returns bool. It requires the 0x prefix.
          uint64_t parsed = 0;
          if (!parseHexU64(s, parsed))
          {
            throw RpcMethodError(
                ErrorCode::InvalidParams,
                "field 'version' must be 0x-prefixed hex or the "
                "string 'current'",
                makeErrorData(ErrorCode::InvalidParams,
                              {{"field", "version"}}));
          }
          version = parsed;
        }
      }

      const uint64_t resolved_version =
          (version == State::PROOF_VERSION_CURRENT)
              ? node.chain().height()
              : version;

      //  Look up the version's root. If there is none, we can't
      //  produce a proof against it.
      State::StateAccess state(node.stateDB(), resolved_version);

      auto root = state.smtRootAtVersion(resolved_version);
      if (!root.has_value())
      {
        throw RpcMethodError(
            ErrorCode::ProofVersionUnavailable,
            "no committed state root at version " +
                encodeU64Hex(resolved_version),
            makeErrorData(ErrorCode::ProofVersionUnavailable,
                          {{"version", encodeU64Hex(resolved_version)}}));
      }

      //  Produce the proof. The StateAccess was constructed at
      //  resolved_version, so its tree's nodes match — see the
      //  contract comment on StateAccess::proveAtVersion.
      auto proof = state.proveAtVersion(*key, resolved_version);
      if (!proof.has_value())
      {
        throw RpcMethodError(
            ErrorCode::ProofNotAvailable,
            "could not produce a proof for this key at this version",
            makeErrorData(ErrorCode::ProofNotAvailable,
                          {{"version", encodeU64Hex(resolved_version)},
                           {"key_type", encodeU64Hex(*key_type_u64)}}));
      }

      const auto proof_bytes = proof->serialize();

      Common::Json out = Common::Json::object();
      out["status"] = "ok";
      putHash(out, "state_root", *root);
      putU64(out, "version", resolved_version);
      out["proof"] = encodeBytesHex(proof_bytes);
      return out;
    }

    // ---- clrty_getAccount ----
    //
    // Params:
    //   address  (required)
    //
    // Returns the full Account record. Does not throw on missing
    // accounts — the zero account is returned, matching StateAccess's
    // behavior. The `is_empty` field lets a client distinguish "this
    // account exists and holds nothing" from "this account has never
    // been touched."

    Common::Json method_getAccount(Node::Node &node, const RpcConfig & /*config*/,
                                   const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), headHeight(node));
      Core::Account account = state.getAccount(address);

      Common::Json out = encodeAccount(account);
      putAddress(out, "address", address, hrp);
      return out;
    }

    // ---- clrty_getNonce ----
    //
    // Params:
    //   address  (required)
    //
    // Returns:
    //   { "address": <Bech32m>, "nonce": "0x..." }
    //
    // The nonce is the "next expected nonce". A tx from this address
    // must carry exactly this value to be accepted by the mempool
    // (or a higher value, which will queue).

    Common::Json method_getNonce(Node::Node &node, const RpcConfig & /*config*/,
                                 const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), headHeight(node));
      Core::Account account = state.getAccount(address);

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "nonce", account.nonce);
      return out;
    }

    // ---- clrty_getTokenInfo ----
    //
    // Params:
    //   token_id  (required, hex)
    //
    // Returns the TokenInfo record. Token 0 is the native CLRTY
    // token; its record is written at genesis and always exists.

    Common::Json method_getTokenInfo(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const Id token_id = requireU64(req.params, "token_id");

      State::StateAccess state(node.stateDB(), headHeight(node));
      Core::TokenInfo token;
      if (!state.getToken(token_id, token))
      {
        throw RpcMethodError(
            ErrorCode::TokenNotFound,
            "no token with id " + encodeU64Hex(token_id),
            makeErrorData(ErrorCode::TokenNotFound,
                          {{"token_id", encodeU64Hex(token_id)}}));
      }

      return encodeToken(token, hrpForNode(node));
    }

    // ---- clrty_getTokenSupply ----
    //
    // Params:
    //   token_id  (required, hex)
    //
    // Returns the cumulative minted supply. For the native token, reads
    // the `total_supply` global. For custom tokens, reads the per-token
    // supply entry maintained by mint/burn.
    //
    // Note: the native token's supply is stored in global state under
    // "total_supply"; custom tokens have their own supply SMT entry.
    // See StateAccess::getTokenSupply.

    Common::Json method_getTokenSupply(Node::Node &node, const RpcConfig & /*config*/,
                                       const JsonRpcRequest &req)
    {
      const Id token_id = requireU64(req.params, "token_id");

      State::StateAccess state(node.stateDB(), headHeight(node));

      uint64_t supply = 0;
      if (token_id == NATIVE_TOKEN_ID)
      {
        std::vector<uint8_t> bytes;
        if (state.getGlobal("total_supply", bytes) && bytes.size() == 8)
        {
          for (int i = 0; i < 8; ++i)
            supply |= uint64_t(bytes[i]) << (i * 8);
        }
      }
      else
      {
        supply = state.getTokenSupply(token_id);
      }

      Common::Json out = Common::Json::object();
      putU64(out, "token_id", token_id);
      putU64(out, "supply", supply);
      return out;
    }

    // ---- clrty_sendRawTransaction ----
    //
    // Params:
    //   tx  (required, 0x-prefixed hex of a serialized signed Transaction)
    //
    // Returns on success:
    //   { "tx_hash": "0x...", "accepted": true }
    //
    // On mempool rejection: throws RpcMethodError with the code
    // mapped from MempoolAddResult, and data = {tx_hash, reason}.

    Common::Json method_sendRawTransaction(Node::Node &node, const RpcConfig & /*config*/,
                                           const JsonRpcRequest &req)
    {
      const std::string tx_hex = requireString(req.params, "tx");
      Core::Transaction tx = parseTxHex(tx_hex);

      std::string error;
      Core::MempoolAddResult result = node.submitTransaction(tx, error);

      if (result != Core::MempoolAddResult::Accepted)
      {
        ErrorCode code = mempoolResultToErrorCode(result);
        throw RpcMethodError(
            code,
            error.empty() ? nullptr : error.c_str(),
            makeErrorData(code, rejectionData(tx, error)));
      }

      Common::Json out = Common::Json::object();
      putHash(out, "tx_hash", tx.txid());
      out["accepted"] = true;
      return out;
    }

    // ---- clrty_getTransactionByHash ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //
    // Returns the transaction with its location if it exists either
    // in the mempool or in a committed block. `status` is one of
    // "pending" or "confirmed". For pending txs, the block fields
    // are null.

    Common::Json method_getTransactionByHash(Node::Node &node, const RpcConfig & /*config*/,
                                             const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");
      const std::string hrp = hrpForNode(node);

      // ---- Mempool first ----
      auto pending = node.mempool().get(hash);
      if (pending.has_value())
      {
        Common::Json out = Common::Json::object();
        out["tx"] = encodeTransaction(*pending, hrp);
        out["status"] = "pending";
        out["block_hash"] = nullptr;
        out["block_height"] = nullptr;
        out["index"] = nullptr;
        return out;
      }

      // ---- Committed ----
      auto loc = node.chainDB().getTxLocation(hash);
      if (!loc.has_value())
      {
        throw RpcMethodError(
            ErrorCode::TransactionNotFound,
            "transaction not found in mempool or chain",
            makeErrorData(ErrorCode::TransactionNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      auto block = node.chain().getBlock(loc->block_hash);
      if (!block.has_value())
      {
        // Tx index points to a block we don't have. Chain and index
        // are out of sync — this is an internal inconsistency.
        throw RpcMethodError(
            ErrorCode::ChainReadInternal,
            "tx index references a block that is not stored",
            makeErrorData(ErrorCode::ChainReadInternal,
                          {{"block_hash", encodeHash(loc->block_hash)}}));
      }

      if (loc->tx_index >= block->transactions.size())
      {
        throw RpcMethodError(
            ErrorCode::ChainReadInternal,
            "tx index points past the end of the block",
            makeErrorData(ErrorCode::ChainReadInternal,
                          {{"index", loc->tx_index},
                           {"tx_count", block->transactions.size()}}));
      }

      const Core::Transaction &tx = block->transactions[loc->tx_index];

      Common::Json out = Common::Json::object();
      out["tx"] = encodeTransaction(tx, hrp);
      out["status"] = "confirmed";
      putHash(out, "block_hash", loc->block_hash);
      putU64(out, "block_height", loc->block_height);
      out["index"] = loc->tx_index;
      return out;
    }

    // ---- clrty_getTransactionReceipt ----
    //
    // Params:
    //   hash  (required, 0x-prefixed)
    //
    // Returns the consensus receipt (status + fee_paid) plus the
    // block position. This is NOT a full Ethereum-style receipt:
    // there are no logs, no gas, no return data. See Receipt.h.

    Common::Json method_getTransactionReceipt(Node::Node &node, const RpcConfig & /*config*/,
                                              const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");

      auto loc = node.chainDB().getTxLocation(hash);
      if (!loc.has_value())
      {
        throw RpcMethodError(
            ErrorCode::ReceiptNotFound,
            "no receipt: transaction is not confirmed",
            makeErrorData(ErrorCode::ReceiptNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      State::StateAccess state(node.stateDB(), loc->block_height);
      Core::Receipt receipt;
      if (!state.getReceipt(hash, receipt))
      {
        // Tx index says it's in this block, but no receipt exists.
        // This can happen if the block was committed before the
        // receipt was written. In practice they're written in the
        // same txn, so this is an internal inconsistency.
        throw RpcMethodError(
            ErrorCode::ReceiptNotFound,
            "tx index has the transaction but no receipt is stored",
            makeErrorData(ErrorCode::ReceiptNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      Common::Json out = encodeReceipt(receipt);
      putHash(out, "tx_hash", hash);
      putHash(out, "block_hash", loc->block_hash);
      putU64(out, "block_height", loc->block_height);
      out["index"] = loc->tx_index;
      return out;
    }

    // ---- clrty_simulateTransaction ----
    //
    // Params:
    //   tx  (required, 0x-prefixed hex)
    //
    // Executes the tx against a throwaway state txn and returns the
    // resulting receipt. Nothing is persisted. Useful for wallets
    // that want to check "would this succeed?" before broadcasting.
    //
    // Caveats:
    //   - Uses the chain head as the state context. No `height`
    //     parameter yet; add later if simulations need to run against
    //     a specific block.
    //   - Holds a write txn for the duration. Two concurrent calls
    //     will serialize — the second throws because beginWrite fails
    //     with MDBX_BUSY. The dispatcher maps that to InternalError.
    //   - The receipt reflects the executor's outcome, which includes
    //     the fee charge before dispatch. On success, fee_paid equals
    //     tx.fee. On failure, it usually still equals tx.fee (the
    //     executor always charges the fee).

    Common::Json method_simulateTransaction(Node::Node &node, const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const std::string tx_hex = requireString(req.params, "tx");
      Core::Transaction tx = parseTxHex(tx_hex);

      const uint64_t height = node.chain().height();
      const uint64_t chain_id = node.status().chain_id;

      // The throwaway txn. Everything inside is discarded by abort().
      State::StateDB::Txn txn = node.stateDB().beginWrite();

      Core::Receipt receipt;
      try
      {
        State::StateAccess state(node.stateDB(), txn, height);

        Core::TxExecutionContext ctx;
        ctx.current_height = height;
        ctx.chain_id = chain_id;
        ctx.tx_index_in_block = 0;

        receipt = Core::TransactionExecutor::execute(state, tx, ctx);

        // Whether we throw or not, we never commit.
        txn.abort();
      }
      catch (...)
      {
        // Ensure the txn is discarded even if execute threw.
        txn.abort();
        throw;
      }

      Common::Json out = encodeReceipt(receipt);
      putHash(out, "tx_hash", tx.txid());
      putU64(out, "height", height);
      return out;
    }

    // ---- clrty_getRecentBlocks ----
    //
    // Params:
    //   limit  (optional, hex or decimal; default 10; max 100)
    //
    // Returns:
    //   { "blocks": [ <header>, <header>, ... ], "count": <number> }
    //
    // Headers are newest first: blocks[0] is the tip. If the chain is
    // shorter than `limit`, returns what exists without error.

    Common::Json method_getRecentBlocks(Node::Node &node,
                                        const RpcConfig & /*config*/,
                                        const JsonRpcRequest &req)
    {
      uint64_t limit = 10;
      if (auto v = optionalU64(req.params, "limit"); v.has_value())
        limit = *v;

      if (limit == 0 || limit > 100)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'limit' must be 1..100",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "limit"},
                           {"value", encodeU64Hex(limit)}}));
      }

      const uint64_t tip = node.chain().height();
      const std::string hrp = hrpForNode(node);

      Common::Json arr = Common::Json::array();

      // Tip is height 0 at genesis; walk back to 0, then stop.
      uint64_t h = tip;
      uint64_t taken = 0;
      while (taken < limit)
      {
        auto header = node.chainDB().getHeaderByHeight(h);
        if (!header.has_value())
        {
          // A gap in the chain. This shouldn't happen — heights are
          // contiguous from genesis — but if it does, stop rather
          // than throwing. Returning fewer rows is more useful to a
          // client than an error.
          break;
        }

        arr.push_back(encodeBlockHeader(*header, hrp));
        ++taken;

        if (h == 0)
          break; // reached genesis
        --h;
      }

      Common::Json out = Common::Json::object();
      putU64(out, "count", taken);
      out["blocks"] = std::move(arr);
      return out;
    }

    // ---- clrty_getRecentTransactions ----
    //
    // Params:
    //   limit  (optional, hex or decimal; default 10; max 100)
    //
    // Returns:
    //   {
    //     "count": <number>,
    //     "transactions": [
    //       {
    //         "tx":           <transaction object>,
    //         "block_hash":   "0x...",
    //         "block_height": "0x...",
    //         "index":        <number>,
    //       },
    //       ...
    //     ]
    //   }
    //
    // Newest first: transactions[0] is the most recent confirmation.
    //
    // Implementation: walk headers back from the tip, collect the
    // heights whose tx_count > 0, then load those blocks in full
    // and pull transactions. We stop once we have `limit` txs.
    //
    // Worst case: a chain with many empty blocks. We bound the scan
    // to a configurable maximum (MAX_HEADER_SCAN) so a pathological
    // chain can't make a single RPC call walk thousands of headers.

    Common::Json method_getRecentTransactions(Node::Node &node,
                                              const RpcConfig & /*config*/,
                                              const JsonRpcRequest &req)
    {
      constexpr uint64_t MAX_HEADER_SCAN = 200;

      uint64_t limit = 10;
      if (auto v = optionalU64(req.params, "limit"); v.has_value())
        limit = *v;

      if (limit == 0 || limit > 100)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'limit' must be 1..100",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "limit"},
                           {"value", encodeU64Hex(limit)}}));
      }

      const uint64_t tip = node.chain().height();
      const std::string hrp = hrpForNode(node);

      Common::Json arr = Common::Json::array();
      uint64_t collected = 0;

      uint64_t h = tip;
      uint64_t scanned = 0;
      while (collected < limit && scanned < MAX_HEADER_SCAN)
      {
        auto header = node.chainDB().getHeaderByHeight(h);
        if (!header.has_value())
          break;

        ++scanned;

        if (header->tx_count > 0)
        {
          auto block = node.chain().getBlockByHeight(h);
          if (block.has_value())
          {
            // Walk within the block newest-index-first. Within a
            // block, transactions have an implicit order; we emit
            // them in the order the block stores them (ascending
            // index), which matches how they were applied.
            for (size_t i = 0; i < block->transactions.size(); ++i)
            {
              if (collected >= limit)
                break;

              Common::Json entry = Common::Json::object();
              entry["tx"] = encodeTransaction(block->transactions[i], hrp);
              putHash(entry, "block_hash", block->header.hash());
              putU64(entry, "block_height", block->header.height);
              entry["index"] = i;

              arr.push_back(std::move(entry));
              ++collected;
            }
          }
        }

        if (h == 0)
          break;
        --h;
      }

      Common::Json out = Common::Json::object();
      putU64(out, "count", collected);
      out["transactions"] = std::move(arr);
      return out;
    }

    // ---- clrty_getMempoolList ----
    //
    // Params:
    //   limit  (optional, hex or decimal; default 50; max 500)
    //
    // Returns the current mempool contents, sorted by fee rate
    // descending, then by insertion time ascending. This is the
    // order the block builder will prefer.
    //
    // Response:
    //   {
    //     "count":  <hex>,   // number of entries in this response
    //     "total":  <hex>,   // total entries in the pool
    //     "transactions": [
    //       {
    //         "tx":        <transaction object>,
    //         "fee_rate":  <hex>,  // atomic units per byte
    //         "added_ms":  <hex>,  // wall-clock ms when it entered
    //         "tier":      "priority" | "standard",
    //         "size":      <hex>   // serialized byte size
    //       },
    //       ...
    //     ]
    //   }

    Common::Json method_getMempoolList(Node::Node &node,
                                       const RpcConfig & /*config*/,
                                       const JsonRpcRequest &req)
    {
      uint64_t limit = 50;
      if (auto v = optionalU64(req.params, "limit"); v.has_value())
        limit = *v;

      if (limit == 0 || limit > 500)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'limit' must be 1..500",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "limit"},
                           {"value", encodeU64Hex(limit)}}));
      }

      auto entries = node.mempool().snapshot();

      // Sort: fee rate desc, then added_ms asc (older first on ties).
      //
      // Rationale: the next proposer will pick the highest-fee-rate
      // txs first. Ties broken by "who got there first", which is
      // both fairer and matches the mempool's own eviction order
      // (FIFO within a fee tier).
      std::sort(entries.begin(), entries.end(),
                [](const Core::Mempool::Snapshot &a,
                   const Core::Mempool::Snapshot &b)
                {
                  if (a.fee_rate != b.fee_rate)
                    return a.fee_rate > b.fee_rate;
                  return a.added_at_ms < b.added_at_ms;
                });

      const std::string hrp = hrpForNode(node);
      const uint64_t total = static_cast<uint64_t>(entries.size());

      Common::Json arr = Common::Json::array();
      uint64_t count = 0;

      for (const auto &e : entries)
      {
        if (count >= limit)
          break;

        Common::Json entry = Common::Json::object();
        entry["tx"] = encodeTransaction(e.tx, hrp);
        putU64(entry, "fee_rate", e.fee_rate);
        putU64(entry, "added_ms", e.added_at_ms);
        putU64(entry, "size", static_cast<uint64_t>(e.tx_size));
        entry["tier"] =
            (e.tier == Core::FeeTier::Priority) ? "priority" : "standard";

        arr.push_back(std::move(entry));
        ++count;
      }

      Common::Json out = Common::Json::object();
      putU64(out, "count", count);
      putU64(out, "total", total);
      out["transactions"] = std::move(arr);
      return out;
    }
  } // anon namespace

  void registerAdminMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("shutdown", method_shutdown);
    d.registerMethod("setLogLevel", method_setLogLevel);
  }

  void registerAmmMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getPool", method_getPool);
    d.registerMethod("getPosition", method_getPosition);
    d.registerMethod("getPositionByOwner", method_getPositionByOwner);
  }

  void registerChainMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("chainId", method_chainId);
    d.registerMethod("blockNumber", method_blockNumber);
    d.registerMethod("getBlockByNumber", method_getBlockByNumber);
    d.registerMethod("getBlockByHash", method_getBlockByHash);
    d.registerMethod("getBlockHeaderByNumber", method_getBlockHeaderByNumber);
    d.registerMethod("getRecentBlocks", method_getRecentBlocks);
    d.registerMethod("getStateRoot", method_getStateRoot);
  }

  void registerConsensusMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getValidators", method_getValidators);
    d.registerMethod("getValidator", method_getValidator);
    d.registerMethod("getValidatorByAddress", method_getValidatorByAddress);
    d.registerMethod("getActiveSet", method_getActiveSet);
    d.registerMethod("getConsensusState", method_getConsensusState);
  }

  void registerMempoolMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getMempoolStats", method_getMempoolStats);
    d.registerMethod("getMempoolTx", method_getMempoolTx);
    d.registerMethod("getMempoolList", method_getMempoolList);
  }

  void registerNodeMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("ping", method_ping);
    d.registerMethod("status", method_status);
    d.registerMethod("health", method_health);
    d.registerMethod("getPeers", method_getPeers);
    d.registerMethod("getConfig", method_getConfig);

    // Ethereum-style shims. Just enough for tooling that probes
    // these before deciding whether the endpoint is a chain.
    d.registerMethod("web3_clientVersion", method_web3_clientVersion);
    d.registerMethod("net_version", method_net_version);
    d.registerMethod("net_peerCount", method_net_peerCount);
    d.registerMethod("net_listening", method_net_listening);
  }

  void registerOrderMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getOrder", method_getOrder);
    d.registerMethod("getOrdersExpiringAt", method_getOrdersExpiringAt);
  }

  void registerStateMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getBalance", method_getBalance);
    d.registerMethod("getAccount", method_getAccount);
    d.registerMethod("getNonce", method_getNonce);
    d.registerMethod("getTokenInfo", method_getTokenInfo);
    d.registerMethod("getTokenSupply", method_getTokenSupply);
    d.registerMethod("getProof", method_getProof);
  }

  void registerTxMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("sendRawTransaction", method_sendRawTransaction);
    d.registerMethod("getTransactionByHash", method_getTransactionByHash);
    d.registerMethod("getTransactionReceipt", method_getTransactionReceipt);
    d.registerMethod("simulateTransaction", method_simulateTransaction);
    d.registerMethod("getRecentTransactions", method_getRecentTransactions);
  }
}