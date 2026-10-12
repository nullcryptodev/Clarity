// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <thread>
#include <algorithm>
#include <unordered_set>

#include "Methods.h"
#include "Config.h"
#include "JsonRpcDispatcher.h"
#include "Encoding.h"
#include "Encoders.h"

#include "Core/TransactionExecutor.h"
#include "Core/RewardCalculator.h"

#include "Node/Node.h"

#include "State/ProofKeys.h"

namespace Rpc
{
  namespace
  {
    //  Default page size for list endpoints. Every list handler uses
    //  this unless it passes an explicit cap.
    constexpr uint64_t DEFAULT_LIST_LIMIT = 50;
    constexpr uint64_t MAX_LIST_LIMIT = 500;

    bool constantTimeEq(const std::string &a, const std::string &b) noexcept
    {
      if (a.size() != b.size())
        return false;
      unsigned char diff = 0;
      for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
      return diff == 0;
    }

    void requireAdmin(const RpcConfig &config, const std::string &authorization_header)
    {
      if (config.admin_token.empty())
      {
        throw RpcMethodError(
            ErrorCode::MethodNotFound,
            "admin methods are disabled (no admin token configured)"
        );
      }

      const std::string prefix = "Bearer ";
      if (authorization_header.size() < prefix.size() ||
          strncasecmp(authorization_header.c_str(), prefix.c_str(), prefix.size()) != 0)
      {
        throw RpcMethodError(
            ErrorCode::Unauthorized,
            "missing or malformed Authorization header"
        );
      }

      const std::string presented = authorization_header.substr(prefix.size());
      if (!constantTimeEq(presented, config.admin_token))
      {
        throw RpcMethodError(
            ErrorCode::Unauthorized,
            "invalid admin token"
        );
      }
    }

    std::vector<Core::ValidatorInfo> loadAllValidators(State::StateAccess &state)
    {
      std::vector<Core::ValidatorInfo> out;
      state.forEachValidator([&out](const Core::ValidatorInfo &v)
      {
        out.push_back(v);
      });
      return out;
    }

    std::vector<Core::ValidatorInfo> loadActiveValidators(State::StateAccess &state)
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

    uint64_t headHeight(Node::Node &node)
    {
      return node.chain().height();
    }

    Id optionalTokenId(const Common::Json &params)
    {
      auto v = optionalU64(params, "token_id");
      return v.value_or(NATIVE_TOKEN_ID);
    }

    Core::Transaction parseTxHex(const std::string &hex)
    {
      std::vector<uint8_t> bytes;
      if (!parseBytesHex(hex, bytes))
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'tx' must be 0x-prefixed even-length hex",
            makeErrorData(ErrorCode::InvalidParams,
            {
              {"field", "tx"}
            })
        );
      }

      if (bytes.empty())
      {
        throw RpcMethodError(
            ErrorCode::TxMalformed,
            "transaction bytes are empty"
        );
      }

      Core::Transaction tx;
      if (!Core::Transaction::deserialize(bytes.data(), bytes.size(), tx))
      {
        throw RpcMethodError(
            ErrorCode::TxMalformed,
            "transaction failed to deserialize"
        );
      }

      return tx;
    }

    Common::Json rejectionData(const Core::Transaction &tx, const std::string &error)
    {
      Common::Json d = Common::Json::object();
      d["tx_hash"] = encodeHash(tx.txid());
      if (!error.empty())
        d["reason"] = error;
      return d;
    }

    struct PageParams
    {
      uint64_t limit{DEFAULT_LIST_LIMIT};
      uint64_t offset{0};
    };

    PageParams parsePageParams(const Common::Json &params, uint64_t max_limit = MAX_LIST_LIMIT)
    {
      PageParams p;
      if (auto v = optionalU64(params, "limit"); v.has_value())
        p.limit = *v;
      if (auto v = optionalU64(params, "offset"); v.has_value())
        p.offset = *v;

      if (p.limit == 0 || p.limit > max_limit)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'limit' must be 1.." + std::to_string(max_limit),
            makeErrorData(ErrorCode::InvalidParams,
            {
              {"field", "limit"},
              {"value", encodeU64Hex(p.limit)}
            })
        );
      }
      return p;
    }

    uint64_t readU64Global(State::StateAccess &state, const char *name)
    {
      std::vector<uint8_t> bytes;
      if (!state.getGlobal(name, bytes) || bytes.size() != 8)
        return 0;

      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(bytes[i]) << (i * 8);
      return v;
    }

    struct BalanceEntry
    {
      Crypto::Address address;
      uint64_t amount{0};
    };

    bool cmpAmountDesc(const BalanceEntry &a, const BalanceEntry &b)
    {
      if (a.amount != b.amount)
        return a.amount > b.amount;
      return std::memcmp(a.address.data.data(),
                         b.address.data.data(), 32) < 0;
    }

    uint64_t sumTxCountInWindow(Node::Node &node, uint64_t tip, uint64_t window)
    {
      uint64_t total = 0;
      uint64_t h = tip;
      uint64_t scanned = 0;

      while (scanned < window && h <= tip)
      {
        auto header = node.chainDB().getHeaderByHeight(h);
        if (!header.has_value())
          break;
        total += header->tx_count;
        ++scanned;
        if (h == 0)
          break;
        --h;
      }

      return total;
    }

    uint64_t sumFeesInWindow(Node::Node &node, uint64_t tip, uint64_t window)
    {
      uint64_t total = 0;
      uint64_t h = tip;
      uint64_t scanned = 0;

      while (scanned < window && h <= tip)
      {
        auto header = node.chainDB().getHeaderByHeight(h);
        if (!header.has_value())
          break;
        total += header->total_fees;
        ++scanned;
        if (h == 0)
          break;
        --h;
      }

      return total;
    }

    Common::Json method_shutdown(Node::Node &node, const RpcConfig &config, const JsonRpcRequest &)
    {
      requireAdmin(config, getCurrentAuthorization());

      std::thread([&node]()
                  {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        node.stop(); })
          .detach();

      Common::Json j = Common::Json::object();
      j["shutting_down"] = true;
      return j;
    }

    Common::Json method_setLogLevel(Node::Node &,
                                    const RpcConfig &config,
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
            {
              {"level", level}
            })
        );
      }

      throw RpcMethodError(
          ErrorCode::InternalError,
          "runtime log level changes are not yet supported"
      );
    }

    Common::Json method_getPool(Node::Node &node,
                                const RpcConfig & /*config*/,
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
            {
              {"pool_id", encodeU64Hex(pool_id)}
            })
        );
      }

      return encodeAmmPool(pool, hrp);
    }

    Common::Json method_getPosition(Node::Node &node,
                                    const RpcConfig & /*config*/,
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
            {
              {"position_id", encodeU64Hex(pos_id)}
            })
        );
      }

      Core::AmmPool pool;
      bool have_pool = state.getAmmPool(pos.pool_id, pool);

      return encodeAmmPosition(pos, have_pool ? &pool : nullptr, hrp);
    }

    Common::Json method_getPositionByOwner(Node::Node &node,
                                           const RpcConfig & /*config*/,
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
            {
              {"address", encodeAddress(owner, hrp)},
              {"pool_id", encodeU64Hex(pool_id)}
            })
        );
      }

      Core::AmmPosition pos;
      if (!state.getAmmPosition(pos_id, pos))
      {
        throw RpcMethodError(
            ErrorCode::StateReadInternal,
            "position index references a missing position",
            makeErrorData(ErrorCode::StateReadInternal,
            {
              {"position_id", encodeU64Hex(pos_id)}
            })
        );
      }

      Core::AmmPool pool;
      bool have_pool = state.getAmmPool(pos.pool_id, pool);

      return encodeAmmPosition(pos, have_pool ? &pool : nullptr, hrp);
    }

    Common::Json method_getAllPools(Node::Node &node,
                                    const RpcConfig & /*config*/,
                                    const JsonRpcRequest &req)
    {
      const PageParams page = parsePageParams(req.params);
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachAmmPool([&](const Core::AmmPool &pool)
      {
        if (seen < page.offset)
        {
          ++seen;
          return;
        }
        if (emitted >= page.limit)
          return;
        arr.push_back(encodeAmmPool(pool, hrp));
        ++emitted;
      });

      Common::Json out = Common::Json::object();
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["pools"] = std::move(arr);
      return out;
    }

    Common::Json method_getPoolsForToken(Node::Node &node,
                                         const RpcConfig & /*config*/,
                                         const JsonRpcRequest &req)
    {
      const Id token_id = requireU64(req.params, "token_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);

      Common::Json arr = Common::Json::array();

      state.forEachPoolForToken(token_id, [&](const Core::AmmPool &pool)
      {
        arr.push_back(encodeAmmPool(pool, hrp));
      });

      Common::Json out = Common::Json::object();
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["pools"] = std::move(arr);
      return out;
    }

    Common::Json method_getPositionsForPool(Node::Node &node,
                                            const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const Id pool_id = requireU64(req.params, "pool_id");
      const PageParams page = parsePageParams(req.params);
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);

      std::vector<Core::AmmPosition> matches;

      state.forEachAmmPosition([&](const Core::AmmPosition &pos)
      {
        if (pos.pool_id == pool_id)
          matches.push_back(pos);
      });

      std::sort(matches.begin(), matches.end(), [](const Core::AmmPosition &a, const Core::AmmPosition &b)
      {
        if (a.liquidity != b.liquidity)
          return a.liquidity > b.liquidity;
        return a.id < b.id;
      });

      Common::Json arr = Common::Json::array();
      uint64_t emitted = 0;

      for (size_t i = page.offset; i < matches.size(); ++i)
      {
        if (emitted >= page.limit)
          break;

        Core::AmmPool pool;
        const bool have_pool = state.getAmmPool(matches[i].pool_id, pool);

        arr.push_back(encodeAmmPosition(matches[i], have_pool ? &pool : nullptr, hrp));
        ++emitted;
      }

      Common::Json out = Common::Json::object();
      putU64(out, "pool_id", pool_id);
      putU64(out, "count", emitted);
      putU64(out, "total", static_cast<uint64_t>(matches.size()));
      out["positions"] = std::move(arr);
      return out;
    }

    Common::Json method_chainId(Node::Node &node,
                                const RpcConfig & /*config*/,
                                const JsonRpcRequest &req)
    {
      Common::Json j = Common::Json::object();
      putU64(j, "chain_id", node.status().chain_id);
      return j;
    }

    Common::Json method_blockNumber(Node::Node &node,
                                    const RpcConfig & /*config*/,
                                    const JsonRpcRequest &req)
    {
      Common::Json j = Common::Json::object();
      putU64(j, "height", node.chain().height());
      return j;
    }

    Common::Json method_getBlockByNumber(Node::Node &node,
                                         const RpcConfig & /*config*/,
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
            {
              {"height", encodeU64Hex(height)}
            })
        );
      }

      return encodeBlock(*block, full, hrpForNode(node));
    }

    Common::Json method_getBlockByHash(Node::Node &node,
                                       const RpcConfig & /*config*/,
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
            {
              {"hash", encodeHash(hash)}
            })
        );
      }

      return encodeBlock(*block, full, hrpForNode(node));
    }

    Common::Json method_getBlockHeaderByNumber(Node::Node &node,
                                               const RpcConfig & /*config*/,
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
            {
              {"height", encodeU64Hex(height)}
            })
        );
      }

      return encodeBlockHeader(*header, hrpForNode(node));
    }

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
            {
              {"field", "limit"},
              {"value", encodeU64Hex(limit)}
            })
        );
      }

      const uint64_t tip = node.chain().height();
      const std::string hrp = hrpForNode(node);

      Common::Json arr = Common::Json::array();

      uint64_t h = tip;
      uint64_t taken = 0;
      while (taken < limit)
      {
        auto header = node.chainDB().getHeaderByHeight(h);
        if (!header.has_value())
        {
          break;
        }

        arr.push_back(encodeBlockHeader(*header, hrp));
        ++taken;

        if (h == 0)
          break;
        --h;
      }

      Common::Json out = Common::Json::object();
      putU64(out, "count", taken);
      out["blocks"] = std::move(arr);
      return out;
    }

    Common::Json method_getStateRoot(Node::Node &node,
                                     const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const uint64_t height = requireU64(req.params, "height");

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
            {
              {"height", encodeU64Hex(height)}
            })
        );
      }

      putHash(j, "state_root", *root);
      return j;
    }

    Common::Json method_getBlocksRange(Node::Node &node,
                                       const RpcConfig & /*config*/,
                                       const JsonRpcRequest &req)
    {
      const uint64_t start = requireU64(req.params, "start");

      uint64_t count = 50;
      if (auto v = optionalU64(req.params, "count"); v.has_value())
        count = *v;

      if (count == 0 || count > 100)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'count' must be 1..100",
            makeErrorData(ErrorCode::InvalidParams,
            {
              {"field", "count"},
              {"value", encodeU64Hex(count)}
            })
        );
      }

      std::string order = "desc";
      if (auto v = optionalString(req.params, "order"); v.has_value())
        order = *v;
      if (order != "asc" && order != "desc")
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'order' must be 'asc' or 'desc'",
            makeErrorData(ErrorCode::InvalidParams,
            {
              {"field", "order"},
              {"value", order}
            })
        );
      }

      const uint64_t tip = node.chain().height();
      const std::string hrp = hrpForNode(node);

      Common::Json arr = Common::Json::array();
      uint64_t taken = 0;

      if (order == "desc")
      {
        uint64_t h = std::min(start, tip);
        while (taken < count)
        {
          auto header = node.chainDB().getHeaderByHeight(h);
          if (!header.has_value())
            break;
          arr.push_back(encodeBlockHeader(*header, hrp));
          ++taken;
          if (h == 0)
            break;
          --h;
        }
      }
      else
      {
        uint64_t h = start;
        while (taken < count && h <= tip)
        {
          auto header = node.chainDB().getHeaderByHeight(h);
          if (!header.has_value())
            break;
          arr.push_back(encodeBlockHeader(*header, hrp));
          ++taken;
          ++h;
        }
      }

      Common::Json out = Common::Json::object();
      putU64(out, "count", taken);
      putU64(out, "start", start);
      out["order"] = order;
      out["blocks"] = std::move(arr);
      return out;
    }

    Common::Json method_getBlocksByProducer(Node::Node &node,
                                            const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address proposer = requireAddress(req.params, "address", hrp);

      uint64_t limit = 50;
      if (auto v = optionalU64(req.params, "limit"); v.has_value())
        limit = *v;
      if (limit == 0 || limit > 100)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'limit' must be 1..100",
            makeErrorData(ErrorCode::InvalidParams,
            {
              {"field", "limit"},
              {"value", encodeU64Hex(limit)}
            })
        );
      }

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachBlockByProducer(
          proposer,
          static_cast<size_t>(limit),
          [&](uint64_t block_height, const Crypto::Hash &block_hash)
          {
            Common::Json entry = Common::Json::object();
            putU64(entry, "height", block_height);
            putHash(entry, "block_hash", block_hash);
            arr.push_back(std::move(entry));
            return true;
          });

      Common::Json out = Common::Json::object();
      putAddress(out, "proposer", proposer, hrp);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["blocks"] = std::move(arr);
      return out;
    }

    Common::Json method_getBlockStats(Node::Node &node,
                                      const RpcConfig & /*config*/,
                                      const JsonRpcRequest &req)
    {
      constexpr uint64_t MAX_RANGE = 10'000;

      uint64_t from = requireU64(req.params, "from_height");
      uint64_t to = requireU64(req.params, "to_height");

      if (from > to)
        std::swap(from, to);

      const uint64_t tip = node.chain().height();
      if (to > tip)
        to = tip;

      if (to - from + 1 > MAX_RANGE)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "block range exceeds 10,000 blocks",
            makeErrorData(ErrorCode::InvalidParams,
            {
              {"range", encodeU64Hex(to - from + 1)}
            })
        );
      }

      uint64_t total_txs = 0;
      uint64_t total_fees = 0;
      uint64_t blocks = 0;

      for (uint64_t h = from; h <= to; ++h)
      {
        auto header = node.chainDB().getHeaderByHeight(h);
        if (!header.has_value())
          break;
        total_txs += header->tx_count;
        total_fees += header->total_fees;
        ++blocks;
      }

      Common::Json out = Common::Json::object();
      putU64(out, "from_height", from);
      putU64(out, "to_height", to);
      putU64(out, "block_count", blocks);
      putU64(out, "total_transactions", total_txs);
      putU64(out, "total_fees", total_fees);
      return out;
    }

    Common::Json method_getChainStats(Node::Node &node,
                                      const RpcConfig & /*config*/,
                                      const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      const uint64_t tx_counter = state.getMetaU64("tx_counter");
      const uint64_t total_fees = state.getMetaU64("total_fees_lifetime");

      const uint64_t total_supply = readU64Global(state, "total_supply");
      const uint64_t total_staked = readU64Global(state, "total_staked");
      const uint64_t staker_count = readU64Global(state, "staker_count");
      const uint64_t pot = readU64Global(state, "pot");

      const size_t unique_addresses = state.tableEntryCount(State::StateDB::TBL_ACCOUNTS);
      const size_t unique_tokens = state.tableEntryCount(State::StateDB::TBL_TOKENS);
      const size_t unique_validators = state.tableEntryCount(State::StateDB::TBL_INDEX_VALIDATORS);
      const size_t unique_pools = state.tableEntryCount(State::StateDB::TBL_AMM_POOLS);

      Common::Json out = Common::Json::object();
      putU64(out, "height", height);
      putU64(out, "chain_id", node.status().chain_id);
      putU64(out, "epoch", height / Core::ROTATION_INTERVAL);

      putU64(out, "total_transactions", tx_counter);
      putU64(out, "total_fees_lifetime", total_fees);
      putU64(out, "total_supply", total_supply);
      putU64(out, "total_staked", total_staked);
      putU64(out, "staker_count", staker_count);
      putU64(out, "current_pot", pot);

      putU64(out, "unique_addresses", unique_addresses);
      putU64(out, "unique_tokens", unique_tokens);
      putU64(out, "unique_validators", unique_validators);
      putU64(out, "unique_pools", unique_pools);

      putU64(out, "genesis_timestamp_ms", GlobalConfig::GENESIS_TIMESTAMP_MS);
      return out;
    }

    Common::Json method_getEpochInfo(Node::Node &node,
                                     const RpcConfig & /*config*/,
                                     const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();
      const uint64_t epoch = height / Core::ROTATION_INTERVAL;
      const uint64_t epoch_start = epoch * Core::ROTATION_INTERVAL;
      const uint64_t next_epoch_start = epoch_start + Core::ROTATION_INTERVAL;

      Common::Json out = Common::Json::object();
      putU64(out, "epoch", epoch);
      putU64(out, "epoch_start_height", epoch_start);
      putU64(out, "next_epoch_height", next_epoch_start);
      putU64(out, "current_height", height);
      putU64(out, "blocks_until_next_epoch", next_epoch_start > height ? next_epoch_start - height : 0);
      putU64(out, "rotation_interval", Core::ROTATION_INTERVAL);
      return out;
    }

    Common::Json method_getEpochSchedule(Node::Node &node,
                                         const RpcConfig & /*config*/,
                                         const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();
      const uint64_t epoch = height / Core::ROTATION_INTERVAL;
      const uint64_t epoch_start = epoch * Core::ROTATION_INTERVAL;

      Common::Json out = Common::Json::object();
      putU64(out, "rotation_interval", Core::ROTATION_INTERVAL);
      putU64(out, "unbonding_period", Core::UNBONDING_PERIOD);
      putU64(out, "emergency_rotation_rounds", Core::EMERGENCY_ROTATION_ROUNDS);
      putU64(out, "active_set_min", GlobalConfig::ACTIVE_SET_MIN);
      putU64(out, "active_set_max", GlobalConfig::ACTIVE_SET_MAX);
      putU64(out, "current_epoch", epoch);
      putU64(out, "epoch_start_height", epoch_start);
      return out;
    }

    Common::Json method_getValidators(Node::Node &node,
                                      const RpcConfig & /*config*/,
                                      const JsonRpcRequest &req)
    {
      const bool active_only = optionalBool(req.params, "active_only").value_or(false);
      const std::string hrp = hrpForNode(node);
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      std::vector<Core::ValidatorInfo> validators =
          active_only ? loadActiveValidators(state)
                      : loadAllValidators(state);

      const PageParams page = parsePageParams(req.params, 1000);

      if (page.offset >= validators.size())
      {
        Common::Json arr = Common::Json::array();
        Common::Json out = Common::Json::object();
        out["validators"] = std::move(arr);
        putU64(out, "count", 0);
        putU64(out, "total", static_cast<uint64_t>(validators.size()));
        return out;
      }

      const size_t end = std::min(validators.size(), static_cast<size_t>(page.offset + page.limit));
      std::vector<Core::ValidatorInfo> slice(
          validators.begin() + page.offset, validators.begin() + end);

      return encodeValidatorList(slice, height, hrp);
    }

    Common::Json method_getValidator(Node::Node &node,
                                     const RpcConfig & /*config*/,
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
            {
              {"id", encodeU64Hex(id)}
            })
        );
      }

      return encodeValidator(v, height, hrp);
    }

    Common::Json method_getActiveSet(Node::Node &node,
                                     const RpcConfig & /*config*/,
                                     const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      std::vector<uint8_t> set_bytes;
      if (!state.getGlobal("active_set", set_bytes))
      {
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

    Common::Json method_getValidatorByAddress(Node::Node &node,
                                              const RpcConfig & /*config*/,
                                              const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address = requireAddress(req.params, "address", hrp);
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      uint64_t validator_id = 0;
      if (!state.getValidatorByAddress(address, validator_id))
      {
        throw RpcMethodError(
            ErrorCode::ValidatorNotFound,
            "no validator registered for this address",
            makeErrorData(ErrorCode::ValidatorNotFound,
            {
              {"address", encodeAddress(address, hrp)}
            })
        );
      }

      Core::ValidatorInfo v;
      if (!state.getValidator(validator_id, v))
      {
        throw RpcMethodError(
            ErrorCode::ConsensusReadInternal,
            "validator index references a missing record",
            makeErrorData(ErrorCode::ConsensusReadInternal,
            {
              {"validator_id", encodeU64Hex(validator_id)}
            })
        );
      }

      return encodeValidator(v, height, hrp);
    }

    Common::Json method_getConsensusState(Node::Node &node,
                                          const RpcConfig & /*config*/,
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

    Common::Json method_getValidatorStats(Node::Node &node,
                                          const RpcConfig & /*config*/,
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
            {
              {"id", encodeU64Hex(id)}
            })
        );
      }

      constexpr size_t RECENT_BLOCKS = 20;

      Common::Json recent = Common::Json::array();

      state.forEachBlockByProducer(
          v.reward_address, RECENT_BLOCKS,
          [&](uint64_t block_height, const Crypto::Hash &block_hash)
          {
            Common::Json entry = Common::Json::object();
            putU64(entry, "height", block_height);
            putHash(entry, "block_hash", block_hash);
            recent.push_back(std::move(entry));
            return true;
          });

      Common::Json out = encodeValidator(v, height, hrp);
      out["recent_blocks"] = std::move(recent);
      return out;
    }

    Common::Json method_getBalance(Node::Node &node,
                                   const RpcConfig & /*config*/,
                                   const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address = requireAddress(req.params, "address", hrp);
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

    Common::Json method_getAccount(Node::Node &node,
                                   const RpcConfig & /*config*/,
                                   const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address = requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), headHeight(node));
      Core::Account account = state.getAccount(address);

      Common::Json out = encodeAccount(account);
      putAddress(out, "address", address, hrp);
      return out;
    }

    Common::Json method_getNonce(Node::Node &node,
                                 const RpcConfig & /*config*/,
                                 const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address = requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), headHeight(node));
      Core::Account account = state.getAccount(address);

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "nonce", account.nonce);
      return out;
    }

    Common::Json method_getProof(Node::Node &node, const RpcConfig & /*config*/,
                                 const JsonRpcRequest &req)
    {
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

      auto key = State::resolveProofKey(key_type, key_bytes);
      if (!key.has_value())
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "key_bytes does not match the layout for key_type",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"key_type", encodeU64Hex(*key_type_u64)}}));
      }

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

    Common::Json method_getTokensForAddress(Node::Node &node,
                                            const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachTokenBalanceForOwner(
          address,
          [&](Id token_id, uint64_t balance)
          {
            Common::Json entry = Common::Json::object();
            putU64(entry, "token_id", token_id);
            putU64(entry, "balance", balance);
            arr.push_back(std::move(entry));
          });

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["tokens"] = std::move(arr);
      return out;
    }

    Common::Json method_getPositionsForAddress(Node::Node &node,
                                               const RpcConfig & /*config*/,
                                               const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachPositionForOwner(
          address,
          [&](const Core::AmmPosition &pos)
          {
            Core::AmmPool pool;
            const bool have_pool = state.getAmmPool(pos.pool_id, pool);
            arr.push_back(encodeAmmPosition(
                pos, have_pool ? &pool : nullptr, hrp));
          });

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["positions"] = std::move(arr);
      return out;
    }

    Common::Json method_getOrdersForAddress(Node::Node &node,
                                            const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);
      const bool include_filled =
          optionalBool(req.params, "include_filled").value_or(false);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachOrderForOwner(
          address,
          [&](const Core::Order &order)
          {
            if (!include_filled && order.isFullyFilled())
              return;
            arr.push_back(encodeOrder(order, hrp));
          });

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["orders"] = std::move(arr);
      return out;
    }

    Common::Json method_getTransactionsForAddress(Node::Node &node,
                                                  const RpcConfig & /*config*/,
                                                  const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);

      uint64_t limit = 50;
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

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachRecentTxForAddress(
          address,
          static_cast<size_t>(limit),
          [&](const Crypto::Hash &txid, uint64_t block_height, uint32_t tx_index)
          {
            auto block = node.chain().getBlockByHeight(block_height);
            if (!block.has_value())
              return true;
            if (tx_index >= block->transactions.size())
              return true;

            Common::Json entry = Common::Json::object();
            entry["tx"] = encodeTransaction(block->transactions[tx_index], hrp);
            putHash(entry, "block_hash", block->header.hash());
            putU64(entry, "block_height", block_height);
            entry["index"] = tx_index;
            arr.push_back(std::move(entry));
            return true;
          });

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["transactions"] = std::move(arr);
      return out;
    }

    Common::Json method_getStakingInfo(Node::Node &node,
                                       const RpcConfig & /*config*/,
                                       const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();
      State::StateAccess state(node.stateDB(), height);

      const uint64_t total_staked = readU64Global(state, "total_staked");
      const uint64_t staker_count = readU64Global(state, "staker_count");
      const uint64_t pot = readU64Global(state, "pot");

      const uint64_t last_effective_apy_bps =
          state.getMetaU64("last_effective_apy_bps");

      const uint64_t activity_txs =
          sumTxCountInWindow(node, height, Core::ROTATION_INTERVAL);
      const uint64_t avg_tx_per_block =
          Core::ROTATION_INTERVAL > 0
              ? activity_txs / Core::ROTATION_INTERVAL
              : 0;

      const uint16_t base_bps = GlobalConfig::APY_BASE_BPS;
      const uint16_t activity_bps = Core::computeActivityBps(avg_tx_per_block);
      const uint16_t pot_bonus_bps =
          Core::computePotBonusBps(pot, /*pool_baseline=*/0);

      const uint64_t epoch = height / Core::ROTATION_INTERVAL;
      const uint64_t epoch_start = epoch * Core::ROTATION_INTERVAL;
      const uint64_t next_epoch = epoch_start + Core::ROTATION_INTERVAL;

      Common::Json out = Common::Json::object();
      putU64(out, "last_effective_apy_bps", last_effective_apy_bps);

      putU64(out, "base_bps", base_bps);
      putU64(out, "activity_bonus_bps", activity_bps);
      putU64(out, "pot_bonus_bps", pot_bonus_bps);

      putU64(out, "total_staked", total_staked);
      putU64(out, "staker_count", staker_count);
      putU64(out, "current_pot", pot);

      putU64(out, "activity_txs_in_window", activity_txs);
      putU64(out, "avg_tx_per_block", avg_tx_per_block);

      putU64(out, "epoch", epoch);
      putU64(out, "epoch_start_height", epoch_start);
      putU64(out, "next_epoch_height", next_epoch);
      putU64(out, "blocks_until_next_epoch",
             next_epoch > height ? next_epoch - height : 0);
      return out;
    }

    Common::Json method_getAddressStats(Node::Node &node,
                                        const RpcConfig & /*config*/,
                                        const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address address =
          requireAddress(req.params, "address", hrp);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Core::Account acct = state.getAccount(address);

      uint64_t token_count = 0;
      state.forEachTokenBalanceForOwner(
          address, [&](Id, uint64_t)
          { ++token_count; });

      uint64_t position_count = 0;
      state.forEachPositionForOwner(
          address, [&](const Core::AmmPosition &)
          { ++position_count; });

      uint64_t order_count = 0;
      state.forEachOrderForOwner(
          address, [&](const Core::Order &)
          { ++order_count; });

      uint64_t validator_id = 0;
      const bool is_validator = state.getValidatorByAddress(address, validator_id);

      Common::Json out = Common::Json::object();
      putAddress(out, "address", address, hrp);
      putU64(out, "balance", acct.balance);
      putU64(out, "nonce", acct.nonce);
      putU64(out, "staked", acct.staked);
      putU64(out, "pending_rewards", acct.pending_rewards);
      out["staking_opted_out"] = acct.staking_opted_out;

      putU64(out, "token_count", token_count);
      putU64(out, "position_count", position_count);
      putU64(out, "order_count", order_count);

      out["is_validator"] = is_validator;
      putU64(out, "validator_id", validator_id);
      return out;
    }

    Common::Json method_getAddressList(Node::Node &node,
                                       const RpcConfig & /*config*/,
                                       const JsonRpcRequest &req)
    {
      const PageParams page = parsePageParams(req.params, 100);
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachAccount(
          [&](const Crypto::Address &addr, const Core::Account &acct)
          {
            if (seen < page.offset)
            {
              ++seen;
              return;
            }
            if (emitted >= page.limit)
              return;

            Common::Json entry = Common::Json::object();
            putAddress(entry, "address", addr, hrp);
            putU64(entry, "balance", acct.balance);
            putU64(entry, "nonce", acct.nonce);
            arr.push_back(std::move(entry));
            ++emitted;
          });

      Common::Json out = Common::Json::object();
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["addresses"] = std::move(arr);
      return out;
    }

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

    Common::Json method_getAllTokens(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const PageParams page = parsePageParams(req.params);
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachToken([&](const Core::TokenInfo &token)
                         {
        if (seen < page.offset)
        {
          ++seen;
          return;
        }
        if (emitted >= page.limit)
          return;
        arr.push_back(encodeToken(token, hrp));
        ++emitted; });

      Common::Json out = Common::Json::object();
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["tokens"] = std::move(arr);
      return out;
    }

    Common::Json method_getTokenHolders(Node::Node &node, const RpcConfig & /*config*/,
                                        const JsonRpcRequest &req)
    {
      const Id token_id = requireU64(req.params, "token_id");

      uint64_t limit = 50;
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

      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      std::vector<BalanceEntry> holders;

      state.forEachHolderOfToken(
          token_id,
          [&](const Crypto::Address &addr, uint64_t balance)
          {
            holders.push_back({addr, balance});
            return true;
          });

      std::sort(holders.begin(), holders.end(), cmpAmountDesc);

      const size_t take = std::min<size_t>(limit, holders.size());

      Common::Json arr = Common::Json::array();
      for (size_t i = 0; i < take; ++i)
      {
        Common::Json entry = Common::Json::object();
        putAddress(entry, "address", holders[i].address, hrp);
        putU64(entry, "balance", holders[i].amount);
        arr.push_back(std::move(entry));
      }

      Common::Json out = Common::Json::object();
      putU64(out, "token_id", token_id);
      putU64(out, "count", static_cast<uint64_t>(take));
      putU64(out, "total_holders", static_cast<uint64_t>(holders.size()));
      out["holders"] = std::move(arr);
      return out;
    }

    Common::Json method_getTokenTransfers(Node::Node &node, const RpcConfig & /*config*/,
                                          const JsonRpcRequest &req)
    {
      const Id token_id = requireU64(req.params, "token_id");

      uint64_t limit = 50;
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

      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachRecentTxForToken(
          token_id,
          static_cast<size_t>(limit),
          [&](const Crypto::Hash &txid, uint64_t block_height, uint32_t tx_index)
          {
            auto block = node.chain().getBlockByHeight(block_height);
            if (!block.has_value())
              return true;
            if (tx_index >= block->transactions.size())
              return true;

            Common::Json entry = Common::Json::object();
            entry["tx"] = encodeTransaction(block->transactions[tx_index], hrp);
            putHash(entry, "block_hash", block->header.hash());
            putU64(entry, "block_height", block_height);
            entry["index"] = tx_index;
            arr.push_back(std::move(entry));
            return true;
          });

      Common::Json out = Common::Json::object();
      putU64(out, "token_id", token_id);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["transfers"] = std::move(arr);
      return out;
    }

    Common::Json method_getTokensByCreator(Node::Node &node,
                                           const RpcConfig & /*config*/,
                                           const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address creator =
          requireAddress(req.params, "address", hrp);

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

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachToken([&](const Core::TokenInfo &token)
                         {
        if (arr.size() >= limit)
          return;
        if (token.creator != creator)
          return;
        arr.push_back(encodeToken(token, hrp)); });

      Common::Json out = Common::Json::object();
      putAddress(out, "creator", creator, hrp);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["tokens"] = std::move(arr);
      return out;
    }

    Common::Json method_getNft(Node::Node &node, const RpcConfig & /*config*/,
                               const JsonRpcRequest &req)
    {
      const uint64_t nft_id = requireU64(req.params, "nft_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::NftInfo nft;
      if (!state.getNft(nft_id, nft))
      {
        throw RpcMethodError(
            ErrorCode::NftNotFound,
            "no NFT with id " + encodeU64Hex(nft_id),
            makeErrorData(ErrorCode::NftNotFound,
                          {{"nft_id", encodeU64Hex(nft_id)}}));
      }

      return encodeNftInfo(nft, hrp);
    }

    Common::Json method_getNftsForOwner(Node::Node &node,
                                        const RpcConfig & /*config*/,
                                        const JsonRpcRequest &req)
    {
      const std::string hrp = hrpForNode(node);
      const Crypto::Address owner =
          requireAddress(req.params, "address", hrp);
      const PageParams page = parsePageParams(req.params);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachNftForOwner(
          owner,
          [&](const Core::NftInfo &nft)
          {
            if (seen < page.offset)
            {
              ++seen;
              return;
            }
            if (emitted >= page.limit)
              return;
            arr.push_back(encodeNftInfo(nft, hrp));
            ++emitted;
          });

      Common::Json out = Common::Json::object();
      putAddress(out, "address", owner, hrp);
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["nfts"] = std::move(arr);
      return out;
    }

    Common::Json method_getNftsForCollection(Node::Node &node,
                                             const RpcConfig & /*config*/,
                                             const JsonRpcRequest &req)
    {
      const uint64_t collection_id = requireU64(req.params, "collection_id");
      const PageParams page = parsePageParams(req.params);
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      //  Reject early if the collection doesn't exist, so a typo
      //  returns CollectionNotFound rather than an empty list.
      Core::NftCollection collection;
      if (!state.getNftCollection(collection_id, collection))
      {
        throw RpcMethodError(
            ErrorCode::NftCollectionNotFound,
            "no collection with id " + encodeU64Hex(collection_id),
            makeErrorData(ErrorCode::NftCollectionNotFound,
                          {{"collection_id", encodeU64Hex(collection_id)}}));
      }

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachNftForCollection(
          collection_id,
          [&](const Core::NftInfo &nft)
          {
            if (seen < page.offset)
            {
              ++seen;
              return;
            }
            if (emitted >= page.limit)
              return;
            arr.push_back(encodeNftInfo(nft, hrp));
            ++emitted;
          });

      Common::Json out = Common::Json::object();
      putU64(out, "collection_id", collection_id);
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["nfts"] = std::move(arr);
      return out;
    }

    Common::Json method_getCollection(Node::Node &node,
                                      const RpcConfig & /*config*/,
                                      const JsonRpcRequest &req)
    {
      const uint64_t collection_id = requireU64(req.params, "collection_id");
      const uint64_t height = node.chain().height();
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), height);
      Core::NftCollection collection;
      if (!state.getNftCollection(collection_id, collection))
      {
        throw RpcMethodError(
            ErrorCode::NftCollectionNotFound,
            "no collection with id " + encodeU64Hex(collection_id),
            makeErrorData(ErrorCode::NftCollectionNotFound,
                          {{"collection_id", encodeU64Hex(collection_id)}}));
      }

      return encodeNftCollection(collection, hrp);
    }

    Common::Json method_getAllCollections(Node::Node &node,
                                          const RpcConfig & /*config*/,
                                          const JsonRpcRequest &req)
    {
      const PageParams page = parsePageParams(req.params);
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachNftCollection(
          [&](const Core::NftCollection &c)
          {
            if (seen < page.offset)
            {
              ++seen;
              return;
            }
            if (emitted >= page.limit)
              return;
            arr.push_back(encodeNftCollection(c, hrp));
            ++emitted;
          });

      Common::Json out = Common::Json::object();
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["collections"] = std::move(arr);
      return out;
    }

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

    Common::Json method_getAllOrders(Node::Node &node, const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const PageParams page = parsePageParams(req.params);
      const bool include_filled =
          optionalBool(req.params, "include_filled").value_or(false);
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachOrder([&](const Core::Order &order)
                         {
        if (!include_filled && order.isFullyFilled())
          return;
        if (seen < page.offset)
        {
          ++seen;
          return;
        }
        if (emitted >= page.limit)
          return;
        arr.push_back(encodeOrder(order, hrp));
        ++emitted; });

      Common::Json out = Common::Json::object();
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["orders"] = std::move(arr);
      return out;
    }

    Common::Json method_getOrdersByPair(Node::Node &node, const RpcConfig & /*config*/,
                                        const JsonRpcRequest &req)
    {
      const Id sell_token = requireU64(req.params, "sell_token");
      const Id buy_token = requireU64(req.params, "buy_token");
      const PageParams page = parsePageParams(req.params);
      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();
      uint64_t seen = 0;
      uint64_t emitted = 0;

      state.forEachOrderForPair(sell_token, buy_token,
                                [&](const Core::Order &order)
                                {
                                  if (order.isFullyFilled())
                                    return;
                                  if (seen < page.offset)
                                  {
                                    ++seen;
                                    return;
                                  }
                                  if (emitted >= page.limit)
                                    return;
                                  arr.push_back(encodeOrder(order, hrp));
                                  ++emitted;
                                });

      Common::Json out = Common::Json::object();
      putU64(out, "sell_token", sell_token);
      putU64(out, "buy_token", buy_token);
      putU64(out, "count", emitted);
      putU64(out, "offset", page.offset);
      putU64(out, "limit", page.limit);
      out["orders"] = std::move(arr);
      return out;
    }

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

    Common::Json method_getTransactionByHash(Node::Node &node, const RpcConfig & /*config*/,
                                             const JsonRpcRequest &req)
    {
      const Crypto::Hash hash = requireHash(req.params, "hash");
      const std::string hrp = hrpForNode(node);

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

    Common::Json method_getTransactionReceipt(Node::Node &node,
                                              const RpcConfig & /*config*/,
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

      std::vector<uint8_t> receipt_bytes;
      if (!node.chainDB().getReceipt(hash, receipt_bytes))
      {
        throw RpcMethodError(
            ErrorCode::ReceiptNotFound,
            "tx index has the transaction but no receipt is stored",
            makeErrorData(ErrorCode::ReceiptNotFound,
                          {{"hash", encodeHash(hash)}}));
      }

      Core::Receipt receipt;
      if (!Core::Receipt::deserializeState(receipt_bytes.data(),
                                           receipt_bytes.size(),
                                           receipt))
      {
        throw RpcMethodError(
            ErrorCode::ReceiptNotFound,
            "stored receipt failed to deserialize",
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

    Common::Json method_simulateTransaction(Node::Node &node, const RpcConfig & /*config*/,
                                            const JsonRpcRequest &req)
    {
      const std::string tx_hex = requireString(req.params, "tx");
      Core::Transaction tx = parseTxHex(tx_hex);

      const uint64_t height = node.chain().height();
      const uint64_t chain_id = node.status().chain_id;

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

        txn.abort();
      }
      catch (...)
      {
        txn.abort();
        throw;
      }

      Common::Json out = encodeReceipt(receipt);
      putHash(out, "tx_hash", tx.txid());
      putU64(out, "height", height);
      return out;
    }

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

      auto type_filter = optionalU64(req.params, "type_code");

      const std::string hrp = hrpForNode(node);

      Common::Json arr = Common::Json::array();
      uint64_t collected = 0;

      if (type_filter.has_value())
      {
        State::StateAccess state(node.stateDB(), node.chain().height());

        state.forEachRecentTxOfType(
            static_cast<uint8_t>(*type_filter),
            static_cast<size_t>(limit),
            [&](const Crypto::Hash &txid, uint64_t block_height, uint32_t tx_index)
            {
              auto block = node.chain().getBlockByHeight(block_height);
              if (!block.has_value())
                return true;
              if (tx_index >= block->transactions.size())
                return true;

              Common::Json entry = Common::Json::object();
              entry["tx"] = encodeTransaction(block->transactions[tx_index], hrp);
              putHash(entry, "block_hash", block->header.hash());
              putU64(entry, "block_height", block_height);
              entry["index"] = tx_index;
              arr.push_back(std::move(entry));
              return true;
            });

        Common::Json out = Common::Json::object();
        putU64(out, "count", static_cast<uint64_t>(arr.size()));
        out["transactions"] = std::move(arr);
        return out;
      }

      const uint64_t tip = node.chain().height();

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

    Common::Json method_getAllTransactions(Node::Node &node,
                                           const RpcConfig & /*config*/,
                                           const JsonRpcRequest &req)
    {
      Common::Json params = req.params;
      if (!params.contains("limit"))
        params["limit"] = "0x32"; // 50

      JsonRpcRequest sub = req;
      sub.params = std::move(params);
      return method_getRecentTransactions(node, RpcConfig{}, sub);
    }

    Common::Json method_getTransactionsByType(Node::Node &node,
                                              const RpcConfig & /*config*/,
                                              const JsonRpcRequest &req)
    {
      const Id type_code = requireU64(req.params, "type_code");

      Common::Json params = req.params;
      params["type_code"] = encodeU64Hex(type_code);
      if (!params.contains("limit"))
        params["limit"] = "0x32";

      JsonRpcRequest sub = req;
      sub.params = std::move(params);
      return method_getRecentTransactions(node, RpcConfig{}, sub);
    }

    Common::Json method_getTxCount(Node::Node &node,
                                   const RpcConfig & /*config*/,
                                   const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);
      const uint64_t lifetime = state.getMetaU64("tx_counter");

      const uint64_t epoch_txs =
          sumTxCountInWindow(node, height, Core::ROTATION_INTERVAL);

      const uint64_t epoch = height / Core::ROTATION_INTERVAL;

      Common::Json out = Common::Json::object();
      putU64(out, "total_transactions", lifetime);
      putU64(out, "epoch_transactions", epoch_txs);
      putU64(out, "current_epoch", epoch);
      return out;
    }

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

      std::string order_by = "fee";
      if (auto v = optionalString(req.params, "order_by"); v.has_value())
        order_by = *v;
      if (order_by != "fee" && order_by != "time")
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'order_by' must be 'fee' or 'time'",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "order_by"}, {"value", order_by}}));
      }

      auto entries = node.mempool().snapshot();

      if (order_by == "fee")
      {
        std::sort(entries.begin(), entries.end(),
                  [](const Core::Mempool::Snapshot &a,
                     const Core::Mempool::Snapshot &b)
                  {
                    if (a.fee_rate != b.fee_rate)
                      return a.fee_rate > b.fee_rate;
                    return a.added_at_ms < b.added_at_ms;
                  });
      }
      else
      {
        std::sort(entries.begin(), entries.end(),
                  [](const Core::Mempool::Snapshot &a,
                     const Core::Mempool::Snapshot &b)
                  {
                    return a.added_at_ms > b.added_at_ms;
                  });
      }

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
      out["order_by"] = order_by;
      out["transactions"] = std::move(arr);
      return out;
    }

    Common::Json method_getFeeStats(Node::Node &node,
                                    const RpcConfig & /*config*/,
                                    const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      const uint64_t lifetime_fees =
          state.getMetaU64("total_fees_lifetime");
      const uint64_t tx_counter =
          state.getMetaU64("tx_counter");

      const uint64_t epoch_fees =
          sumFeesInWindow(node, height, Core::ROTATION_INTERVAL);

      const uint64_t daily_fees = state.getMetaU64("fees_in_window");

      const uint64_t avg_fee_per_block =
          height > 0 ? lifetime_fees / (height + 1) : 0;
      const uint64_t avg_fee_per_tx =
          tx_counter > 0 ? lifetime_fees / tx_counter : 0;

      Common::Json out = Common::Json::object();
      putU64(out, "total_fees_lifetime", lifetime_fees);
      putU64(out, "fees_last_epoch", epoch_fees);
      putU64(out, "fees_last_24h", daily_fees);
      putU64(out, "avg_fee_per_block", avg_fee_per_block);
      putU64(out, "avg_fee_per_transaction", avg_fee_per_tx);
      putU64(out, "total_transactions", tx_counter);
      return out;
    }

    Common::Json method_getPotInfo(Node::Node &node,
                                   const RpcConfig & /*config*/,
                                   const JsonRpcRequest & /*req*/)
    {
      const uint64_t height = node.chain().height();

      State::StateAccess state(node.stateDB(), height);

      const uint64_t pot = readU64Global(state, "pot");
      const uint64_t total_to_pot = readU64Global(state, "total_to_pot");
      const uint64_t total_distributed =
          readU64Global(state, "total_pot_distributed");
      const uint64_t last_apy =
          readU64Global(state, "last_effective_apy_bps");

      const uint64_t pool_baseline =
          Core::applyBps(GlobalConfig::BLOCK_REWARD,
                         GlobalConfig::STAKER_SHARE_BPS) *
          Core::ROTATION_INTERVAL;
      const uint64_t pot_high = pool_baseline * Core::POT_HIGH_EPOCHS;

      uint64_t fill_bps = 0;
      if (pot_high > 0)
      {
        __uint128_t tmp =
            static_cast<__uint128_t>(pot) * 10'000ULL / pot_high;
        fill_bps = static_cast<uint64_t>(tmp);
      }

      const uint64_t epoch = height / Core::ROTATION_INTERVAL;
      const uint64_t epoch_start = epoch * Core::ROTATION_INTERVAL;
      const uint64_t next_epoch = epoch_start + Core::ROTATION_INTERVAL;

      Common::Json out = Common::Json::object();
      putU64(out, "current_pot", pot);
      putU64(out, "pot_high_threshold", pot_high);
      putU64(out, "pot_fill_bps_of_high", fill_bps);
      putU64(out, "total_to_pot", total_to_pot);
      putU64(out, "total_pot_distributed", total_distributed);
      putU64(out, "last_effective_apy_bps", last_apy);

      putU64(out, "epoch", epoch);
      putU64(out, "epoch_start_height", epoch_start);
      putU64(out, "next_epoch_height", next_epoch);
      putU64(out, "blocks_until_payout",
             next_epoch > height ? next_epoch - height : 0);
      return out;
    }

    Common::Json method_ping(Node::Node &, const RpcConfig &,
                             const JsonRpcRequest &)
    {
      return Common::Json("pong");
    }

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

      putHash(j, "state_root", node.stateRoot());
      return j;
    }

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

    Common::Json method_getPeers(Node::Node &node, const RpcConfig &,
                                 const JsonRpcRequest &)
    {
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

    Common::Json method_getMethods(Node::Node & /*node*/, const RpcConfig & /*config*/,
                                   const JsonRpcRequest & /*req*/)
    {
      Common::Json out = Common::Json::object();

      auto makeArray = [](std::initializer_list<const char *> names)
      {
        Common::Json arr = Common::Json::array();
        for (const char *n : names)
          arr.push_back(n);
        return arr;
      };

      out["chain"] = makeArray({
          "chainId",
          "blockNumber",
          "getBlockByNumber",
          "getBlockByHash",
          "getBlockHeaderByNumber",
          "getBlocksRange",
          "getBlocksByProducer",
          "getBlockStats",
          "getChainStats",
          "getEpochInfo",
          "getEpochSchedule",
          "getRecentBlocks",
          "getStateRoot",
      });

      out["state"] = makeArray({
          "getBalance",
          "getAccount",
          "getNonce",
          "getTokensForAddress",
          "getPositionsForAddress",
          "getOrdersForAddress",
          "getTransactionsForAddress",
          "getStakingInfo",
          "getAddressStats",
          "getAddressList",
          "getProof",
      });

      out["tokens"] = makeArray({
          "getTokenInfo",
          "getTokenSupply",
          "getAllTokens",
          "getTokenHolders",
          "getTokenTransfers",
          "getTokensByCreator",
      });

      out["nfts"] = makeArray({
          "getNft",
          "getNftsForOwner",
          "getNftsForCollection",
          "getCollection",
          "getAllCollections",
      });

      out["amm"] = makeArray({
          "getPool",
          "getPosition",
          "getPositionByOwner",
          "getAllPools",
          "getPoolsForToken",
          "getPositionsForPool",
      });

      out["orders"] = makeArray({
          "getOrder",
          "getOrdersExpiringAt",
          "getAllOrders",
          "getOrdersByPair",
          "getOrderBook",
          "getOrderFills",
          "getPairTrades",
      });

      out["transactions"] = makeArray({
          "sendRawTransaction",
          "getTransactionByHash",
          "getTransactionReceipt",
          "simulateTransaction",
          "getRecentTransactions",
          "getAllTransactions",
          "getTransactionsByType",
          "getTxCount",
      });

      out["mempool"] = makeArray({
          "getMempoolStats",
          "getMempoolTx",
          "getMempoolList",
      });

      out["consensus"] = makeArray({
          "getValidators",
          "getValidator",
          "getValidatorByAddress",
          "getValidatorStats",
          "getActiveSet",
          "getConsensusState",
      });

      out["metrics"] = makeArray({
          "getFeeStats",
          "getPotInfo",
      });

      out["node"] = makeArray({
          "ping",
          "status",
          "health",
          "getPeers",
          "getConfig",
          "getMethods",
          "web3_clientVersion",
          "net_version",
          "net_peerCount",
          "net_listening",
      });

      return out;
    }

    // ---- Compatibility shims ----

    Common::Json method_web3_clientVersion(Node::Node &, const RpcConfig &,
                                           const JsonRpcRequest &)
    {
      return Common::Json(GlobalConfig::CLIENT_VERSION);
    }

    Common::Json method_net_version(Node::Node &node, const RpcConfig &,
                                    const JsonRpcRequest &)
    {
      std::string s = std::to_string(node.status().chain_id);
      return Common::Json(s);
    }

    Common::Json method_net_peerCount(Node::Node &node, const RpcConfig &,
                                      const JsonRpcRequest &)
    {
      return Common::Json(encodeU64Hex(node.status().peer_count));
    }

    Common::Json method_net_listening(Node::Node &node, const RpcConfig &,
                                      const JsonRpcRequest &)
    {
      return Common::Json(node.status().peer_count > 0);
    }

    Common::Json method_getOrderBook(Node::Node &node,
                                     const RpcConfig & /*config*/,
                                     const JsonRpcRequest &req)
    {
      const Id base = requireU64(req.params, "base_token");
      const Id quote = requireU64(req.params, "quote_token");

      if (base == quote)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "base_token and quote_token must differ",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"base_token", encodeU64Hex(base)},
                           {"quote_token", encodeU64Hex(quote)}}));
      }

      uint64_t depth = 20;
      if (auto v = optionalU64(req.params, "depth"); v.has_value())
        depth = *v;
      if (depth == 0 || depth > 100)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "field 'depth' must be 1..100",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"field", "depth"},
                           {"value", encodeU64Hex(depth)}}));
      }

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json bids = Common::Json::array();
      Common::Json asks = Common::Json::array();

      state.snapshotBookSide(
          base, quote, /*side=*/1, static_cast<size_t>(depth),
          [&](uint64_t price, uint64_t total_base, size_t order_count)
          {
            Common::Json lvl = Common::Json::object();
            putU64(lvl, "price", price);
            putU64(lvl, "total_base", total_base);
            putU64(lvl, "order_count", static_cast<uint64_t>(order_count));
            bids.push_back(std::move(lvl));
          });

      state.snapshotBookSide(
          base, quote, /*side=*/0, static_cast<size_t>(depth),
          [&](uint64_t price, uint64_t total_base, size_t order_count)
          {
            Common::Json lvl = Common::Json::object();
            putU64(lvl, "price", price);
            putU64(lvl, "total_base", total_base);
            putU64(lvl, "order_count", static_cast<uint64_t>(order_count));
            asks.push_back(std::move(lvl));
          });

      Common::Json out = Common::Json::object();
      putU64(out, "base_token", base);
      putU64(out, "quote_token", quote);
      putU64(out, "price_scale", Core::OrderBook::BOOK_PRICE_SCALE);
      out["bids"] = std::move(bids);
      out["asks"] = std::move(asks);
      return out;
    }

    Common::Json method_getOrderFills(Node::Node &node,
                                      const RpcConfig & /*config*/,
                                      const JsonRpcRequest &req)
    {
      const Id order_id = requireU64(req.params, "order_id");

      uint64_t limit = 100;
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

      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachRecentFillForOrder(
          order_id, static_cast<size_t>(limit),
          [&](const Core::Fill &f, uint64_t height, uint32_t tx_index)
          {
            arr.push_back(encodeFill(f, height, tx_index, hrp));
            return true;
          });

      Common::Json out = Common::Json::object();
      putU64(out, "order_id", order_id);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["fills"] = std::move(arr);
      return out;
    }

    Common::Json method_getPairTrades(Node::Node &node,
                                      const RpcConfig & /*config*/,
                                      const JsonRpcRequest &req)
    {
      const Id base = requireU64(req.params, "base_token");
      const Id quote = requireU64(req.params, "quote_token");

      if (base == quote)
      {
        throw RpcMethodError(
            ErrorCode::InvalidParams,
            "base_token and quote_token must differ",
            makeErrorData(ErrorCode::InvalidParams,
                          {{"base_token", encodeU64Hex(base)},
                           {"quote_token", encodeU64Hex(quote)}}));
      }

      uint64_t limit = 100;
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

      const std::string hrp = hrpForNode(node);

      State::StateAccess state(node.stateDB(), node.chain().height());

      Common::Json arr = Common::Json::array();

      state.forEachRecentFillForPair(
          base, quote, static_cast<size_t>(limit),
          [&](const Core::Fill &f, uint64_t height, uint32_t tx_index)
          {
            arr.push_back(encodeFill(f, height, tx_index, hrp));
            return true;
          });

      Common::Json out = Common::Json::object();
      putU64(out, "base_token", base);
      putU64(out, "quote_token", quote);
      putU64(out, "count", static_cast<uint64_t>(arr.size()));
      out["trades"] = std::move(arr);
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

    d.registerMethod("getAllPools", method_getAllPools);
    d.registerMethod("getPoolsForToken", method_getPoolsForToken);
    d.registerMethod("getPositionsForPool", method_getPositionsForPool);
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

    d.registerMethod("getBlocksRange", method_getBlocksRange);
    d.registerMethod("getBlocksByProducer", method_getBlocksByProducer);
    d.registerMethod("getBlockStats", method_getBlockStats);
    d.registerMethod("getChainStats", method_getChainStats);
    d.registerMethod("getEpochInfo", method_getEpochInfo);
    d.registerMethod("getEpochSchedule", method_getEpochSchedule);
  }

  void registerConsensusMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getValidators", method_getValidators);
    d.registerMethod("getValidator", method_getValidator);
    d.registerMethod("getValidatorByAddress", method_getValidatorByAddress);
    d.registerMethod("getActiveSet", method_getActiveSet);
    d.registerMethod("getConsensusState", method_getConsensusState);
    d.registerMethod("getValidatorStats", method_getValidatorStats);
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
    d.registerMethod("getMethods", method_getMethods);
    d.registerMethod("getFeeStats", method_getFeeStats);
    d.registerMethod("getPotInfo", method_getPotInfo);

    d.registerMethod("web3_clientVersion", method_web3_clientVersion);
    d.registerMethod("net_version", method_net_version);
    d.registerMethod("net_peerCount", method_net_peerCount);
    d.registerMethod("net_listening", method_net_listening);
  }

  void registerOrderMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getOrder", method_getOrder);
    d.registerMethod("getOrdersExpiringAt", method_getOrdersExpiringAt);
    d.registerMethod("getAllOrders", method_getAllOrders);
    d.registerMethod("getOrdersByPair", method_getOrdersByPair);
    d.registerMethod("getOrderBook", method_getOrderBook);
    d.registerMethod("getOrderFills", method_getOrderFills);
    d.registerMethod("getPairTrades", method_getPairTrades);
  }

  void registerStateMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getBalance", method_getBalance);
    d.registerMethod("getAccount", method_getAccount);
    d.registerMethod("getNonce", method_getNonce);
    d.registerMethod("getTokenInfo", method_getTokenInfo);
    d.registerMethod("getTokenSupply", method_getTokenSupply);
    d.registerMethod("getProof", method_getProof);

    d.registerMethod("getTokensForAddress", method_getTokensForAddress);
    d.registerMethod("getPositionsForAddress", method_getPositionsForAddress);
    d.registerMethod("getOrdersForAddress", method_getOrdersForAddress);
    d.registerMethod("getTransactionsForAddress", method_getTransactionsForAddress);
    d.registerMethod("getStakingInfo", method_getStakingInfo);
    d.registerMethod("getAddressStats", method_getAddressStats);
    d.registerMethod("getAddressList", method_getAddressList);

    d.registerMethod("getAllTokens", method_getAllTokens);
    d.registerMethod("getTokenHolders", method_getTokenHolders);
    d.registerMethod("getTokenTransfers", method_getTokenTransfers);
    d.registerMethod("getTokensByCreator", method_getTokensByCreator);
  }

  void registerTxMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("sendRawTransaction", method_sendRawTransaction);
    d.registerMethod("getTransactionByHash", method_getTransactionByHash);
    d.registerMethod("getTransactionReceipt", method_getTransactionReceipt);
    d.registerMethod("simulateTransaction", method_simulateTransaction);
    d.registerMethod("getRecentTransactions", method_getRecentTransactions);

    d.registerMethod("getAllTransactions", method_getAllTransactions);
    d.registerMethod("getTransactionsByType", method_getTransactionsByType);
    d.registerMethod("getTxCount", method_getTxCount);
  }

  void registerNftMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("getNft", method_getNft);
    d.registerMethod("getNftsForOwner", method_getNftsForOwner);
    d.registerMethod("getNftsForCollection", method_getNftsForCollection);
    d.registerMethod("getCollection", method_getCollection);
    d.registerMethod("getAllCollections", method_getAllCollections);
  }
} // namespace Rpc