// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ConsensusMethods.h"

#include "Encoders/Encoding.h"
#include "Encoders/ValidatorEncoder.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"

#include "Core/Chain.h"
#include "Core/ValidatorTypes.h"
#include "Node/Node.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

namespace Rpc
{

  namespace
  {
    // ---- Helpers ----

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
                                     const JsonRpcRequest &/*req*/)
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

    // ---- clrty_getConsensusState ----
    //
    // No params.
    //
    // Returns the current consensus progress: height, round, step,
    // and whether the node is a validator. Reads Node::Status, which
    // takes the status mutex.

    Common::Json method_getConsensusState(Node::Node &node, const RpcConfig & /*config*/,
                                          const JsonRpcRequest &/*req*/)
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

  } // anonymous namespace

  void registerConsensusMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_getValidators", method_getValidators);
    d.registerMethod("clrty_getValidator", method_getValidator);
    d.registerMethod("clrty_getActiveSet", method_getActiveSet);
    d.registerMethod("clrty_getConsensusState", method_getConsensusState);
  }

} // namespace Rpc