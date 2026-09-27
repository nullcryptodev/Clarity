// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateMethods.h"

#include "Encoders/AccountEncoder.h"
#include "Encoders/Encoding.h"
#include "Encoders/TokenEncoder.h"
#include "JsonRpcDispatcher.h"
#include "JsonRpcError.h"
#include "Methods.h"

#include "Core/Chain.h"
#include "Node/Node.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

namespace Rpc
{

  namespace
  {
    // ---- Helpers ----

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

  } // anonymous namespace

  void registerStateMethods(JsonRpcDispatcher &d)
  {
    d.registerMethod("clrty_getBalance", method_getBalance);
    d.registerMethod("clrty_getAccount", method_getAccount);
    d.registerMethod("clrty_getNonce", method_getNonce);
    d.registerMethod("clrty_getTokenInfo", method_getTokenInfo);
    d.registerMethod("clrty_getTokenSupply", method_getTokenSupply);
  }

} // namespace Rpc