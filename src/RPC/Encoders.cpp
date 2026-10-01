// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Encoders.h"
#include "Encoding.h"

#include "Wallet/AddressCodec.h"

#include <algorithm>
#include <cstdio>

namespace Rpc
{
  // ===========================================================================
  //  JsonWriter — a small helper for populating a Common::Json object
  //  with the conventions every encoder uses.
  //
  //  This replaces the free put* functions the encoders used to call.
  //  Having the format in the method name ("setHexU64" rather than
  //  "putU64") makes each call site self-documenting and prevents the
  //  class of bug where a bech32m encoder is used for a value that
  //  should be hex.
  // ===========================================================================

  namespace
  {
    constexpr char HEX_LOWER[] = "0123456789abcdef";

    //  Encode a __uint128_t as "0x..." with no leading zeros. Zero is
    //  "0x0". Used for AmmPool::k() which can exceed 2^64.
    std::string encodeU128Hex(__uint128_t v)
    {
      if (v == 0)
        return "0x0";

      std::string out;
      out.reserve(34);

      bool started = false;
      for (int shift = 124; shift >= 0; shift -= 4)
      {
        const uint8_t nib = uint8_t((v >> shift) & 0xF);
        if (!started)
        {
          if (nib == 0)
            continue;
          out.push_back('0');
          out.push_back('x');
          started = true;
        }
        out.push_back(HEX_LOWER[nib]);
      }

      return out;
    }

    //  Encode a Crypto::Hash or any 32-byte ByteArray as "0x...".
    //  Every byte is emitted, including leading zeros — a hash is a
    //  fixed-width value, so the wire representation should be
    //  fixed-width too.
    template <size_t N>
    std::string encodeBytesHex(const std::array<uint8_t, N> &data)
    {
      std::string out;
      out.reserve(2 + N * 2);
      out.push_back('0');
      out.push_back('x');
      for (uint8_t b : data)
      {
        out.push_back(HEX_LOWER[b >> 4]);
        out.push_back(HEX_LOWER[b & 0x0F]);
      }
      return out;
    }

    std::string encodeVectorHex(const std::vector<uint8_t> &v)
    {
      std::string out;
      out.reserve(2 + v.size() * 2);
      out.push_back('0');
      out.push_back('x');
      for (uint8_t b : v)
      {
        out.push_back(HEX_LOWER[b >> 4]);
        out.push_back(HEX_LOWER[b & 0x0F]);
      }
      return out;
    }

    //  Encode a Crypto::Address as a bech32m string, or return a
    //  JSON null if the address is the null address. Bech32m cannot
    //  represent the zero pubkey, and emitting an empty string
    //  invites clients to try to parse it.
    Common::Json encodeAddressOrNull(const Crypto::Address &addr,
                                     const std::string &hrp)
    {
      if (addr.isNull())
        return Common::Json(nullptr);

      const std::string s = Wallet::encodeAddress(addr, hrp);
      if (s.empty())
        return Common::Json(nullptr);
      return s;
    }

    // =========================================================================
    //  JsonWriter
    // =========================================================================

    class JsonWriter
    {
    public:
      explicit JsonWriter(Common::Json &out) : out_(out) {}

      //  Unsigned integers, hex-encoded.
      void setHexU64(const char *key, uint64_t v)
      {
        out_[key] = encodeU64Hex(v);
      }

      void setHexU128(const char *key, __uint128_t v)
      {
        out_[key] = encodeU128Hex(v);
      }

      //  Numbers that fit in a JSON number without precision loss.
      //  Use for counts and small enums, not for balances.
      void setNumber(const char *key, uint64_t v)
      {
        out_[key] = v;
      }

      void setBool(const char *key, bool v)
      {
        out_[key] = v;
      }

      void setString(const char *key, const std::string &s)
      {
        out_[key] = s;
      }

      //  Address as bech32m, or JSON null if the address is null.
      void setAddress(const char *key, const Crypto::Address &a,
                      const std::string &hrp)
      {
        out_[key] = encodeAddressOrNull(a, hrp);
      }

      //  Address as bech32m. Emits null for null addresses. Same as
      //  setAddress, but the name makes it clear that null is a
      //  legitimate encoding for this field.
      void setNullableAddress(const char *key, const Crypto::Address &a,
                              const std::string &hrp)
      {
        setAddress(key, a, hrp);
      }

      //  32-byte hash as 0x-prefixed hex. Fixed width.
      void setHash(const char *key, const Crypto::Hash &h)
      {
        out_[key] = encodeBytesHex(h.data);
      }

      //  32-byte public key as 0x-prefixed hex. Fixed width.
      //  This is the right encoder for consensus_key and node_key —
      //  both are signing keys, not addresses.
      template <size_t N>
      void setPublicKey(const char *key, const std::array<uint8_t, N> &pk)
      {
        out_[key] = encodeBytesHex(pk);
      }

      //  64-byte signature as 0x-prefixed hex. Fixed width.
      void setSignature(const char *key, const Crypto::Signature &s)
      {
        out_[key] = encodeBytesHex(s.data);
      }

      //  Arbitrary-length byte vector as 0x-prefixed hex.
      void setBytes(const char *key, const std::vector<uint8_t> &v)
      {
        out_[key] = encodeVectorHex(v);
      }

      //  Nested object / array — the caller builds these separately
      //  and hands them in whole.
      void setObject(const char *key, Common::Json obj)
      {
        out_[key] = std::move(obj);
      }

    private:
      Common::Json &out_;
    };

    // =========================================================================
    //  Display helpers (strings only, no state)
    // =========================================================================

    const char *conditionName(Core::OrderConditionType t) noexcept
    {
      switch (t)
      {
      case Core::OrderConditionType::Invalid:
        return "invalid";
      case Core::OrderConditionType::ExpiresAtHeight:
        return "expires_at_height";
      case Core::OrderConditionType::PriceAbove:
        return "price_above";
      case Core::OrderConditionType::PriceBelow:
        return "price_below";
      case Core::OrderConditionType::VolumeBelow:
        return "volume_below";
      case Core::OrderConditionType::BalanceBelow:
        return "balance_below";
      }
      return "unknown";
    }

    const char *modeName(Core::OrderExecutionMode m) noexcept
    {
      switch (m)
      {
      case Core::OrderExecutionMode::Passive:
        return "passive";
      case Core::OrderExecutionMode::Active:
        return "active";
      }
      return "unknown";
    }

    const char *backingName(Core::BackingModel b) noexcept
    {
      switch (b)
      {
      case Core::BackingModel::Unbacked:
        return "unbacked";
      case Core::BackingModel::Backed:
        return "backed";
      case Core::BackingModel::Hybrid:
        return "hybrid";
      }
      return "unknown";
    }

    std::string describeCondition(const Core::OrderCondition &c)
    {
      switch (c.type)
      {
      case Core::OrderConditionType::ExpiresAtHeight:
        return "expires at height " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::PriceAbove:
        return "cancels if price above " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::PriceBelow:
        return "cancels if price below " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::VolumeBelow:
        return "cancels if 24h volume below " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::BalanceBelow:
        return "cancels if balance below " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::Invalid:
        return "invalid condition";
      }
      return "unknown condition";
    }

    Common::Json encodeCondition(const Core::OrderCondition &c)
    {
      Common::Json j = Common::Json::object();
      JsonWriter w(j);

      w.setString("type", conditionName(c.type));
      w.setNumber("type_code", static_cast<uint64_t>(c.type));
      w.setHexU64("param1", c.param1);
      w.setHexU64("param2", c.param2);
      w.setString("description", describeCondition(c));

      return j;
    }
  } // anonymous namespace

  // ===========================================================================
  //  Account
  // ===========================================================================

  Common::Json encodeAccount(const Core::Account &account)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHexU64("nonce", account.nonce);
    w.setHexU64("balance", account.balance);
    w.setHexU64("staked", account.staked);
    w.setHexU64("pending_rewards", account.pending_rewards);
    w.setHexU64("last_reward_epoch", account.last_reward_epoch);
    w.setHexU64("staker_since_height", account.staker_since_height);
    w.setHexU64("created_at_height", account.created_at_height);

    w.setBool("staking_opted_out", account.staking_opted_out);

    // Derived.
    w.setBool("is_empty", account.isEmpty());
    w.setHexU64("total_value", account.totalValue());

    return j;
  }

  // ===========================================================================
  //  AmmPool
  // ===========================================================================

  Common::Json encodeAmmPool(const Core::AmmPool &pool, const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHexU64("id", pool.id);
    w.setAddress("creator", pool.creator, hrp);
    w.setHexU64("token_a", pool.token_a);
    w.setHexU64("token_b", pool.token_b);
    w.setHexU64("reserve_a", pool.reserve_a);
    w.setHexU64("reserve_b", pool.reserve_b);
    w.setHexU64("total_liquidity", pool.total_liquidity);
    w.setNumber("fee_bps", pool.fee_bps);
    w.setHexU64("created_at_height", pool.created_at_height);
    w.setBool("active", pool.active);

    // k = reserve_a * reserve_b, as 128-bit.
    w.setHexU128("k", pool.k());

    return j;
  }

  // ===========================================================================
  //  AmmPosition
  // ===========================================================================

  Common::Json encodeAmmPosition(const Core::AmmPosition &position,
                                 const Core::AmmPool *pool,
                                 const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHexU64("id", position.id);
    w.setAddress("owner", position.owner, hrp);
    w.setHexU64("pool_id", position.pool_id);
    w.setHexU64("liquidity", position.liquidity);
    w.setHexU64("created_at_height", position.created_at_height);

    if (pool != nullptr && pool->total_liquidity != 0)
    {
      // share_bps = position.liquidity * 10000 / pool.total_liquidity.
      // 128-bit intermediate to avoid overflow.
      const __uint128_t share =
          static_cast<__uint128_t>(position.liquidity) * 10000;
      const uint64_t share_bps =
          static_cast<uint64_t>(share / pool->total_liquidity);
      w.setNumber("share_bps", share_bps);
    }

    return j;
  }

  // ===========================================================================
  //  BlockHeader
  // ===========================================================================

  Common::Json encodeBlockHeader(const Core::BlockHeader &header,
                                 const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHash("hash", header.hash());
    w.setNumber("version", header.version);
    w.setNumber("chain_id", header.chain_id);

    w.setHexU64("height", header.height);
    w.setHash("parent_hash", header.parent_hash);
    w.setHexU64("timestamp_ms", header.timestamp_ms);
    w.setAddress("proposer", header.proposer, hrp);

    w.setHexU64("epoch", header.epoch);
    w.setHexU64("rotation_index", header.rotation_index);
    w.setHexU64("commit_round", header.commit_round);
    w.setHexU64("emergency_rotation", header.emergency_rotation);

    w.setHash("state_root", header.state_root);
    w.setHash("tx_root", header.tx_root);
    w.setHash("receipts_root", header.receipts_root);
    w.setHash("validator_set_root", header.validator_set_root);

    w.setHexU64("total_fees", header.total_fees);
    w.setNumber("tx_count", header.tx_count);
    w.setNumber("active_validator_count", header.active_validator_count);

    return j;
  }

  // ===========================================================================
  //  Block
  // ===========================================================================

  Common::Json encodeBlock(const Core::Block &block,
                           bool include_transactions,
                           const std::string &hrp)
  {
    // Reuse the header encoder, then extend.
    Common::Json j = encodeBlockHeader(block.header, hrp);
    JsonWriter w(j);

    Common::Json txs = Common::Json::array();
    if (include_transactions)
    {
      for (const auto &tx : block.transactions)
        txs.push_back(encodeTransaction(tx, hrp));
    }
    else
    {
      for (const auto &tx : block.transactions)
        txs.push_back(encodeBytesHex(tx.txid().data));
    }
    w.setObject("transactions", std::move(txs));

    Common::Json parts = Common::Json::array();
    for (Id vid : block.participants)
      parts.push_back(encodeU64Hex(vid));
    w.setObject("participants", std::move(parts));

    // Quorum signatures: exposed but not primary. Clients that need
    // them for verification get them; clients that don't, ignore them.
    Common::Json sigs = Common::Json::array();
    for (const auto &qs : block.quorum_signatures)
    {
      Common::Json s = Common::Json::object();
      JsonWriter sw(s);
      sw.setNumber("signer_index", qs.signer_index);
      sw.setSignature("signature", qs.signature);
      sigs.push_back(std::move(s));
    }
    w.setObject("quorum_signatures", std::move(sigs));

    return j;
  }

  // ===========================================================================
  //  Order
  // ===========================================================================

  Common::Json encodeOrder(const Core::Order &order, const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHexU64("id", order.id);
    w.setAddress("owner", order.owner, hrp);
    w.setString("mode", modeName(order.mode));
    w.setNumber("mode_code", static_cast<uint64_t>(order.mode));

    w.setHexU64("sell_token", order.sell_token);
    w.setHexU64("buy_token", order.buy_token);
    w.setHexU64("sell_amount", order.sell_amount);
    w.setHexU64("min_buy_amount", order.min_buy_amount);
    w.setHexU64("filled_amount", order.filled_amount);
    w.setHexU64("remaining_amount", order.remainingAmount());

    w.setHexU64("created_at_height", order.created_at_height);
    w.setHexU64("order_expires_at_height", order.order_expires_at_height);
    w.setBool("is_fully_filled", order.isFullyFilled());

    w.setNumber("condition_count", order.condition_count);

    Common::Json arr = Common::Json::array();
    for (uint8_t i = 0;
         i < order.condition_count && i < Core::ORDER_MAX_CONDITIONS;
         ++i)
    {
      arr.push_back(encodeCondition(order.conditions[i]));
    }
    w.setObject("conditions", std::move(arr));

    return j;
  }

  // ===========================================================================
  //  Token
  // ===========================================================================

  Common::Json encodeToken(const Core::TokenInfo &token, const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHexU64("id", token.id);
    w.setString("name", token.name);
    w.setString("symbol", token.symbol);
    w.setNumber("decimals", token.decimals);
    w.setAddress("creator", token.creator, hrp);
    w.setString("backing", backingName(token.backing));
    w.setNumber("backing_code", static_cast<uint64_t>(token.backing));
    w.setHexU64("max_supply", token.maxSupply);
    w.setNumber("royalty_bps", token.royaltyBps);

    if (token.fingerprint.has_value())
      w.setHash("fingerprint", *token.fingerprint);
    else
      j["fingerprint"] = Common::Json(nullptr);

    // Derived.
    w.setBool("is_native", token.isNative());
    w.setBool("is_bridged", token.isBridged());

    return j;
  }

  // ===========================================================================
  //  Transaction
  // ===========================================================================

  Common::Json encodeTransaction(const Core::Transaction &tx,
                                 const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHash("hash", tx.txid());
    w.setNumber("version", tx.version);
    w.setHexU64("chain_id", tx.chain_id);

    w.setString("type", std::string(Core::txTypeName(tx.tx_type)));
    w.setNumber("type_code", static_cast<uint64_t>(tx.tx_type));

    w.setHexU64("nonce", tx.nonce);
    w.setHexU64("valid_until_height", tx.valid_until_height);
    w.setAddress("from", tx.from, hrp);
    // `to` can legitimately be null for transactions that don't
    // have a recipient (opt-in-staking, claim-rewards, etc).
    w.setNullableAddress("to", tx.to, hrp);
    w.setHexU64("token_id", tx.token_id);
    w.setHexU64("amount", tx.amount);
    w.setHexU64("fee", tx.fee);
    w.setBytes("payload", tx.payload);
    w.setNumber("payload_size", tx.payload.size());
    w.setSignature("signature", tx.signature);

    return j;
  }

  // ===========================================================================
  //  Receipt
  // ===========================================================================

  Common::Json encodeReceipt(const Core::Receipt &r)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    switch (r.status)
    {
    case Core::ReceiptStatus::Success:
      w.setString("status", "success");
      break;
    case Core::ReceiptStatus::Failure:
      w.setString("status", "failure");
      break;
    }
    w.setNumber("status_code", static_cast<uint64_t>(r.status));
    w.setHexU64("fee_paid", r.fee_paid);

    return j;
  }

  // ===========================================================================
  //  Validator
  // ===========================================================================

  Common::Json encodeValidator(const Core::ValidatorInfo &v,
                               uint64_t current_height,
                               const std::string &hrp)
  {
    Common::Json j = Common::Json::object();
    JsonWriter w(j);

    w.setHexU64("id", v.id);
    w.setAddress("reward_address", v.reward_address, hrp);
    //  Consensus key is a signing key, not an address. Emit as raw
    //  hex, matching the documentation. Previously this used the
    //  address encoder, which produced a bech32m string that
    //  contradicted the docs and could not be distinguished from an
    //  actual address by a client.
    w.setPublicKey("consensus_key", v.effectiveConsensusKey().data);
    w.setPublicKey("node_key", v.node_key.data);
    w.setAddress("owner", v.owner, hrp);

    w.setHexU64("registered_at_height", v.registered_at_height);
    w.setHexU64("stake", v.stake);

    w.setNumber("uptime_score", v.uptime_score);
    w.setHexU64("last_ping_height", v.last_ping_height);
    w.setHexU64("last_seen_height", v.last_seen_height);

    w.setNumber("reward_multiplier", v.reward_multiplier);
    w.setNumber("infraction_count", v.infraction_count);
    w.setHexU64("last_infraction_height", v.last_infraction_height);

    w.setHexU64("total_blocks_produced", v.total_blocks_produced);
    w.setHexU64("total_rewards_earned", v.total_rewards_earned);
    w.setHexU64("epochs_active", v.epochs_active);

    w.setBool("is_seed", v.is_seed);
    w.setBool("is_active", v.is_active);
    w.setHexU64("became_active_at", v.became_active_at);
    w.setHexU64("last_active_at", v.last_active_at);

    // Derived.
    w.setBool("can_be_active", v.canBeActive());
    w.setBool("meets_stake_req", v.meetsStakeRequirement());
    w.setBool("is_offline", v.isOffline(current_height));

    return j;
  }

  Common::Json encodeValidatorList(
      const std::vector<Core::ValidatorInfo> &validators,
      uint64_t current_height,
      const std::string &hrp)
  {
    auto sorted = validators;
    std::sort(sorted.begin(), sorted.end(),
              [](const Core::ValidatorInfo &a, const Core::ValidatorInfo &b)
              {
                return a.id < b.id;
              });

    Common::Json arr = Common::Json::array();
    for (const auto &v : sorted)
    {
      arr.push_back(encodeValidator(v, current_height, hrp));
    }
    return arr;
  }
} // namespace Rpc