// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionBuilder.h"

#include "Signer.h"

#include "Core/BridgeTypes.h"
#include "Core/TransactionTypes.h"
#include "Core/NftTypes.h"
#include "Core/OrderBook.h"

#include <cstring>

namespace Wallet
{
  namespace
  {
    void appendU8(std::vector<uint8_t> &out, uint8_t v)
    {
      out.push_back(v);
    }

    void appendU16(std::vector<uint8_t> &out, uint16_t v)
    {
      out.push_back(uint8_t(v));
      out.push_back(uint8_t(v >> 8));
    }

    void appendU32(std::vector<uint8_t> &out, uint32_t v)
    {
      out.push_back(uint8_t(v));
      out.push_back(uint8_t(v >> 8));
      out.push_back(uint8_t(v >> 16));
      out.push_back(uint8_t(v >> 24));
    }

    void appendU64(std::vector<uint8_t> &out, uint64_t v)
    {
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(v >> (i * 8)));
    }

    void appendHash(std::vector<uint8_t> &out, const Crypto::Hash &h)
    {
      out.insert(out.end(), h.data.begin(), h.data.end());
    }

    bool appendLenString(std::vector<uint8_t> &out,
                         const std::string &s,
                         bool len_u16,
                         size_t max_len,
                         WalletStatus *error_out,
                         const char *field_name)
    {
      if (s.size() > max_len)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              std::string(field_name) + " exceeds maximum length");
        return false;
      }
      if (len_u16)
        appendU16(out, static_cast<uint16_t>(s.size()));
      else
        appendU8(out, static_cast<uint8_t>(s.size()));
      out.insert(out.end(), s.begin(), s.end());
      return true;
    }

    bool validateCommon(const Crypto::Address &from,
                        const TxCommonParams &common,
                        WalletStatus *error_out)
    {
      if (from.isNull())
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "from address is null");
        return false;
      }

      if (common.chain_id == 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "chain_id is zero");
        return false;
      }

      if (common.fee == 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "fee must be non-zero");
        return false;
      }

      return true;
    }

    Core::Transaction makeBase(Core::TxType type,
                               const Crypto::Address &from,
                               const TxCommonParams &common)
    {
      Core::Transaction tx;
      tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
      tx.chain_id = common.chain_id;
      tx.tx_type = type;
      tx.nonce = common.nonce;
      tx.valid_until_height = common.valid_until_height;
      tx.from = from;
      tx.fee = common.fee;
      return tx;
    }

    //  Validate that a signature block is structurally well-formed:
    //  2-byte count followed by exactly count * 66 bytes. The
    //  executor's parseBridgeSignatureBlock does the same check,
    //  but catching it here means the caller gets an error before
    //  signing rather than after submitting a rejected transaction.
    bool validateSignatureBlock(const std::vector<uint8_t> &block,
                                WalletStatus *error_out)
    {
      if (block.size() < 2)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "signature block is too short (needs at least a 2-byte count)");
        return false;
      }
      const uint16_t count =
          uint16_t(block[0]) | (uint16_t(block[1]) << 8);
      if (block.size() != 2 + static_cast<size_t>(count) * 66)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "signature block length does not match its declared count");
        return false;
      }
      return true;
    }
  } // anonymous namespace

  //  ---- Transfer ----

  std::optional<Core::Transaction> buildTransfer(
      const Crypto::Address &from,
      const TransferParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.to.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "transfer destination is null");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "transfer amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::Transfer, from, params.common);
    tx.to = params.to;
    tx.token_id = params.token_id;
    tx.amount = params.amount;
    return tx;
  }

  //  ---- Staking ----

  namespace
  {
    std::optional<Core::Transaction> buildStakingTx(
        Core::TxType type,
        const Crypto::Address &from,
        const StakingParams &params,
        WalletStatus *error_out)
    {
      if (!validateCommon(from, params.common, error_out))
        return std::nullopt;

      return makeBase(type, from, params.common);
    }
  } // anonymous namespace

  std::optional<Core::Transaction> buildOptInStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    return buildStakingTx(Core::TxType::OptInStaking,
                          from, params, error_out);
  }

  std::optional<Core::Transaction> buildOptOutStaking(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    return buildStakingTx(Core::TxType::OptOutStaking,
                          from, params, error_out);
  }

  std::optional<Core::Transaction> buildClaimRewards(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    return buildStakingTx(Core::TxType::ClaimRewards,
                          from, params, error_out);
  }

  //  ---- Register Validator ----

  std::optional<Core::Transaction> buildRegisterValidator(
      const Crypto::Address &from,
      const RegisterValidatorParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.node_key.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "validator node key is null");
      return std::nullopt;
    }

    if (params.stake < GlobalConfig::VALIDATOR_MIN_STAKE)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "stake below VALIDATOR_MIN_STAKE");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::RegisterValidator, from, params.common);
    tx.amount = params.stake;
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(),
                params.node_key.data.data(),
                params.node_key.data.size());
    return tx;
  }

  //  ---- Unregister Validator ----

  std::optional<Core::Transaction> buildUnregisterValidator(
      const Crypto::Address &from,
      const StakingParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    return makeBase(Core::TxType::UnregisterValidator, from, params.common);
  }

  //  ---- Update Reward Address ----

  std::optional<Core::Transaction> buildUpdateRewardAddress(
      const Crypto::Address &from,
      const UpdateRewardParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.new_reward_address.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new reward address is null");
      return std::nullopt;
    }

    if (params.new_reward_address == from)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new reward address equals current address");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::UpdateRewardAddress, from, params.common);
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(),
                params.new_reward_address.data.data(),
                params.new_reward_address.data.size());
    return tx;
  }

  //  ---- Rotate Consensus Key ----

  std::optional<Core::Transaction> buildRotateConsensusKey(
      const Crypto::Address &from,
      const RotateConsensusParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.new_consensus_key.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new consensus key is null");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::RotateConsensusKey, from, params.common);
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(),
                params.new_consensus_key.data.data(),
                params.new_consensus_key.data.size());
    return tx;
  }

  //  ---- Create Token ----

  std::optional<Core::Transaction> buildCreateToken(
      const Crypto::Address &from,
      const CreateTokenParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.name.empty())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "token name is empty");
      return std::nullopt;
    }

    if (params.symbol.size() < Core::TOKEN_SYMBOL_MIN ||
        params.symbol.size() > Core::TOKEN_SYMBOL_MAX)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "token symbol must be between TOKEN_SYMBOL_MIN and "
            "TOKEN_SYMBOL_MAX characters");
      return std::nullopt;
    }

    if (params.decimals > 18)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "decimals must be between 0 and 18");
      return std::nullopt;
    }

    if (params.backing > 1)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "backing must be 0 (unbacked) or 1 (bridged)");
      return std::nullopt;
    }

    if (params.royalty_bps > 10'000)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "royalty_bps must be between 0 and 10000");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::CreateToken, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU8(p, params.decimals);
    appendU8(p, params.backing);

    if (!appendLenString(p, params.name, /*len_u16=*/false,
                         Core::TOKEN_NAME_MAX, error_out, "name"))
      return std::nullopt;
    if (!appendLenString(p, params.symbol, /*len_u16=*/false,
                         Core::TOKEN_SYMBOL_MAX, error_out, "symbol"))
      return std::nullopt;

    appendU64(p, params.max_supply);
    appendU16(p, params.royalty_bps);

    if (params.fingerprint.has_value())
    {
      appendU8(p, 1);
      appendHash(p, *params.fingerprint);
    }
    else
    {
      appendU8(p, 0);
    }

    return tx;
  }

  //  ---- Mint Token ----

  std::optional<Core::Transaction> buildMintToken(
      const Crypto::Address &from,
      const MintTokenParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.token_id == NATIVE_TOKEN_ID)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "cannot mint the native token");
      return std::nullopt;
    }

    if (params.to.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "mint recipient is null");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "mint amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::MintToken, from, params.common);
    tx.to = params.to;
    tx.token_id = params.token_id;
    tx.amount = params.amount;
    return tx;
  }

  //  ---- Burn Token ----

  std::optional<Core::Transaction> buildBurnToken(
      const Crypto::Address &from,
      const BurnTokenParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.token_id == NATIVE_TOKEN_ID)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "cannot burn the native token");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "burn amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::BurnToken, from, params.common);
    tx.token_id = params.token_id;
    tx.amount = params.amount;
    return tx;
  }

  //  ---- Update Token Meta ----

  std::optional<Core::Transaction> buildUpdateTokenMeta(
      const Crypto::Address &from,
      const UpdateTokenMetaParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.token_id == NATIVE_TOKEN_ID)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "cannot update the native token's metadata");
      return std::nullopt;
    }

    if (params.new_name.empty() &&
        params.new_symbol.empty() &&
        params.new_royalty_bps == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "no metadata change requested");
      return std::nullopt;
    }

    if (!params.new_symbol.empty() &&
        (params.new_symbol.size() < Core::TOKEN_SYMBOL_MIN ||
         params.new_symbol.size() > Core::TOKEN_SYMBOL_MAX))
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new symbol must be between TOKEN_SYMBOL_MIN and "
            "TOKEN_SYMBOL_MAX characters");
      return std::nullopt;
    }

    if (params.new_royalty_bps > 10'000)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new_royalty_bps must be between 0 and 10000");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::UpdateTokenMeta, from, params.common);
    tx.token_id = params.token_id;

    std::vector<uint8_t> &p = tx.payload;
    if (!appendLenString(p, params.new_name, /*len_u16=*/false,
                         Core::TOKEN_NAME_MAX, error_out, "new_name"))
      return std::nullopt;
    if (!appendLenString(p, params.new_symbol, /*len_u16=*/false,
                         Core::TOKEN_SYMBOL_MAX, error_out, "new_symbol"))
      return std::nullopt;
    appendU16(p, params.new_royalty_bps);

    return tx;
  }

  //  ---- NFT: Create Collection ----

  std::optional<Core::Transaction> buildCreateNftCollection(
      const Crypto::Address &from,
      const CreateNftCollectionParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.name.empty())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "collection name is empty");
      return std::nullopt;
    }
    if (params.symbol.empty())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "collection symbol is empty");
      return std::nullopt;
    }

    if (params.reward_token_id == 0)
    {
      if (params.reward_rate_per_epoch != 0 || params.escrow_amount != 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "reward_token_id is zero but rate or escrow is non-zero");
        return std::nullopt;
      }
    }
    else
    {
      if (params.reward_rate_per_epoch == 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "reward_token_id set but reward_rate_per_epoch is zero");
        return std::nullopt;
      }
    }

    Core::Transaction tx = makeBase(Core::TxType::CreateNftCollection,
                                    from, params.common);

    std::vector<uint8_t> &p = tx.payload;

    if (!appendLenString(p, params.name, /*len_u16=*/false,
                         Core::NFT_COLLECTION_NAME_MAX, error_out, "name"))
      return std::nullopt;
    if (!appendLenString(p, params.symbol, /*len_u16=*/false,
                         Core::NFT_COLLECTION_SYMBOL_MAX, error_out, "symbol"))
      return std::nullopt;
    if (!appendLenString(p, params.base_uri, /*len_u16=*/true,
                         Core::NFT_URI_MAX, error_out, "base_uri"))
      return std::nullopt;

    appendU32(p, params.reward_token_id);
    appendU64(p, params.reward_rate_per_epoch);
    appendU64(p, params.escrow_amount);

    return tx;
  }

  //  ---- NFT: Mint ----

  std::optional<Core::Transaction> buildMintNft(
      const Crypto::Address &from,
      const MintNftParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.metadata_uri.size() > Core::NFT_URI_MAX)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "metadata_uri exceeds maximum length");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::MintNft, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.collection_id);

    const bool has_hash = !params.metadata_hash.isNull();
    appendHash(p, params.metadata_hash);
    appendU8(p, has_hash ? 1 : 0);

    appendU16(p, static_cast<uint16_t>(params.metadata_uri.size()));
    p.insert(p.end(), params.metadata_uri.begin(), params.metadata_uri.end());

    return tx;
  }

  //  ---- NFT: Wrap ----

  std::optional<Core::Transaction> buildWrapNft(
      const Crypto::Address &from,
      const WrapNftParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.underlying_token_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "underlying_token_id is zero");
      return std::nullopt;
    }
    if (params.wrapped_amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "wrapped_amount is zero");
      return std::nullopt;
    }
    if (params.metadata_uri.size() > Core::NFT_URI_MAX)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "metadata_uri exceeds maximum length");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::WrapNft, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU32(p, params.underlying_token_id);
    appendU64(p, params.wrapped_amount);
    appendU64(p, params.collection_id);

    const bool has_hash = !params.metadata_hash.isNull();
    appendHash(p, params.metadata_hash);
    appendU8(p, has_hash ? 1 : 0);

    appendU16(p, static_cast<uint16_t>(params.metadata_uri.size()));
    p.insert(p.end(), params.metadata_uri.begin(), params.metadata_uri.end());

    return tx;
  }

  //  ---- NFT: Transfer ----

  std::optional<Core::Transaction> buildTransferNft(
      const Crypto::Address &from,
      const TransferNftParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.nft_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "nft_id is zero");
      return std::nullopt;
    }
    if (params.new_owner.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "new_owner is null");
      return std::nullopt;
    }
    if (params.new_owner == from)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "new_owner equals current owner");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::TransferNft, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.nft_id);
    p.insert(p.end(), params.new_owner.data.begin(), params.new_owner.data.end());

    return tx;
  }

  //  ---- NFT: Burn ----

  std::optional<Core::Transaction> buildBurnNft(
      const Crypto::Address &from,
      const BurnNftParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.nft_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "nft_id is zero");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::BurnNft, from, params.common);
    appendU64(tx.payload, params.nft_id);
    return tx;
  }

  //  ---- NFT: Update Metadata ----

  std::optional<Core::Transaction> buildUpdateNftMetadata(
      const Crypto::Address &from,
      const UpdateNftMetadataParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.nft_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "nft_id is zero");
      return std::nullopt;
    }
    if (params.metadata_uri.size() > Core::NFT_URI_MAX)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "metadata_uri exceeds maximum length");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::UpdateNftMetadata,
                                    from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.nft_id);

    const bool has_hash = !params.metadata_hash.isNull();
    appendHash(p, params.metadata_hash);
    appendU8(p, has_hash ? 1 : 0);

    appendU16(p, static_cast<uint16_t>(params.metadata_uri.size()));
    p.insert(p.end(), params.metadata_uri.begin(), params.metadata_uri.end());

    appendU8(p, params.freeze ? 1 : 0);

    return tx;
  }

  //  ---- NFT: Top Up ----

  std::optional<Core::Transaction> buildTopUpNft(
      const Crypto::Address &from,
      const TopUpNftParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.nft_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "nft_id is zero");
      return std::nullopt;
    }
    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::TopUpNft, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.nft_id);
    appendU32(p, params.token_id);
    appendU64(p, params.amount);

    return tx;
  }

  //  ---- NFT: Claim Reward ----

  std::optional<Core::Transaction> buildClaimNftReward(
      const Crypto::Address &from,
      const ClaimNftRewardParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    return makeBase(Core::TxType::ClaimNftReward, from, params.common);
  }

  //  ---- NFT: Refill Collection Reward ----

  std::optional<Core::Transaction> buildRefillCollectionReward(
      const Crypto::Address &from,
      const RefillCollectionRewardParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.collection_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "collection_id is zero");
      return std::nullopt;
    }
    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::RefillCollectionReward,
                                    from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.collection_id);
    appendU64(p, params.amount);

    return tx;
  }

  //  ---- AMM: Create Pool ----

  std::optional<Core::Transaction> buildCreatePool(
      const Crypto::Address &from,
      const CreatePoolParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.token_a == params.token_b)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "token_a and token_b must differ");
      return std::nullopt;
    }

    if (params.amount_a == 0 || params.amount_b == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "both amounts must be non-zero");
      return std::nullopt;
    }

    if (params.fee_bps > Core::AMM_MAX_FEE_BPS)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "fee_bps exceeds AMM_MAX_FEE_BPS");
      return std::nullopt;
    }

    if (params.token_a == NATIVE_TOKEN_ID &&
        params.amount_a < Core::MIN_POOL_LIQUIDITY)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "CLRTY side is below MIN_POOL_LIQUIDITY");
      return std::nullopt;
    }

    if (params.token_b == NATIVE_TOKEN_ID &&
        params.amount_b < Core::MIN_POOL_LIQUIDITY)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "CLRTY side is below MIN_POOL_LIQUIDITY");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::CreatePool, from, params.common);

    tx.token_id = params.token_a;
    tx.amount = params.amount_a;

    std::vector<uint8_t> &p = tx.payload;
    appendU32(p, params.token_b);
    appendU64(p, params.amount_b);
    appendU16(p, params.fee_bps);

    return tx;
  }

  //  ---- AMM: Add Liquidity ----

  std::optional<Core::Transaction> buildAddLiquidity(
      const Crypto::Address &from,
      const AddLiquidityParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    if (params.amount_in == 0 || params.amount_other == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "both amounts must be non-zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::AddLiquidity, from, params.common);
    tx.token_id = params.token_in;
    tx.amount = params.amount_in;

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.pool_id);
    appendU64(p, params.amount_other);

    return tx;
  }

  //  ---- AMM: Remove Liquidity ----

  std::optional<Core::Transaction> buildRemoveLiquidity(
      const Crypto::Address &from,
      const RemoveLiquidityParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.position_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "position_id is zero");
      return std::nullopt;
    }

    Core::Transaction tx = makeBase(Core::TxType::RemoveLiquidity,
                                    from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.position_id);
    appendU64(p, params.amount);

    return tx;
  }

  //  ---- AMM: Swap ----

  std::optional<Core::Transaction> buildSwap(
      const Crypto::Address &from,
      const SwapParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    if (params.amount_in == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount_in is zero");
      return std::nullopt;
    }

    if (params.to.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "swap recipient is null");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::Swap, from, params.common);
    tx.token_id = params.token_in;
    tx.amount = params.amount_in;
    tx.to = params.to;

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.pool_id);
    appendU64(p, params.min_amount_out);

    return tx;
  }

  //  ---- Order Book: Create Order ----

  std::optional<Core::Transaction> buildCreateOrder(
      const Crypto::Address &from,
      const CreateOrderParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.sell_token == params.buy_token)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "sell_token and buy_token must differ");
      return std::nullopt;
    }

    if (params.sell_amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "sell_amount is zero");
      return std::nullopt;
    }

    if (params.min_buy_amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "min_buy_amount is zero");
      return std::nullopt;
    }

    if (params.mode != Core::OrderExecutionMode::Passive &&
        params.mode != Core::OrderExecutionMode::Active)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "unknown order mode");
      return std::nullopt;
    }

    if (params.mode == Core::OrderExecutionMode::Active)
    {
      if (params.pool_id == 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "Active order requires a non-zero pool_id");
        return std::nullopt;
      }
    }
    else
    {
      if (params.pool_id != 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "Passive order must have pool_id == 0");
        return std::nullopt;
      }
    }

    if (params.conditions.size() > Core::ORDER_MAX_CONDITIONS)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "too many conditions");
      return std::nullopt;
    }

    for (const auto &c : params.conditions)
    {
      if (!c.isValid())
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "one or more conditions are invalid");
        return std::nullopt;
      }
    }

    if (params.mode == Core::OrderExecutionMode::Passive)
    {
      Core::Order probe;
      probe.sell_token = params.sell_token;
      probe.buy_token = params.buy_token;
      probe.sell_amount = params.sell_amount;
      probe.min_buy_amount = params.min_buy_amount;
      uint64_t canonical_price = 0;
      if (!Core::OrderBook::canonicalPrice(probe, canonical_price))
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::InvalidParameter,
              "canonical price overflows; order cannot enter the book");
        return std::nullopt;
      }
    }

    Core::Transaction tx =
        makeBase(Core::TxType::CreateOrder, from, params.common);
    tx.token_id = params.sell_token;
    tx.amount = params.sell_amount;

    std::vector<uint8_t> &p = tx.payload;
    appendU32(p, params.buy_token);
    appendU64(p, params.min_buy_amount);
    appendU8(p, static_cast<uint8_t>(params.mode));
    appendU32(p, static_cast<uint32_t>(params.pool_id));
    appendU64(p, params.expires_at_height);
    appendU8(p, static_cast<uint8_t>(params.conditions.size()));

    for (const auto &c : params.conditions)
      c.serializeState(p);

    return tx;
  }

  //  ---- Order Book: Cancel Order ----

  std::optional<Core::Transaction> buildCancelOrder(
      const Crypto::Address &from,
      const CancelOrderParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.order_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "order_id is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::CancelOrder, from, params.common);
    appendU64(tx.payload, params.order_id);
    return tx;
  }

  //  =========================================================================
  //  AMM Farming
  //  =========================================================================

  //  ---- AMM Farm: Create ----

  std::optional<Core::Transaction> buildCreateAmmFarm(
      const Crypto::Address &from,
      const CreateAmmFarmParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    if (params.reward_rate_per_epoch == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "reward_rate_per_epoch must be non-zero");
      return std::nullopt;
    }

    if (params.reward_escrow_amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "reward_escrow_amount must be non-zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::CreateAmmFarm, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.pool_id);
    appendU32(p, params.reward_token_id);
    appendU64(p, params.reward_rate_per_epoch);
    appendU64(p, params.reward_escrow_amount);

    return tx;
  }

  //  ---- AMM Farm: Update Rate ----

  std::optional<Core::Transaction> buildUpdateAmmFarm(
      const Crypto::Address &from,
      const UpdateAmmFarmParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    if (params.new_rate_per_epoch == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "new_rate_per_epoch must be non-zero "
            "(use PauseAmmFarm to stop emissions)");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::UpdateAmmFarm, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.pool_id);
    appendU64(p, params.new_rate_per_epoch);

    return tx;
  }

  //  ---- AMM Farm: Pause ----

  std::optional<Core::Transaction> buildPauseAmmFarm(
      const Crypto::Address &from,
      const PauseAmmFarmParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::PauseAmmFarm, from, params.common);
    appendU64(tx.payload, params.pool_id);
    return tx;
  }

  //  ---- AMM Farm: Refill ----

  std::optional<Core::Transaction> buildRefillAmmFarm(
      const Crypto::Address &from,
      const RefillAmmFarmParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::RefillAmmFarm, from, params.common);

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.pool_id);
    appendU64(p, params.amount);

    return tx;
  }

  //  ---- AMM Farm: Close ----

  std::optional<Core::Transaction> buildCloseAmmFarm(
      const Crypto::Address &from,
      const CloseAmmFarmParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.pool_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "pool_id is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::CloseAmmFarm, from, params.common);
    appendU64(tx.payload, params.pool_id);
    return tx;
  }

  //  ---- AMM Farm: Claim Rewards ----

  std::optional<Core::Transaction> buildClaimAmmFarmRewards(
      const Crypto::Address &from,
      const ClaimAmmFarmRewardsParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    return makeBase(Core::TxType::ClaimAmmFarmRewards,
                    from, params.common);
  }

  //  =========================================================================
  //  Bridge
  //  =========================================================================

  //  ---- BridgeMint ----

  std::optional<Core::Transaction> buildBridgeMint(
      const Crypto::Address &from,
      const BridgeMintParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.source_chain_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "source_chain_id is zero");
      return std::nullopt;
    }

    if (params.source_tx_hash.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "source_tx_hash is null");
      return std::nullopt;
    }

    if (params.destination.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "destination is null");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount is zero");
      return std::nullopt;
    }

    if (!validateSignatureBlock(params.signature_block, error_out))
      return std::nullopt;

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeMint, from, params.common);

    //  Fixed fields: `to` is the submitter (not the destination),
    //  `amount` is zero (the mint amount lives in the payload
    //  because it is denominated in the wrapped token, not the
    //  fee/native token).
    tx.to = from;
    tx.amount = 0;

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.source_chain_id);
    appendHash(p, params.source_tx_hash);
    appendU32(p, params.source_output_index);
    p.insert(p.end(),
             params.destination.data.begin(),
             params.destination.data.end());
    appendU64(p, params.amount);
    p.insert(p.end(),
             params.signature_block.begin(),
             params.signature_block.end());

    return tx;
  }

  //  ---- BridgeBurn ----

  std::optional<Core::Transaction> buildBridgeBurn(
      const Crypto::Address &from,
      const BridgeBurnParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.source_chain_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "source_chain_id is zero");
      return std::nullopt;
    }

    if (params.wrapped_token_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "wrapped_token_id is zero");
      return std::nullopt;
    }

    if (params.destination_blob.empty())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "destination_blob is empty");
      return std::nullopt;
    }

    if (params.destination_blob.size() > 255)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "destination_blob exceeds 255 bytes");
      return std::nullopt;
    }

    //  Chain-aware destination-blob shape check.
    //
    //  The burn tx carries destination_blob verbatim to the
    //  withdrawal record; the release path (CcxAdapter or
    //  BitcoinAdapter, via validate_destination) is what actually
    //  consumes it. A blob that the release-side validator will
    //  reject is an unreleasable burn: the burn is on-chain, the
    //  quorum forms, the release attempt fails, and the user's
    //  value is stranded. Catching the shape at build time moves
    //  the failure from "after quorum + finality" to "before the
    //  tx is signed", which is strictly better.
    //
    //  For CCX, the 64-byte length is the whole shape; the spend
    //  and view keys are opaque pubkeys and there's nothing
    //  cheaper to validate here than "is it 64 bytes". The
    //  existing `destination_blob.size() > 255` check above is
    //  not enough — a 40-byte blob would pass it and fail every
    //  release attempt. So enforce 64 for CCX here too.
    //
    //  For BTC, accept the four standard output-script shapes.
    //  Anything else (ASCII bytes of the bech32 string, the raw
    //  20-byte hash, a P2WSH script) is rejected. The check is
    //  chain-agnostic in the sense that all four shapes are
    //  valid on mainnet/testnet/regtest — only the bech32 HRP
    //  differs, and destination_blob doesn't carry the HRP.
    {
      constexpr uint64_t kCcxChainId = 0x43435831ULL; // 'CCX1'
      constexpr uint64_t kBtcChainId = 0x42544331ULL; // 'BTC1'

      const auto &b = params.destination_blob;
      const size_t n = b.size();

      if (params.source_chain_id == kCcxChainId)
      {
        if (n != 64)
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::InvalidParameter,
                "CCX destination_blob must be exactly 64 bytes "
                "(spend ‖ view pubkeys); got " +
                    std::to_string(n));
          return std::nullopt;
        }
      }
      else if (params.source_chain_id == kBtcChainId)
      {
        const bool valid_btc_shape =
            (n == 22 && b[0] == 0x00 && b[1] == 0x14) ||                  // P2WPKH
            (n == 23 && b[0] == 0xa9 && b[1] == 0x14 && b[22] == 0x87) || // P2SH
            (n == 25 && b[0] == 0x76 && b[1] == 0xa9 && b[2] == 0x14 &&
             b[23] == 0x88 && b[24] == 0xac) ||        // P2PKH
            (n == 34 && b[0] == 0x51 && b[1] == 0x20); // P2TR

        if (!valid_btc_shape)
        {
          if (error_out)
          {
            std::string got_hex;
            static const char HEX[] = "0123456789abcdef";
            for (size_t i = 0; i < std::min<size_t>(n, 4); ++i)
            {
              got_hex.push_back(HEX[b[i] >> 4]);
              got_hex.push_back(HEX[b[i] & 0xF]);
            }
            if (n > 4)
              got_hex += "…";
            *error_out = WalletStatus::fail(
                WalletError::InvalidParameter,
                "Bitcoin destination_blob must be a supported "
                "scriptPubKey: P2WPKH (22B 0x0014…), P2SH "
                "(23B 0xa914…87), P2PKH (25B 0x76a914…88ac), or "
                "P2TR (34B 0x5120…). Got " +
                    std::to_string(n) +
                    " bytes starting with 0x" + got_hex +
                    ". Pass the scriptPubKey bytes, not the bech32 "
                    "string.");
          }
          return std::nullopt;
        }
      }
      //  Unknown source_chain_id: don't invent a shape check here.
      //  The executor gates on the chain being registered, and
      //  registration is where the chain's adapter constraints
      //  are declared. An unregistered chain never reaches
      //  buildBridgeBurn in normal use; if it somehow does, the
      //  executor rejects the tx on apply and no funds move.
      //  Adding a guess here would just be a second place to get
      //  the shape wrong.
    }

    if (params.destination_address.empty())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "destination_address is empty");
      return std::nullopt;
    }

    if (params.destination_address.size() > 255)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "destination_address exceeds 255 bytes");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount is zero");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeBurn, from, params.common);
    tx.to = from;
    tx.token_id = params.wrapped_token_id;
    tx.amount = 0;

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.source_chain_id);
    appendU8(p, static_cast<uint8_t>(params.destination_blob.size()));
    p.insert(p.end(),
             params.destination_blob.begin(),
             params.destination_blob.end());
    appendU8(p, static_cast<uint8_t>(params.destination_address.size()));
    p.insert(p.end(),
             params.destination_address.begin(),
             params.destination_address.end());
    appendU64(p, params.amount);

    return tx;
  }

  //  ---- BridgeAckWithdrawal ----

  std::optional<Core::Transaction> buildBridgeAckWithdrawal(
      const Crypto::Address &from,
      const BridgeAckWithdrawalParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.withdrawal_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "withdrawal_id is zero");
      return std::nullopt;
    }

    if (params.release_tx_hash.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "release_tx_hash is null");
      return std::nullopt;
    }

    if (params.release_height == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "release_height is zero");
      return std::nullopt;
    }

    if (!validateSignatureBlock(params.signature_block, error_out))
      return std::nullopt;

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeAckWithdrawal, from, params.common);
    tx.to = from;
    tx.amount = 0;

    //  Payload layout (matching executeBridgeAckWithdrawal):
    //    [8]  withdrawal_id
    //    [32] release_tx_hash
    //    [8]  release_height
    //    [2]  count || N*66 signature block
    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.withdrawal_id);
    appendHash(p, params.release_tx_hash);
    appendU64(p, params.release_height);
    p.insert(p.end(),
             params.signature_block.begin(),
             params.signature_block.end());

    return tx;
  }

  //  ---- BridgePause / BridgeUnpause ----

  namespace
  {
    std::optional<Core::Transaction> buildBridgePauseKind(
        Core::TxType type,
        const Crypto::Address &from,
        const BridgePauseParams &params,
        WalletStatus *error_out)
    {
      if (!validateCommon(from, params.common, error_out))
        return std::nullopt;

      if (!validateSignatureBlock(params.signature_block, error_out))
        return std::nullopt;

      Core::Transaction tx = makeBase(type, from, params.common);
      tx.to = from;
      tx.amount = 0;

      std::vector<uint8_t> &p = tx.payload;
      appendU64(p, params.bound_height);
      p.insert(p.end(),
               params.signature_block.begin(),
               params.signature_block.end());

      return tx;
    }
  } // anonymous namespace

  std::optional<Core::Transaction> buildBridgePause(
      const Crypto::Address &from,
      const BridgePauseParams &params,
      WalletStatus *error_out)
  {
    return buildBridgePauseKind(Core::TxType::BridgePause,
                                from, params, error_out);
  }

  std::optional<Core::Transaction> buildBridgeUnpause(
      const Crypto::Address &from,
      const BridgePauseParams &params,
      WalletStatus *error_out)
  {
    return buildBridgePauseKind(Core::TxType::BridgeUnpause,
                                from, params, error_out);
  }

  //  ---- BridgeRegisterChain ----

  std::optional<Core::Transaction> buildBridgeRegisterChain(
      const Crypto::Address &from,
      const BridgeRegisterChainParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.registration_blob.empty())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "registration_blob is empty");
      return std::nullopt;
    }

    //  The registration blob length is a single byte prefix.
    if (params.registration_blob.size() > 255)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter,
            "registration_blob exceeds 255 bytes");
      return std::nullopt;
    }

    if (!validateSignatureBlock(params.signature_block, error_out))
      return std::nullopt;

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeRegisterChain, from, params.common);
    tx.to = from;
    tx.amount = 0;

    std::vector<uint8_t> &p = tx.payload;
    appendU8(p, static_cast<uint8_t>(params.registration_blob.size()));
    p.insert(p.end(),
             params.registration_blob.begin(),
             params.registration_blob.end());
    p.insert(p.end(),
             params.signature_block.begin(),
             params.signature_block.end());

    return tx;
  }

  //  ---- BridgeRegisterDeposit ----

  std::optional<Core::Transaction> buildBridgeRegisterDeposit(
      const Crypto::Address &from,
      const BridgeRegisterDepositParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.source_chain_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "source_chain_id is zero");
      return std::nullopt;
    }

    if (params.destination.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "destination is null");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeRegisterDeposit, from, params.common);

    //  No `to`, no `token_id`, no `amount`: everything the
    //  executor needs is in the payload, matching the pattern
    //  BridgeRegisterChain follows.
    tx.to = from;
    tx.token_id = 0;
    tx.amount = 0;

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.source_chain_id);
    p.insert(p.end(),
             params.destination.data.begin(),
             params.destination.data.end());

    return tx;
  }

  //  ---- Sign ----

  std::optional<Crypto::Hash> signTransaction(
      Core::Transaction &tx,
      Signer &signer,
      const HdPath &path,
      WalletStatus *error_out)
  {
    if (!signer.isReady())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreLocked,
            "signer is not ready");
      return std::nullopt;
    }

    const Crypto::Hash hash = tx.signingHash();

    auto sig = signer.signAtPath(path, hash, error_out);
    if (!sig.has_value())
      return std::nullopt;

    tx.signature = *sig;
    return hash;
  }

  //  ---- BridgeAttest ----

  std::optional<Core::Transaction> buildBridgeAttest(
      const Crypto::Address &from,
      const BridgeAttestParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.source_chain_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "source_chain_id is zero");
      return std::nullopt;
    }

    if (params.source_tx_hash.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "source_tx_hash is null");
      return std::nullopt;
    }

    if (params.destination.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "destination is null");
      return std::nullopt;
    }

    if (params.amount == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "amount is zero");
      return std::nullopt;
    }

    if (params.signature.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "signature is null");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeAttest, from, params.common);
    tx.to = from;
    tx.amount = 0;

    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.source_chain_id);
    appendHash(p, params.source_tx_hash);
    appendU32(p, params.source_output_index);
    p.insert(p.end(),
             params.destination.data.begin(),
             params.destination.data.end());
    appendU64(p, params.amount);
    appendU16(p, params.signer_index);
    p.insert(p.end(),
             params.signature.data.begin(),
             params.signature.data.end());

    return tx;
  }

  //  ---- BridgeAckAttest ----

  std::optional<Core::Transaction> buildBridgeAckAttest(
      const Crypto::Address &from,
      const BridgeAckAttestParams &params,
      WalletStatus *error_out)
  {
    if (!validateCommon(from, params.common, error_out))
      return std::nullopt;

    if (params.withdrawal_id == 0)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "withdrawal_id is zero");
      return std::nullopt;
    }

    if (params.signature.isNull())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::InvalidParameter, "signature is null");
      return std::nullopt;
    }

    Core::Transaction tx =
        makeBase(Core::TxType::BridgeAckAttest, from, params.common);
    tx.to = from;
    tx.amount = 0;

    //  Payload layout (matching executeBridgeAckAttest):
    //    [8]  withdrawal_id
    //    [2]  signer_index
    //    [64] signature
    //  Total: 74 bytes.
    std::vector<uint8_t> &p = tx.payload;
    appendU64(p, params.withdrawal_id);
    appendU16(p, params.signer_index);
    p.insert(p.end(),
             params.signature.data.begin(),
             params.signature.data.end());

    return tx;
  }
} // namespace Wallet