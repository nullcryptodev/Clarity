// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionBuilder.h"

#include "Signer.h"

#include "Core/TransactionTypes.h"
#include "Core/NftTypes.h"

#include <cstring>

namespace Wallet
{
  namespace
  {
    //  Payload append helpers. The NFT payloads use explicit
    //  little-endian writes so the wallet builder and the executor
    //  parse the same layout without either side depending on the
    //  transaction's fixed-field serializer for the payload bytes.
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

    //  Append a hash. Always 32 bytes; the executor reads a
    //  has_hash flag separately, so the hash bytes are written
    //  unconditionally and the flag disambiguates.
    void appendHash(std::vector<uint8_t> &out, const Crypto::Hash &h)
    {
      out.insert(out.end(), h.data.begin(), h.data.end());
    }

    //  Append a length-prefixed string. `len_bytes` selects u8 or
    //  u16; the executor's parsers read the same width for the same
    //  field.
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

    //  Common validation applied to every user-submitted transaction.
    //  Builders call this first, then apply type-specific checks.
    //
    //  The executor will re-check all of these on-chain; the builder
    //  checks them so the user gets an error before signing, not after.
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

    //  Build a transaction skeleton. The builder fills in the type,
    //  common fields, and payload; the type-specific code fills in
    //  `to`, `amount`, `token_id` if it uses them.
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
      // tx.to, token_id, amount, fee left at defaults; caller fills.
      tx.fee = common.fee;
      return tx;
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
    // Payload is empty: the executor reads `to`, `token_id`, and
    // `amount` from the fixed fields.

    return tx;
  }

  //  ---- Staking (opt-in / opt-out / claim) ----

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

      Core::Transaction tx = makeBase(type, from, params.common);
      // No `to`, no `amount`, no payload. The executor uses `from`
      // to identify the account and does the rest itself.
      return tx;
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
    // The stake moves from the sender's balance into the validator
    // record. It goes in `amount`.
    tx.amount = params.stake;
    // The payload carries the P2P node key (32 bytes).
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

    Core::Transaction tx =
        makeBase(Core::TxType::UnregisterValidator, from, params.common);
    // Empty payload. The executor looks up the validator by `from`.
    return tx;
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
    // The payload carries the new reward address (32 bytes).
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(),
                params.new_reward_address.data.data(),
                params.new_reward_address.data.size());
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

    //  A reward schedule must be internally consistent. The executor
    //  enforces this too via NftCollection::isValid; the builder
    //  checks so the caller gets a pre-signing error.
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

    //  The hash is always written as 32 bytes. The flag says
    //  whether it is meaningful.
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

    Core::Transaction tx = makeBase(Core::TxType::ClaimNftReward,
                                    from, params.common);
    //  Empty payload. The executor walks the caller's NFTs.
    return tx;
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
    // Payload carries the new consensus key (32 bytes).
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

    //  Name and symbol are validated on-chain too, but a caller
    //  that passes an empty name should see the error before the
    //  fee is charged. The on-chain validation is authoritative.
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

    //  Payload layout, matching executeCreateToken:
    //    [1]  decimals
    //    [1]  backing
    //    [1]  name_len
    //    [N]  name
    //    [1]  symbol_len
    //    [M]  symbol
    //    [8]  max_supply (LE)
    //    [2]  royalty_bps (LE)
    //    [1]  has_fingerprint
    //    [32] fingerprint (only if has_fingerprint)

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

    //  The executor reads these from the fixed fields, not the
    //  payload. The payload is empty.
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

    //  Same as mint: the executor reads the fixed fields.
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

    //  A no-op update burns a fee for nothing. Reject it here so
    //  the caller sees the error before signing.
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

    //  The executor reads token_id from the fixed field.
    tx.token_id = params.token_id;

    //  Payload layout, matching executeUpdateTokenMeta:
    //    [1]  name_len
    //    [N]  name
    //    [1]  symbol_len
    //    [M]  symbol
    //    [2]  royalty_bps (LE)
    //
    //  Empty name and empty symbol mean "no change" on the
    //  respective field. The royalty is always written; the
    //  executor treats 0 as "no change".

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

    // The signing hash commits to every field except the signature
    // itself. See Transaction::signingHash().
    const Crypto::Hash hash = tx.signingHash();

    // Derive-and-sign in one call. The signer handles the derivation
    // path and the signature format.
    auto sig = signer.signAtPath(path, hash, error_out);
    if (!sig.has_value())
      return std::nullopt;

    tx.signature = *sig;
    return hash;
  }

} // namespace Wallet