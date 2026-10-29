// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string_view>

namespace Core
{
  //  Transaction Types
  //
  //  Every transaction has a type byte. The values are grouped by
  //  category so related types share a range. The ranges are:
  //
  //    0x00–0x0F  Core (transfers)
  //    0x10–0x1F  Staking
  //    0x20–0x2F  Validator
  //    0x30–0x3F  AMM
  //    0x40–0x4F  DEX / Orders / NFTs
  //    0x50–0x5F  Token management
  //    0x60–0x6F  Governance (reserved)
  //    0x70–0x7F  Cross-chain / Bridge
  //    0x80–0x8F  AMM Farming
  //    0xF0–0xFE  System (implicit)
  //    0xFF       Invalid sentinel
  //
  //  Values are never reused. If a type is removed, its value stays
  //  reserved. If a range is exhausted, a new range is opened; the
  //  category grouping is not load-bearing for correctness, only for
  //  readability.
  //
  //  Note on the bridge: the operational signer set is the active
  //  validator set. A validator IS a bridge watcher: there is no
  //  separate watcher role, no separate stake, no per-chain
  //  registration. Attestation quorums are computed against the
  //  active validator set at the height of the operation, using
  //  bftQuorum(active_validators). See Core/BridgeTypes.h for the
  //  full rationale.
  //
  //  The two watcher-registration types (0x77, 0x78) are reserved
  //  and never dispatched. The handler functions that used to
  //  implement them are gone. A block carrying either type is
  //  rejected by the executor's dispatch default. The enum values
  //  are kept so RPC output and log lines for a historical or
  //  foreign block name the type instead of falling through to
  //  "unknown", and so that future reuse doesn't collide with an
  //  older protocol version.

  enum TxType : uint8_t
  {
    //  ---- Core (0x00–0x0F) ----

    Transfer = 0x00,

    //  ---- Staking (0x10–0x1F) ----

    OptInStaking = 0x10,
    OptOutStaking = 0x11,
    ClaimRewards = 0x12,

    //  ---- Validator (0x20–0x2F) ----

    RegisterValidator = 0x20,
    UnregisterValidator = 0x21,
    UpdateRewardAddress = 0x22,
    RotateConsensusKey = 0x23,

    //  ---- AMM (0x30–0x3F) ----
    //
    //  Pool and liquidity primitives. Farming (which attaches a
    //  reward schedule to a pool) lives in its own range below; the
    //  split is intentional so that "AMM" reads as "the pool and
    //  its swaps" and "AMM Farming" reads as "emissions on top of
    //  it."

    CreatePool = 0x30,
    AddLiquidity = 0x31,
    RemoveLiquidity = 0x32,
    Swap = 0x33,

    //  ---- DEX / Orders / NFTs (0x40–0x4F) ----

    CreateOrder = 0x40,
    CancelOrder = 0x41,
    CreateNftCollection = 0x42,
    MintNft = 0x43,
    WrapNft = 0x44,
    TransferNft = 0x45,
    BurnNft = 0x46,
    UpdateNftMetadata = 0x47,
    TopUpNft = 0x48,
    ClaimNftReward = 0x49,
    RefillCollectionReward = 0x4A,

    //  ---- Token management (0x50–0x5F) ----

    CreateToken = 0x50,
    MintToken = 0x51,
    BurnToken = 0x52,
    UpdateTokenMeta = 0x53,

    //  ---- Cross-chain / Bridge (0x70–0x7F) ----

    BridgeMint = 0x70,
    BridgeBurn = 0x71,
    BridgePause = 0x72,
    BridgeUnpause = 0x73,
    BridgeAckWithdrawal = 0x74,
    BridgeRegisterChain = 0x75,
    //  0x76 reserved (was BridgeSetSignerSet; removed when the
    //  operational signer set became the active validator set;
    //  never reuse)
    RegisterBridgeWatcher = 0x77,   // RESERVED. No handler. Rejected by dispatch.
    UnregisterBridgeWatcher = 0x78, // RESERVED. No handler. Rejected by dispatch.
    //  Per-validator attestation over a bridge deposit. Each active
    //  validator submits one of these per deposit; the collection of
    //  BridgeAttest transactions with a quorum of distinct
    //  validator_ids is what makes a BridgeMint valid.
    BridgeAttest = 0x79,
    //  Per-validator attestation over a bridge withdrawal. Each
    //  active validator submits one of these per withdrawal; the
    //  collection of BridgeAckAttest transactions with a quorum of
    //  distinct validator_ids is what makes a BridgeAckWithdrawal
    //  valid — and what authorizes the corresponding CCX release.
    BridgeAckAttest = 0x7A,
    //  Register a per-authority deposit destination for a bridge
    //  source chain. The executor assigns the index (see
    //  BridgeDepositRecord in Core/BridgeTypes.h); the caller
    //  provides only (source_chain_id, destination). A CCX user
    //  submits one of these to bind their rclrty1... reward
    //  address to a subaddress of the bridge's custody wallet.
    //  Bitcoin does not require registration: the OP_RETURN on the
    //  deposit carries the destination directly.
    BridgeRegisterDeposit = 0x7B,

    //  ---- AMM Farming (0x80–0x8F) ----
    //
    //  A farm is an escrow + a rate attached to one pool. Emission is
    //  pro-rata across the pool's LP shares at each epoch boundary,
    //  using a reward-per-share accumulator; claims are lazily
    //  settled into pending_rewards, then moved to balance by the
    //  existing ClaimRewards. The escrow is a real token balance at
    //  Keys::ammFarmAddress(pool_id).
    //
    //  CreateAmmFarm     creates the schedule and funds the escrow
    //                    from the creator's balance of reward_token_id.
    //  UpdateAmmFarm     changes the per-epoch rate. Applies at the
    //                    *next* epoch boundary, not the current one.
    //  PauseAmmFarm      stops emissions without closing the farm.
    //  RefillAmmFarm     adds to the escrow and un-pauses.
    //  CloseAmmFarm      refunds any remaining escrow to the creator
    //                    and deletes the schedule. Refused while the
    //                    pool has liquidity; a full drain closes the
    //                    farm automatically.
    //  ClaimAmmFarmRewards
    //                    settles every position the caller holds
    //                    across every farmed pool into
    //                    pending_rewards. Empty payload.

    CreateAmmFarm = 0x80,
    UpdateAmmFarm = 0x81,
    PauseAmmFarm = 0x82,
    RefillAmmFarm = 0x83,
    CloseAmmFarm = 0x84,
    ClaimAmmFarmRewards = 0x85,

    //  ---- System (0xF0–0xFE) ----

    BlockReward = 0xF0,  // implicit, generated by consensus
    OrderExpired = 0xF1, // implicit, generated by order engine
    Slash = 0xF2,        // implicit, generated by consensus

    //  ---- Sentinel ----

    Invalid = 0xFF,
  };

  //  Returns a stable, human-readable name for a transaction type.
  //  Used by the RPC encoder (the `type` field alongside the numeric
  //  `type_code`) and by log lines.
  //
  //  The names are part of the RPC surface. Renaming one is a
  //  breaking change to clients that switch on the string; clients
  //  that switch on the numeric code are unaffected.
  constexpr std::string_view txTypeName(TxType type) noexcept
  {
    switch (type)
    {
    case Transfer:
      return "transfer";
    case OptInStaking:
      return "opt_in_staking";
    case OptOutStaking:
      return "opt_out_staking";
    case ClaimRewards:
      return "claim_rewards";
    case RegisterValidator:
      return "register_validator";
    case UnregisterValidator:
      return "unregister_validator";
    case UpdateRewardAddress:
      return "update_reward_address";
    case RotateConsensusKey:
      return "rotate_consensus_key";
    case CreatePool:
      return "create_pool";
    case AddLiquidity:
      return "add_liquidity";
    case RemoveLiquidity:
      return "remove_liquidity";
    case Swap:
      return "swap";
    case CreateOrder:
      return "create_order";
    case CancelOrder:
      return "cancel_order";
    case CreateNftCollection:
      return "create_nft_collection";
    case MintNft:
      return "mint_nft";
    case WrapNft:
      return "wrap_nft";
    case TransferNft:
      return "transfer_nft";
    case BurnNft:
      return "burn_nft";
    case UpdateNftMetadata:
      return "update_nft_metadata";
    case TopUpNft:
      return "top_up_nft";
    case ClaimNftReward:
      return "claim_nft_reward";
    case RefillCollectionReward:
      return "refill_collection_reward";
    case CreateToken:
      return "create_token";
    case MintToken:
      return "mint_token";
    case BurnToken:
      return "burn_token";
    case UpdateTokenMeta:
      return "update_token_meta";
    case BridgeMint:
      return "bridge_mint";
    case BridgeBurn:
      return "bridge_burn";
    case BridgePause:
      return "bridge_pause";
    case BridgeUnpause:
      return "bridge_unpause";
    case BridgeAckWithdrawal:
      return "bridge_ack_withdrawal";
    case BridgeRegisterChain:
      return "bridge_register_chain";
    case RegisterBridgeWatcher:
      return "register_bridge_watcher"; // reserved type name
    case UnregisterBridgeWatcher:
      return "unregister_bridge_watcher"; // reserved type name
    case BridgeAttest:
      return "bridge_attest";
    case BridgeAckAttest:
      return "bridge_ack_attest";
    case BridgeRegisterDeposit:
      return "bridge_register_deposit";
    case CreateAmmFarm:
      return "create_amm_farm";
    case UpdateAmmFarm:
      return "update_amm_farm";
    case PauseAmmFarm:
      return "pause_amm_farm";
    case RefillAmmFarm:
      return "refill_amm_farm";
    case CloseAmmFarm:
      return "close_amm_farm";
    case ClaimAmmFarmRewards:
      return "claim_amm_farm_rewards";
    case BlockReward:
      return "block_reward";
    case OrderExpired:
      return "order_expired";
    case Slash:
      return "slash";
    case Invalid:
      return "invalid";
    }
    return "unknown";
  }

  //  True if the type is a system transaction (implicitly generated
  //  by the chain, not submitted by users).
  constexpr bool isSystemTx(TxType type) noexcept
  {
    return type == Slash || type == BlockReward || type == OrderExpired;
  }

  // True if this type can be submitted by users.
  constexpr bool isUserSubmitted(TxType t) noexcept
  {
    return static_cast<uint8_t>(t) < 0xF0;
  }
} // namespace Core