// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "TransactionTypes.h"

namespace Core
{

std::string_view txTypeName(TxType t) noexcept
{
  switch (t) {
    // Core
    case TxType::Transfer:            return "transfer";

    // Staking
    case TxType::OptInStaking:        return "optin-staking";
    case TxType::OptOutStaking:       return "optout-staking";
    case TxType::ClaimRewards:        return "claim-rewards";

    // Validator
    case TxType::RegisterValidator:   return "register-validator";
    case TxType::UnregisterValidator: return "unregister-validator";
    case TxType::UpdateRewardAddress: return "update-reward-address";

    // AMM
    case TxType::CreatePool:          return "create-pool";
    case TxType::AddLiquidity:        return "add-liquidity";
    case TxType::RemoveLiquidity:     return "remove-liquidity";
    case TxType::Swap:                return "swap";

    // DEX / Orders
    case TxType::CreateOrder:         return "create-order";
    case TxType::CancelOrder:         return "cancel-order";

    // Token management
    case TxType::CreateToken:         return "create-token";
    case TxType::MintToken:           return "mint-token";
    case TxType::BurnToken:           return "burn-token";
    case TxType::UpdateTokenMeta:     return "update-token-meta";

    // System
    case TxType::BlockReward:         return "block-reward";
    case TxType::OrderExpired:        return "order-expired";
    case TxType::Slash:               return "slash";

    // Sentinels
    case TxType::Invalid:             return "invalid";
  }
  return "unknown";
}

} // namespace Core