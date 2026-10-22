// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Common/Json.h"
#include "Crypto/Types.h"

namespace Bridge
{
  struct ChainWatcherConfig
  {
    std::string chain_short_name;
    bool enabled{false};

    //  Source-chain daemon RPC (bitcoind, conceal daemon, etc.).
    std::string rpc_host;
    uint16_t rpc_port{0};
    std::string rpc_user;
    std::string rpc_password;

    //  Source-chain confirmation depth for deposits.
    uint16_t confirmation_depth{0};

    //  Per-chain state directory (relative to WatcherConfig::state_dir).
    std::string state_subdir;

    //  Source-chain custody / deposit address, as a display string.
    std::string bridge_address;

    //  Source-chain custody / deposit address, as the opaque blob.
    std::vector<uint8_t> bridge_deposit_address;

    //  Source-chain wallet RPC.
    std::string wallet_rpc_host;
    uint16_t wallet_rpc_port{0};
    std::string wallet_rpc_user;
    std::string wallet_rpc_password;

    //  CCX-specific.
    uint64_t ccx_network_prefix{0x13};

    //  Clarity blocks a BridgeBurn must be buried under before release.
    uint16_t burn_finality_depth{3};

    //  The full `chains[]` entry as parsed, carried so an adapter
    //  can interpret transport-specific fields without the struct
    //  growing a field per transport.
    Common::Json raw_json;

    uint64_t start_height{0};
  };

  struct WatcherConfig
  {
    std::string app_name;
    std::string clarity_rpc_host;
    uint16_t clarity_rpc_port{0};
    std::string clarity_rpc_user;
    std::string clarity_rpc_password;

    std::string keystore_path;
    std::string password_file;
    std::string consensus_key_file;
    std::string view_key_file;

    std::string mint_destination;

    std::string state_dir;

    bool no_wizard{false};
    std::string log_level{"info"};

    std::vector<ChainWatcherConfig> chains;

    uint64_t start_height{0};
  };
} // namespace Bridge