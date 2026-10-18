// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"

namespace Bridge
{
  struct ChainWatcherConfig
  {
    std::string chain_short_name;

    std::string rpc_host{"127.0.0.1"};
    uint16_t rpc_port{0};

    std::string rpc_user;
    std::string rpc_password;

    uint16_t confirmation_depth{20};

    std::string state_subdir;

    bool enabled{false};

    //  Opaque deposit-address blob. The adapter defines its shape;
    //  for CCX it's a 64-byte (spend ‖ view) pubkey pair. Populated
    //  by the wizard, or from cmd_start's --bridge-address (which
    //  goes through ChainAdapter::parse_deposit_address). The
    //  chain-agnostic session never inspects its contents.
    std::vector<uint8_t> bridge_deposit_address;
  };

  struct WatcherConfig
  {
    std::string app_name{"clarity-bridge"};

    std::string clarity_rpc_host{"127.0.0.1"};
    uint16_t clarity_rpc_port{9633};

    std::string clarity_rpc_user;
    std::string clarity_rpc_password;

    std::string keystore_path;
    std::string password_file;

    std::string state_dir{"./bridge-state"};

    uint64_t watcher_id{0};

    std::vector<ChainWatcherConfig> chains;

    std::string consensus_key_file;

    std::string view_key_file;

    std::string mint_destination;

    bool needWizard() const noexcept;
  };

} // namespace Bridge