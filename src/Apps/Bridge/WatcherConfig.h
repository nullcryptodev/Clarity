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

    //  ---- Withdrawal release configuration ----
    //
    //  The CCX wallet RPC endpoint used by submit_release. Distinct
    //  from the daemon RPC (which only relays raw transactions);
    //  the wallet RPC holds the custody spend key and can build,
    //  sign, and submit a release.
    //
    //  Empty host means "release not configured" — submit_release
    //  returns ok=false with a clear error, and the withdrawal
    //  scan loop will not launch releases for this chain. That's
    //  the right behavior for a deployment that is deposit-only.
    std::string wallet_rpc_host;
    uint16_t wallet_rpc_port{0};
    std::string wallet_rpc_user;
    std::string wallet_rpc_password;

    //  CCX address network prefix byte. See
    //  CcxAdapter::set_network_prefix for values.
    //
    //  Default: 0x13 (CCX mainnet). Testnets use 0x53.
    //
    //  This is per-chain because different CCX networks have
    //  different prefixes, and a future non-CCX chain adapter
    //  would have its own address scheme entirely (and would
    //  likely ignore this field).
    uint64_t ccx_network_prefix{0x13};

    //  How many Clarity blocks a BridgeBurn must be buried under
    //  before the federation releases the corresponding CCX.
    //  Protects against reorg-driven double-release.
    //
    //  Default: 3, conservative for a BFT-finality chain. A
    //  probabilistic-finality chain would want more.
    uint16_t burn_finality_depth{3};

    //  Base58 form of the deposit address, as the operator
    //  configured it (config file `bridge_address`, or
    //  cmd_start's --bridge-address). Persisted here so a
    //  restarted watcher does not need the flag re-supplied, and
    //  so CcxAdapter::set_custody_address_string has a
    //  source for walletd's sourceAddresses / changeAddress.
    //
    //  May be empty even when bridge_deposit_address is set (the
    //  wizard path populates the blob first). When both are set,
    //  this string is authoritative for walletd operations; the
    //  blob is authoritative for scanning.
    std::string bridge_address;

    //  Hex form of the deposit blob, as an alternate config
    //  source when a base58 address is not available. Parsed into
    //  bridge_deposit_address at config load time. Prefer
    //  bridge_address when both are present.
    std::string destination_blob;
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
  };

} // namespace Bridge