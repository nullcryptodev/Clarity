// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Bridge
{
  //  Per-chain watcher configuration. One of these exists for
  //  every enabled chain. The wizard populates it; the CLI can
  //  populate it; the app never constructs it from scratch after
  //  startup.
  struct ChainWatcherConfig
  {
    //  Which adapter this is for (short_name from the adapter).
    std::string chain_short_name;

    //  RPC endpoint of the source chain's daemon.
    std::string rpc_host{"127.0.0.1"};
    uint16_t rpc_port{0};

    //  How deep to require the source chain to be before a
    //  deposit is minted. The on-chain registration's value is
    //  the protocol minimum; the operator may raise it. It may
    //  not be lowered at this level.
    uint16_t confirmation_depth{20};

    //  Directory for this chain's watcher state. Filled by the
    //  app from `<state_dir>/<chain_short_name>/`.
    std::string state_subdir;

    //  True if the operator enabled this chain. The wizard sets
    //  this based on the operator's choice; the CLI sets it based
    //  on which `--chain <name>` flags were supplied.
    bool enabled{false};
  };

  //  Global bridge app configuration. Shared across every chain
  //  the app runs.
  struct WatcherConfig
  {
    //  App identity.
    std::string app_name{"clarity-bridge"};

    //  Clarity node RPC. One per app, not per chain: every
    //  watcher talks to the same Clarity node.
    std::string clarity_rpc_host{"127.0.0.1"};
    uint16_t clarity_rpc_port{9633};

    //  Keystore, shared across every chain. The operator's
    //  identity on Clarity is one address; each chain's watcher
    //  registration references the same address.
    std::string keystore_path;
    std::string password_file;

    //  Root state directory. Per-chain state goes under
    //  `<state_dir>/<chain_short_name>/`.
    std::string state_dir{"./bridge-state"};

    //  Watcher id on Clarity. May be zero until resolved from
    //  the keystore at startup.
    uint64_t watcher_id{0};

    //  Per-chain configs, one for each adapter that's enabled.
    //  Populated by the wizard or the CLI.
    std::vector<ChainWatcherConfig> chains;

    //  True if the wizard should run. False only when the CLI
    //  supplied every field needed for every enabled chain.
    bool needWizard() const noexcept;
  };

} // namespace Bridge