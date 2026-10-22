// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <vector>

#include "../Adapters/ChainAdapter.h"

#include "Common/Json.h"
#include "WatcherConfig.h"

namespace Bridge
{
  struct Args; // forward decl; BridgeConfig::load takes Args&

  //  Config-file loader. Populates args.config directly rather
  //  than returning a WatcherConfig, which matches the "CLI flags
  //  override config values" flow in Args.cpp: the config is
  //  loaded first, then parseArgs's pass-2 loop applies CLI flags
  //  on top of it. Throws std::runtime_error on a missing file,
  //  malformed JSON, or a required field with the wrong type.
  namespace BridgeConfig
  {
    void load(const std::string &path, Args &args);
  }

  //  Create the top-level state directory if it doesn't exist.
  bool ensureStateRoot(const std::string &path);

  //  Create one subdirectory per enabled chain under
  //  WatcherConfig::state_dir.
  bool ensureChainStateDirs(const WatcherConfig &cfg);

  //  Expand a leading "~" to $HOME.
  std::string expandHome(const std::string &path);

  //  Fill in an adapter's per-chain defaults (RPC endpoint,
  //  confirmation depth) from the adapter itself.
  void applyAdapterDefaults(const ChainAdapter &adapter,
                            ChainWatcherConfig &cfg);

} // namespace Bridge