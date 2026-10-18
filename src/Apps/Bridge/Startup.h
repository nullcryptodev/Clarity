// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Args.h"
#include "Session.h"

namespace Bridge
{
  //  Run the startup wizard. Populates the session's config and
  //  runtime set.
  //
  //  What the wizard does:
  //
  //    1. Probes the Clarity node; retries, or offers a different
  //       endpoint, or continues offline.
  //
  //    2. Lists the chain adapters compiled into the binary. If
  //       the CLI already enabled a subset via --chain, those are
  //       pre-selected; otherwise the operator picks one or more.
  //
  //    3. For each enabled chain, ensures the per-chain config is
  //       complete (RPC endpoint, confirmation depth) — using the
  //       CLI override if given, otherwise prompting.
  //
  //    4. Probes each enabled chain's source-chain RPC.
  //
  //    5. Opens the keystore (used across all chains), or asks
  //       whether to continue offline.
  //
  //    6. Resolves the watcher id from the keystore, or prompts
  //       for it if the operator supplied one on the CLI.
  //
  //    7. Prints a summary banner listing the enabled chains and
  //       their endpoints.
  //
  //  Returns false only on explicit user abort (Ctrl+D at a
  //  prompt, or a fatal configuration error).
  bool runStartupWizard(WatcherSession &session, Args &args);

} // namespace Bridge