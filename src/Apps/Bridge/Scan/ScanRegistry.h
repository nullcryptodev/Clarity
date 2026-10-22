// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

namespace Bridge
{
  class WatcherSession;

  namespace Scan
  {
    //  ---- Scan lifecycle ----
    //
    //  The process-wide handles the scan threads use. They live
    //  in a single registry (a static map in ScanRegistry.cpp)
    //  because the process only ever has one WatcherSession, so
    //  per-session ownership would be a false distinction. Each
    //  entry is one running scan thread, keyed by chain name.
    //
    //  startScan is idempotent: if a thread is already running
    //  for the chain, it returns without starting a second one.
    //  This matches the "start is a no-op if already running"
    //  behaviour the REPL's cmd_start relied on before the split.
    //
    //  stopScan sets the per-chain stop flag and joins the
    //  thread. If no thread is running for the chain, it is a
    //  no-op.
    //
    //  requestStopAllScans sets every stop flag and joins every
    //  thread. Called from cmd_exit and from main()'s clean-
    //  shutdown path. Idempotent: a second call after all threads
    //  have joined does nothing.

    void startScan(WatcherSession &session, const std::string &chain_name);
    void stopScan(const std::string &chain_name);
    void requestStopAllScans();
  } // namespace Scan
} // namespace Bridge