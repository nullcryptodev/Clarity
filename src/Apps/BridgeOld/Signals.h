// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <csignal>

namespace Bridge
{
  //  Foreground-service stop flag. SIGINT/SIGTERM set it; the
  //  service loop in main() polls it and breaks cleanly when it
  //  flips.
  //
  //  Why a plain sig_atomic_t and not std::atomic<bool>: the
  //  signal handler runs asynchronously and may only touch
  //  async-signal-safe state. sig_atomic_t is the standard
  //  primitive for "a flag a signal handler can set". The
  //  writer (handler) only ever does `= 1`; the reader (main
  //  loop) does `!= 0`, which is atomic in practice on every
  //  platform this codebase targets.
  extern volatile std::sig_atomic_t g_stop_requested;

  //  Install SIGINT and SIGTERM handlers that set g_stop_requested.
  //  Idempotent — calling twice re-installs the same handlers.
  void installStopSignalHandlers();

  //  Reset the flag. Useful in tests and in the REPL path so a
  //  stale flag from a previous phase can't wedge a fresh session.
  void clearStopSignal();
} // namespace Bridge