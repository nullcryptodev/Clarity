// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Signals.h"

namespace Bridge
{
  volatile std::sig_atomic_t g_stop_requested = 0;

  namespace
  {
    void handleStopSignal(int /*sig*/)
    {
      //  Async-signal-safe: assigning to a sig_atomic_t is the
      //  only operation permitted here. Any cleanup happens in
      //  the main thread after it observes the flag.
      g_stop_requested = 1;
    }
  } // anonymous namespace

  void installStopSignalHandlers()
  {
    std::signal(SIGINT, handleStopSignal);
    std::signal(SIGTERM, handleStopSignal);
  }

  void clearStopSignal()
  {
    g_stop_requested = 0;
  }
} // namespace Bridge