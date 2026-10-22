#pragma once

#include "Args.h"
#include "Session.h"

#include <string>

namespace Bridge
{
  //  Run the startup wizard. Populates the session's config and
  //  runtime set. (See the .cpp for the full step list.)
  //
  //  Returns false only on explicit user abort (Ctrl+D at a
  //  prompt, or a fatal configuration error).
  bool runStartupWizard(WatcherSession &session, Args &args);

  //  Headless counterparts of the three helpers the wizard uses
  //  internally, exported so Main.cpp can populate the session
  //  from CLI args without re-prompting. Behaviour matches the
  //  wizard exactly.
  std::string expandHome(const std::string &path);

  bool ensureStateRoot(const std::string &path);

  bool ensureChainStateDirs(const WatcherConfig &cfg);

} // namespace Bridge