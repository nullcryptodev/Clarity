#pragma once

#include "Args.h"
#include "Session/Session.h"

#include <string>

namespace Bridge
{
  //  Run the startup wizard. Populates the session's config and
  //  runtime set. (See the .cpp for the full step list.)
  //
  //  Returns false only on explicit user abort (Ctrl+D at a
  //  prompt, or a fatal configuration error).
  bool runStartupWizard(WatcherSession &session, Args &args);

} // namespace Bridge