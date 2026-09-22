// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Types.h"

namespace Consensus
{

  const char *stepName(Step s) noexcept
  {
    switch (s)
    {
    case Step::NewHeight:
      return "new-height";
    case Step::Propose:
      return "propose";
    case Step::Prevote:
      return "prevote";
    case Step::Precommit:
      return "precommit";
    case Step::Commit:
      return "commit";
    }
    return "unknown";
  }

} // namespace Consensus