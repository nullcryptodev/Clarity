// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "LoggerRef.h"

namespace Logging {

LoggerRef::LoggerRef(ILogger& logger, const std::string& category) : logger(&logger), category(category) {
}

LoggerMessage LoggerRef::operator()(Level level, const std::string &color) const
{
  // If caller didn't pass a color, compute it from the level
  const std::string &actualColor = color.empty() ? levelToColor(level) : color;
  return LoggerMessage(*logger, category, level, actualColor);
}

ILogger& LoggerRef::getLogger() const {
  return *logger;
}

Level LoggerRef::getLevel() const
{
  return logger->getLevel();
}
}
