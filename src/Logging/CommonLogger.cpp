// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "CommonLogger.h"
#include "Types.h"

namespace Logging
{
  void CommonLogger::operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body)
  {
    if (level <= logLevel && disabledCategories.count(category) == 0)
    {
      std::string messageBody = body;

      if (!body.empty() && body[0] == DELIMETER[0])
      {
        size_t delimEnd = body.find(DELIMETER, 1);
        if (delimEnd != std::string::npos)
        {
          // Skip the color code
          messageBody = body.substr(delimEnd + 1);
        }
      }

      std::string levelColor = levelToColor(level);
      std::string levelName = LEVEL_NAMES[level];

      // Format: <levelColor>[LEVEL]<DEFAULT> message
      std::string output = levelColor + "[" + levelName + "]" + DEFAULT + " " + messageBody;

      doLogString(output);
    }
  }

  void CommonLogger::setPattern(const std::string &pattern)
  {
    this->pattern = pattern;
  }

  void CommonLogger::enableCategory(const std::string &category)
  {
    disabledCategories.erase(category);
  }

  void CommonLogger::disableCategory(const std::string &category)
  {
    disabledCategories.insert(category);
  }

  void CommonLogger::setMaxLevel(Level level)
  {
    logLevel = level;
  }

  CommonLogger::CommonLogger(Level level) : logLevel(level), pattern("")
  {
    // Pattern is empty by default — we build the prefix manually
  }

  void CommonLogger::doLogString(const std::string &message)
  {
    // Base class does nothing
  }

} // namespace Logging