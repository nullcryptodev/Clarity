// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ConsoleLogger.h"
#include <iostream>
#include <unordered_map>
#include <Common/ConsoleTools.h>

namespace Logging
{
  ConsoleLogger::ConsoleLogger(Level level) : CommonLogger(level)
  {
  }

  void ConsoleLogger::doLogString(const std::string &message)
  {
    std::lock_guard<std::mutex> lock(mutex);
    bool readingText = true;
    bool changedColor = false;
    std::string color = "";

    // Use fully qualified Common::console::Color
    static std::unordered_map<std::string, Common::console::Color> colorMapping = {
        {BLUE, Common::console::Color::Blue},
        {GREEN, Common::console::Color::Green},
        {RED, Common::console::Color::Red},
        {YELLOW, Common::console::Color::Yellow},
        {WHITE, Common::console::Color::White},
        {CYAN, Common::console::Color::Cyan},
        {MAGENTA, Common::console::Color::Magenta},

        {BRIGHT_BLUE, Common::console::Color::BrightBlue},
        {BRIGHT_GREEN, Common::console::Color::BrightGreen},
        {BRIGHT_RED, Common::console::Color::BrightRed},
        {BRIGHT_YELLOW, Common::console::Color::BrightYellow},
        {BRIGHT_WHITE, Common::console::Color::BrightWhite},
        {BRIGHT_CYAN, Common::console::Color::BrightCyan},
        {BRIGHT_MAGENTA, Common::console::Color::BrightMagenta},

        {DEFAULT, Common::console::Color::Default}};

    for (size_t charPos = 0; charPos < message.size(); ++charPos)
    {
      if (message[charPos] == DELIMETER[0])
      {
        readingText = !readingText;
        color += message[charPos];
        if (readingText)
        {
          auto it = colorMapping.find(color);
          // Fully qualify Common::console::Color
          Common::console::setTextColor(it == colorMapping.end() ? Common::console::Color::Default : it->second);
          changedColor = true;
          color.clear();
        }
      }
      else if (readingText)
      {
        std::cout << message[charPos];
      }
      else
      {
        color += message[charPos];
      }
    }

    if (changedColor)
    {
      Common::console::setTextColor(Common::console::Color::Default);
    }

    // Flush after every log message
    std::cout.flush();
  }

} // namespace Logging