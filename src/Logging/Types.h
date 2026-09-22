#pragma once

#include <string>
#include <array>

namespace Logging
{
  inline constexpr const char *DEFAULT = "\x1F""DEFAULT\x1F";
  inline constexpr const char *BLUE = "\x1F""BLUE\x1F";
  inline constexpr const char *GREEN = "\x1F""GREEN\x1F";
  inline constexpr const char *RED = "\x1F""RED\x1F";
  inline constexpr const char *YELLOW = "\x1F""YELLOW\x1F";
  inline constexpr const char *WHITE = "\x1F""WHITE\x1F";
  inline constexpr const char *CYAN = "\x1F""CYAN\x1F";
  inline constexpr const char *MAGENTA = "\x1F""MAGENTA\x1F";

  inline constexpr const char *BRIGHT_BLUE = "\x1F""BRIGHT_BLUE\x1F";
  inline constexpr const char *BRIGHT_GREEN = "\x1F""BRIGHT_GREEN\x1F";
  inline constexpr const char *BRIGHT_RED = "\x1F""BRIGHT_RED\x1F";
  inline constexpr const char *BRIGHT_YELLOW = "\x1F""BRIGHT_YELLOW\x1F";
  inline constexpr const char *BRIGHT_WHITE = "\x1F""BRIGHT_WHITE\x1F";
  inline constexpr const char *BRIGHT_CYAN = "\x1F""BRIGHT_CYAN\x1F";
  inline constexpr const char *BRIGHT_MAGENTA = "\x1F""BRIGHT_MAGENTA\x1F";

  inline constexpr const char *DELIMETER = "\x1F";

  enum Level : uint8_t
  {
    ERROR = 0,
    WARNING = 1,
    INFO = 2,
    DEBUGGING = 3
  };

  // Level names — keep in sync with enum
  const std::array<std::string, 4> LEVEL_NAMES = {
      "ERROR",
      "WARNING",
      "INFO",
      "DEBUGGING"
  };

  // Helper: Convert level to string
  inline std::string levelToString(Level level)
  {
    if (static_cast<size_t>(level) < LEVEL_NAMES.size())
    {
      return LEVEL_NAMES[static_cast<size_t>(level)];
    }
    return "UNKNOWN";
  }

  // Helper: Get color for level
  inline const char *levelToColor(Level level)
  {
    switch (level)
    {
    case ERROR:
      return BRIGHT_RED;
    case WARNING:
      return BRIGHT_YELLOW;
    case INFO:
      return BRIGHT_MAGENTA;
    case DEBUGGING:
      return BRIGHT_CYAN;
    default:
      return DEFAULT;
    }
  }

} // namespace Logging