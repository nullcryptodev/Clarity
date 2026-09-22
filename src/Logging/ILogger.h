#pragma once

#include <string>
#include <array>
#include <boost/date_time/posix_time/posix_time.hpp>

#include "Types.h"

#undef ERROR

namespace Logging
{
  class ILogger
  {
  public:
    virtual void operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body) = 0;

    virtual Level getLevel() const = 0;
  };
} // namespace Logging