#pragma once

#include "Logging/ILogger.h"

namespace Tests
{
  class NoopLogger : public Logging::ILogger
  {
  public:
    void operator()(const std::string & /*category*/,
                    Logging::Level /*level*/,
                    boost::posix_time::ptime /*time*/,
                    const std::string & /*body*/) override
    {
      // debug logs for testing:
      // std::cerr << level << " - " << body << std::endl;
    }

    Logging::Level getLevel() const override
    {
      return Logging::INFO;
    }
  };
}