#pragma once

#include "Logging/ILogger.h"

#include <iostream>

namespace Tests
{
  //  NoopLogger
  //
  //  Truly silent. Every log call is discarded. This is the default
  //  test logger; using it keeps test output readable and keeps the
  //  test suite from serializing on a shared std::cerr across
  //  multiple threads.
  class NoopLogger : public Logging::ILogger
  {
  public:
    void operator()(const std::string & /*category*/,
                    Logging::Level /*level*/,
                    boost::posix_time::ptime /*time*/,
                    const std::string & /*body*/) override
    {
      // Intentionally silent. See StdErrLogger for a variant that
      // prints, and the comment on Logging::ILogger for the interface
      // contract.
    }

    Logging::Level getLevel() const override
    {
      return Logging::INFO;
    }
  };

  //  StdErrLogger
  //
  //  Prints every log line to std::cerr with a level prefix. Used
  //  when debugging a specific test and the log output is what you
  //  need to see. Not the default: a test suite with 1500 tests and
  //  a network of nodes generates enormous output, most of it noise.
  //
  //  To use it in a specific test, construct one locally and pass it
  //  to the constructor of the thing under test:
  //
  //    StdErrLogger verbose;
  //    Node::Node node(cfg, verbose);
  //
  //  The fixture's default logger_ is a NoopLogger; a test that wants
  //  verbose output overrides it for its own scope.
  class StdErrLogger : public Logging::ILogger
  {
  public:
    explicit StdErrLogger(Logging::Level min_level = Logging::DEBUGGING)
        : min_level_(min_level)
    {
    }

    void operator()(const std::string &category,
                    Logging::Level level,
                    boost::posix_time::ptime /*time*/,
                    const std::string &body) override
    {
      if (level < min_level_)
        return;
      std::cerr << "[" << category << "] " << level << " - " << body << "\n";
    }

    Logging::Level getLevel() const override
    {
      return min_level_;
    }

  private:
    Logging::Level min_level_;
  };
}