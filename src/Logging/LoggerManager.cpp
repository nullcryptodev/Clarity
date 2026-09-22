// Copyright (c) 2011-2017 The Cryptonote developers
// Copyright (c) 2017-2018 The Circle Foundation & Conceal Devs
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "LoggerManager.h"
#include <thread>
#include "ConsoleLogger.h"
#include "FileLogger.h"
#include "Types.h"

namespace Logging
{

  using Common::Json;

  LoggerManager::LoggerManager()
  {
  }

  void LoggerManager::operator()(const std::string &category, Level level, boost::posix_time::ptime time, const std::string &body)
  {
    std::unique_lock<std::mutex> lock(reconfigureLock);
    LoggerGroup::operator()(category, level, time, body);
  }

  void LoggerManager::configure(const Json &val)
  {
    std::unique_lock<std::mutex> lock(reconfigureLock);
    loggers.clear();
    LoggerGroup::loggers.clear();

    Level globalLevel;
    if (val.contains("globalLevel"))
    {
      auto &levelVal = val["globalLevel"];
      if (levelVal.is_number_integer())
      {
        globalLevel = static_cast<Level>(levelVal.get<int>());
      }
      else
      {
        throw std::runtime_error("parameter globalLevel has wrong type");
      }
    }
    else
    {
      globalLevel = INFO;
    }

    std::vector<std::string> globalDisabledCategories;

    if (val.contains("globalDisabledCategories"))
    {
      auto &globalDisabledCategoriesList = val["globalDisabledCategories"];
      if (globalDisabledCategoriesList.is_array())
      {
        for (const auto &categoryVal : globalDisabledCategoriesList)
        {
          if (categoryVal.is_string())
          {
            globalDisabledCategories.push_back(categoryVal.get<std::string>());
          }
        }
      }
      else
      {
        throw std::runtime_error("parameter globalDisabledCategories has wrong type");
      }
    }

    if (val.contains("loggers"))
    {
      auto &loggersList = val["loggers"];
      if (loggersList.is_array())
      {
        for (const auto &loggerConfiguration : loggersList)
        {
          if (!loggerConfiguration.is_object())
          {
            throw std::runtime_error("loggers element must be objects");
          }

          Level level = INFO;
          if (loggerConfiguration.contains("level"))
          {
            level = static_cast<Level>(loggerConfiguration["level"].get<int>());
          }

          std::string type = loggerConfiguration["type"].get<std::string>();
          std::unique_ptr<Logging::CommonLogger> logger;

          if (type == "console")
          {
            logger.reset(new ConsoleLogger(level));
          }
          else if (type == "file")
          {
            std::string filename = loggerConfiguration["filename"].get<std::string>();
            auto fileLogger = new FileLogger(level);
            fileLogger->init(filename);
            logger.reset(fileLogger);
          }
          else
          {
            throw std::runtime_error("Unknown logger type: " + type);
          }

          if (loggerConfiguration.contains("pattern"))
          {
            logger->setPattern(loggerConfiguration["pattern"].get<std::string>());
          }

          std::vector<std::string> disabledCategories;
          if (loggerConfiguration.contains("disabledCategories"))
          {
            auto &disabledCategoriesVal = loggerConfiguration["disabledCategories"];
            for (const auto &categoryVal : disabledCategoriesVal)
            {
              if (categoryVal.is_string())
              {
                logger->disableCategory(categoryVal.get<std::string>());
              }
            }
          }

          loggers.emplace_back(std::move(logger));
          addLogger(*loggers.back());
        }
      }
      else
      {
        throw std::runtime_error("loggers parameter has wrong type");
      }
    }
    else
    {
      throw std::runtime_error("loggers parameter missing");
    }

    setMaxLevel(globalLevel);
    for (const auto &category : globalDisabledCategories)
    {
      disableCategory(category);
    }
  }

  void LoggerManager::flush()
  {
    std::lock_guard<std::mutex> lock(reconfigureLock);
    for (auto &logger : loggers)
    {
      // Cast to ConsoleLogger and flush if possible
      auto *consoleLogger = dynamic_cast<ConsoleLogger *>(logger.get());
      if (consoleLogger)
      {
        consoleLogger->flush();
      }
    }
  }
}