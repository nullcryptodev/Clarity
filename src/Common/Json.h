#pragma once

#include <nlohmann/json.hpp>

namespace Common
{
  // Alias for convenience
  using Json = nlohmann::json;

  // Convenience functions for Common operations
  inline bool getBoolOrDefault(const Json &j, const std::string &key, bool defaultVal = false)
  {
    if (j.contains(key) && j[key].is_boolean())
    {
      return j[key].get<bool>();
    }
    return defaultVal;
  }

  inline int getIntOrDefault(const Json &j, const std::string &key, int defaultVal = 0)
  {
    if (j.contains(key) && j[key].is_number_integer())
    {
      return j[key].get<int>();
    }
    return defaultVal;
  }

  inline std::string getStringOrDefault(const Json &j, const std::string &key,
                                        const std::string &defaultVal = "")
  {
    if (j.contains(key) && j[key].is_string())
    {
      return j[key].get<std::string>();
    }
    return defaultVal;
  }

  template <typename T>
  inline std::vector<T> getVectorOrDefault(const Json &j, const std::string &key)
  {
    std::vector<T> result;
    if (j.contains(key) && j[key].is_array())
    {
      for (const auto &item : j[key])
      {
        if constexpr (std::is_same_v<T, std::string>)
        {
          if (item.is_string())
            result.push_back(item.get<std::string>());
        }
        else if constexpr (std::is_integral_v<T>)
        {
          if (item.is_number_integer())
            result.push_back(item.get<T>());
        }
        else if constexpr (std::is_floating_point_v<T>)
        {
          if (item.is_number_float())
            result.push_back(item.get<T>());
        }
      }
    }
    return result;
  }

  // Serialization helpers for custom types
  template <typename T>
  Json toJson(const T &obj)
  {
    Json j;
    // Specialize for your types
    return j;
  }

  template <typename T>
  T fromJson(const Json &j)
  {
    T obj;
    // Specialize for your types
    return obj;
  }
}