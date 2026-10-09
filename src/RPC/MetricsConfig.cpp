// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "MetricsConfig.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdexcept>

namespace Rpc
{

  namespace
  {
    bool isValidBindAddress(const std::string &addr)
    {
      if (addr.empty())
        return false;

      unsigned char buf[sizeof(struct in6_addr)];
      if (inet_pton(AF_INET, addr.c_str(), buf) == 1)
        return true;
      if (inet_pton(AF_INET6, addr.c_str(), buf) == 1)
        return true;
      return false;
    }
  } // anonymous namespace

  void validateMetricsConfig(const MetricsConfig &config)
  {
    if (!config.enabled)
      return;

    if (!isValidBindAddress(config.bind_address))
    {
      throw std::runtime_error(
          "metrics: bind_address '" + config.bind_address +
          "' is not a valid IPv4 or IPv6 address");
    }

    if (config.port == 0)
    {
      throw std::runtime_error("metrics: port must be non-zero");
    }

    if (config.worker_threads == 0)
    {
      throw std::runtime_error("metrics: worker_threads must be > 0");
    }

    if (config.worker_threads > 16)
    {
      throw std::runtime_error(
          "metrics: worker_threads above 16 is not supported");
    }

    if (config.max_queued_connections == 0)
    {
      throw std::runtime_error(
          "metrics: max_queued_connections must be > 0");
    }

    if (config.max_request_bytes < 1024)
    {
      throw std::runtime_error(
          "metrics: max_request_bytes must be at least 1024");
    }

    if (config.max_request_bytes > 1024 * 1024)
    {
      throw std::runtime_error(
          "metrics: max_request_bytes above 1 MiB is not supported");
    }

    if (config.socket_timeout_seconds == 0)
    {
      throw std::runtime_error(
          "metrics: socket_timeout_seconds must be > 0");
    }

    // Rate limiter convention: both zero (disabled) or both non-zero.
    const bool burst_off = (config.rate_limit_burst == 0);
    const bool rate_off = (config.rate_limit_per_second == 0);
    if (burst_off != rate_off)
    {
      throw std::runtime_error(
          "metrics: rate_limit_burst and rate_limit_per_second must both "
          "be zero (disabled) or both be non-zero (enabled)");
    }

    if (!rate_off && config.rate_limit_burst < config.rate_limit_per_second)
    {
      throw std::runtime_error(
          "metrics: rate_limit_burst must be >= rate_limit_per_second");
    }
  }

} // namespace Rpc