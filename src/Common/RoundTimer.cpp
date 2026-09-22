// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RoundTimer.h"

namespace Common
{

  RoundTimer::RoundTimer(Callback cb)
      : callback_(std::move(cb))
  {
  }

  uint64_t RoundTimer::timeoutForRound(uint32_t round) noexcept
  {
    uint64_t timeout = BASE_TIMEOUT_MS * (static_cast<uint64_t>(round) + 1);
    return timeout > MAX_TIMEOUT_MS ? MAX_TIMEOUT_MS : timeout;
  }

  void RoundTimer::start(uint32_t round)
  {
    deadline_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutForRound(round));
    running_ = true;
  }

  void RoundTimer::stop()
  {
    running_ = false;
  }

  bool RoundTimer::isRunning() const noexcept
  {
    return running_;
  }

  bool RoundTimer::isExpired() const noexcept
  {
    if (!running_)
      return false;
    return std::chrono::steady_clock::now() >= deadline_;
  }

  bool RoundTimer::poll()
  {
    if (!running_)
      return false;
    if (std::chrono::steady_clock::now() < deadline_)
      return false;

    running_ = false;
    if (callback_)
      callback_();
    return true;
  }

  void RoundTimer::forceExpire() noexcept
  {
    deadline_ = std::chrono::steady_clock::now();
  }

} // namespace Consensus