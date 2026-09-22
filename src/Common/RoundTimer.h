// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>

namespace Common
{
  inline constexpr uint64_t BASE_TIMEOUT_MS = 5'000;
  inline constexpr uint64_t MAX_TIMEOUT_MS = 60'000;

  // Passive timer. Doesn't own a thread.
  // The event loop polls isExpired() and fires the callback.
  class RoundTimer
  {
  public:
    using Callback = std::function<void()>;

    explicit RoundTimer(Callback on_timeout);

    static uint64_t timeoutForRound(uint32_t round) noexcept;

    void start(uint32_t round);
    void stop();

    bool isRunning() const noexcept;
    bool isExpired() const noexcept;

    // If expired and running, invoke the callback and stop.
    // Returns true if the callback fired.
    bool poll();

    // Force the timer to be considered expired as of "now" for the
    // next poll(). Primarily useful for tests, but harmless in
    // production — nothing else calls it.
    void forceExpire() noexcept;

  private:
    Callback callback_;
    std::chrono::steady_clock::time_point deadline_;
    bool running_{false};
  };

} // namespace Consensus