// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chrono>
#include <cstdint>

namespace Common
{
  // Token-bucket rate limiter.
  //
  // One bucket holds up to `burst` tokens. Tokens refill continuously at
  // `refillPerSecond`. `tryConsume(n)` succeeds if n tokens are available,
  // deducts them, and returns true; otherwise it leaves the bucket
  // unchanged and returns false.
  //
  // The bucket is NOT thread-safe. Each instance is owned by a single
  // logical actor:
  //   - In P2P, one bucket per Peer, touched only from that peer's asio
  //     strand (all Peer callbacks run on the same strand).
  //   - In RPC, one bucket per source IP, touched only from the worker
  //     thread handling that connection (or guarded by a mutex if a
  //     future change shares buckets across workers).
  //
  // Construction with burst == 0 or refillPerSecond == 0 disables the
  // bucket: tryConsume always returns true. This matches the RPC config
  // convention ("both zero = disabled").
  class RateLimiter
  {
  public:
    using Clock = std::chrono::steady_clock;

    RateLimiter() = default;

    RateLimiter(uint32_t burst, uint32_t refillPerSecond)
        : burst_(burst),
          refillPerSecond_(refillPerSecond),
          tokens_(burst),
          lastRefill_(Clock::now()),
          enabled_(burst != 0 && refillPerSecond != 0)
    {
    }

    // Returns true and deducts n tokens if n are available. Returns
    // false and leaves the bucket unchanged otherwise. Always returns
    // true when the bucket is disabled.
    bool tryConsume(uint32_t n = 1)
    {
      if (!enabled_)
        return true;

      refill();

      if (tokens_ >= n)
      {
        tokens_ -= n;
        return true;
      }
      return false;
    }

    // Tokens currently available, after refilling to now. For
    // introspection / tests only.
    uint32_t available()
    {
      if (!enabled_)
        return burst_;
      refill();
      return tokens_;
    }

    bool enabled() const noexcept { return enabled_; }
    uint32_t burst() const noexcept { return burst_; }
    uint32_t refillPerSecond() const noexcept { return refillPerSecond_; }

  private:
    void refill()
    {
      const auto now = Clock::now();
      const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                               now - lastRefill_)
                               .count();
      if (elapsed <= 0)
        return;

      lastRefill_ = now;

      // Accumulate fractional tokens in micro-units to avoid losing
      // refill on sub-second intervals. refillPerSecond_ is small
      // (< 2^32); elapsed is microseconds; the product fits in uint64.
      const uint64_t gainedMicro =
          static_cast<uint64_t>(refillPerSecond_) * static_cast<uint64_t>(elapsed);

      microTokens_ += gainedMicro;

      // 1 token == 1'000'000 micro-tokens.
      const uint64_t whole = microTokens_ / 1'000'000ULL;
      if (whole == 0)
        return;

      microTokens_ -= whole * 1'000'000ULL;

      const uint64_t capped = static_cast<uint64_t>(tokens_) + whole;
      tokens_ = static_cast<uint32_t>(capped > burst_ ? burst_ : capped);
    }

    uint32_t burst_ = 0;
    uint32_t refillPerSecond_ = 0;
    uint32_t tokens_ = 0;
    uint64_t microTokens_ = 0;
    Clock::time_point lastRefill_{};
    bool enabled_ = false;
  };

} // namespace Common