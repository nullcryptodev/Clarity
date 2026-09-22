// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

namespace Core
{
  //  Reward System Constants
  //
  //  All values are protocol constants. Changing them requires a hard fork.
  //  Governance parameters (which can change via vote) are marked "gov".
  //
  // ---- Validator rotation ----

  inline constexpr uint64_t ROTATION_INTERVAL = 60;      // blocks per epoch
  inline constexpr uint64_t TARGET_ROTATION_EPOCHS = 21; // full set turns over
  inline constexpr uint64_t ACTIVE_SET_MIN = 11;         // BFT minimum (7 of 11)
  inline constexpr uint64_t ACTIVE_SET_MAX = 100;        // BFT ceiling
  inline constexpr uint64_t ACTIVE_SET_DEFAULT = 21;
  inline constexpr uint64_t SEED_NODES = 2; // always active

  static_assert(ACTIVE_SET_MIN >= 4,
                "BFT needs at least 4 validators");
  static_assert(ACTIVE_SET_MIN <= ACTIVE_SET_DEFAULT,
                "Default must be >= minimum");
  static_assert(ACTIVE_SET_DEFAULT <= ACTIVE_SET_MAX,
                "Default must be <= maximum");
  static_assert(SEED_NODES <= ACTIVE_SET_MIN,
                "Seeds must fit within the minimum active set");

  // BFT quorum: 2n/3 + 1
  constexpr uint64_t bftQuorum(uint64_t n) noexcept
  {
    return (n * 2) / 3 + 1;
  }

  // ---- Active set sizing (traffic-responsive) ----

  // How often the active set size is reconsidered.
  inline constexpr uint64_t ACTIVE_SET_UPDATE_INTERVAL = 600; // blocks (~10 min)

  // Traffic metric smoothing factor (EMA). 2000 bps = 20%.
  inline constexpr uint16_t TRAFFIC_EMA_ALPHA_BPS = 2000;

  // Target transaction count per block at which the active set reaches MAX.
  inline constexpr uint64_t TRAFFIC_SATURATION_TX = 1000;

  // ---- Staker APY (basis points) ----

  inline constexpr uint16_t APY_BASE_BPS = 500;          // 5.00% (gov)
  inline constexpr uint16_t APY_ACTIVITY_MAX_BPS = 500;  // +5.00% max
  inline constexpr uint16_t APY_POT_BONUS_MAX_BPS = 300; // +3.00% max

  // Balance bonus: stakers holding >= threshold get +3% weight
  inline constexpr uint16_t BALANCE_BONUS_BPS = 300;                        // 3.00%
  inline constexpr uint64_t BALANCE_BONUS_THRESHOLD = 1000ULL * 100'000ULL; // 1000 CLRTY

  // ---- Staking thresholds ----

  inline constexpr uint64_t AUTO_STAKE_THRESHOLD = 100ULL * 100'000ULL; // 100 CLRTY
  inline constexpr uint64_t VALIDATOR_MIN_STAKE = 1000ULL * 100'000ULL; // 1000 CLRTY

  // ---- Uptime scoring ----

  // Validators with uptime below this are removed from the pool.
  inline constexpr uint16_t UPTIME_REMOVAL_THRESHOLD_BPS = 2500; // 25%

  // Validators with uptime below this are removed from the active set
  // (but stay in the pool).
  inline constexpr uint16_t UPTIME_ACTIVE_MIN_BPS = 9000; // 90%

  // EMA smoothing factor for uptime scoring.
  inline constexpr uint16_t UPTIME_EMA_ALPHA_BPS = 2000; // 20%

  // ---- Timing ----

  // Assumed wall-clock duration of one block, in seconds. Used only by
  // the reward formula to convert "blocks per epoch" into "seconds per
  // epoch" for the APY target calculation. It is a *modelling* parameter,
  // not a consensus rule: the actual block interval may drift and the
  // pot absorbs the difference. The value is chosen to match the design
  // discussion's 1-second-block assumption.
  inline constexpr uint64_t NOMINAL_BLOCK_SECONDS = 1;

  inline constexpr uint64_t SECONDS_PER_EPOCH =
      ROTATION_INTERVAL * NOMINAL_BLOCK_SECONDS;

  // ---- Pot mechanics ----
  //
  // The pot holds staker rewards that couldn't be distributed because
  // the total staked amount was too small to absorb the target payout.
  // Thresholds are expressed as a number of epochs' worth of the
  // per-epoch staker pool:
  //
  //   POT_LOW  = 1 week  of undistributed rewards
  //   POT_HIGH = 1 month — pot bonus APY kicks in above this
  //   POT_MAX  = 3 months — excess is burned above this
  //
  // Computed from SECONDS_PER_EPOCH so they scale with the block-time
  // assumption. Note that POT_MAX is intentionally large — on a chain
  // with low staked value, it may never be reached. Tests that need to
  // exercise the burn or bonus paths set the pot directly rather than
  // waiting for it to accumulate.

  inline constexpr uint64_t POT_LOW_EPOCHS =
      (7ULL * 24ULL * 3600ULL) / SECONDS_PER_EPOCH;

  inline constexpr uint64_t POT_HIGH_EPOCHS =
      (30ULL * 24ULL * 3600ULL) / SECONDS_PER_EPOCH;

  inline constexpr uint64_t POT_MAX_EPOCHS =
      (90ULL * 24ULL * 3600ULL) / SECONDS_PER_EPOCH;

  static_assert(POT_LOW_EPOCHS < POT_HIGH_EPOCHS,
                "POT_LOW must be < POT_HIGH");
  static_assert(POT_HIGH_EPOCHS < POT_MAX_EPOCHS,
                "POT_HIGH must be < POT_MAX");

  // ---- Utility: percentage extraction ----

  // Extract `bps`/10000 of `value`. Rounds down. Overflow-safe.
  inline uint64_t applyBps(uint64_t value, uint16_t bps) noexcept
  {
    // Split to avoid overflow: value * bps can be up to 2^64 * 10000.
    // Do the multiplication in 128-bit space.
    __uint128_t tmp = static_cast<__uint128_t>(value) * bps;
    return static_cast<uint64_t>(tmp / 10'000);
  }

  // Extract the part of `value` corresponding to `bps` out of 10000,
  // rounding to nearest.
  inline uint64_t applyBpsRound(uint64_t value, uint16_t bps) noexcept
  {
    __uint128_t tmp = static_cast<__uint128_t>(value) * bps;
    tmp += 5'000;
    return static_cast<uint64_t>(tmp / 10'000);
  }

  // ---- Offline detection ----

  // How often we check the active set for offline validators.
  // Runs on blocks where (height + 1) % OFFLINE_CHECK_INTERVAL == 0.
  inline constexpr uint64_t OFFLINE_CHECK_INTERVAL = 10;

  // Number of consecutive blocks offline before a validator is removed.
  // Provides a grace period for transient network blips.
  inline constexpr uint64_t OFFLINE_KICK_BLOCKS = 20;

  // ---- Chain halt ----

  // If the live (non-offline) active set drops below this, consensus
  // cannot proceed. The chain halts and logs a critical error.
  inline constexpr size_t MIN_LIVE_VALIDATORS = 4;

  // ---- Slashing (reward multiplier) ----

  // Every validator starts at 100% of their earned reward.
  // Each proven infraction reduces the multiplier by REWARD_MULTIPLIER_PENALTY.
  // The multiplier never goes below REWARD_MULTIPLIER_FLOOR.
  // There is no automatic recovery.
  inline constexpr uint16_t REWARD_MULTIPLIER_START = 10'000;
  inline constexpr uint16_t REWARD_MULTIPLIER_FLOOR = 2'000;
  inline constexpr uint16_t REWARD_MULTIPLIER_PENALTY = 2'000;

  static_assert(REWARD_MULTIPLIER_START > REWARD_MULTIPLIER_FLOOR,
                "Start must be above floor");
  static_assert(REWARD_MULTIPLIER_PENALTY > 0,
                "Penalty must be positive");

} // namespace Core