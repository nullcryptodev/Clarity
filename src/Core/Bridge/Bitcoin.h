// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include "Crypto/Blake2b.h"
#include "Crypto/Types.h"

namespace Core
{
  //  =========================================================================
  //  Bitcoin Bridge
  //
  //  The Bitcoin adapter. Everything the chain-agnostic bridge core needs
  //  to know about Bitcoin, and nothing else. Mirrors ConcealCCX.h in
  //  shape, with Bitcoin's constants and destination codec.
  //
  //  The chain-agnostic core (BridgeTypes, StateAccess,
  //  TransactionExecutor) reads the registration and the wrapped-token
  //  metadata out of state and does not know Bitcoin exists.
  //  =========================================================================

  namespace BitcoinBridge
  {
    //  'BTC1' in ASCII, big-endian.
    inline constexpr uint64_t BTC_CHAIN_ID = 0x42544331ULL;

    //  Bitcoin has one native asset; asset id 1 distinguishes it from
    //  a future asset that isn't the native coin (e.g. a bridged
    //  ERC-20 from a chain that has both).
    inline constexpr uint64_t BTC_NATIVE_ASSET_ID = 1ULL;

    //  Bitcoin has 8 decimals. The wrapped-BTC token on Clarity has
    //  8 decimals too, matching the source. A deposit of `A` satoshis
    //  mints `A` wBTC atomic units: the amount is preserved exactly,
    //  with no scaling factor and no rounding.
    //
    //  (An earlier design used 5 clarity decimals and multiplied by
    //  1000, which produced a display bug — a 0.00165149 BTC deposit
    //  showed as 165149 wBTC instead of 0.00165149. Matching the
    //  source decimals is the fix.)
    //
    //  These constants are exposed so the RPC, the genesis writer,
    //  and the chain-registration UI can display them without
    //  hardcoding the numbers.
    inline constexpr uint8_t BTC_SOURCE_DECIMALS = 8;
    inline constexpr uint8_t BTC_CLARITY_DECIMALS = 8;

    //  Six confirmations is the standard exchange-depth for Bitcoin.
    inline constexpr uint16_t BTC_CONFIRMATION_DEPTH = 6;

    //  Bitcoin destinations are scriptPubKey bytes, variable-length.
    //  The bounds cover P2PKH (25 bytes), P2SH (23), P2WPKH (22),
    //  P2WSH (34), P2TR (34), and multi-sig scripts up to the
    //  MAX_SCRIPT_SIZE cap.
    inline constexpr uint8_t BTC_DESTINATION_MIN_BYTES = 1;
    inline constexpr uint8_t BTC_DESTINATION_MAX_BYTES = 255;

    //  Bitcoin has no fixed "active validator minimum" per the
    //  protocol; the same BFT quorum rule as CCX applies. 2 is the
    //  minimum meaningful federation. (Renamed from
    //  BTC_ACTIVE_WATCHER_MIN; the field on BridgeChainRegistration
    //  is active_validator_min.)
    inline constexpr uint32_t BTC_ACTIVE_VALIDATOR_MIN = 2;

    //  Wrapped-token metadata that BridgeRegisterChain writes into
    //  the new TokenInfo. The executor does not check these (it
    //  checks the fingerprint, which is stricter); they exist so
    //  the registration payload and the RPC display don't hardcode
    //  string literals.
    inline constexpr std::string_view BTC_WRAPPED_NAME = "Wrapped BTC";
    inline constexpr std::string_view BTC_WRAPPED_SYMBOL = "wBTC";
    inline constexpr uint8_t BTC_WRAPPED_DECIMALS = BTC_CLARITY_DECIMALS;

    //  The wrapped-BTC token's fingerprint:
    //
    //    Blake2b("ccw" || LE64(chain_id) || LE64(asset_id))
    //
    //  This is the chain-specific gate. A token with a different
    //  fingerprint (or none) is rejected by the executor on every
    //  mint, burn, and registration. A user-created token called
    //  "wBTC" with a different fingerprint is not the bridged
    //  asset and cannot move bridge value.
    inline Crypto::Hash wrappedTokenFingerprint()
    {
      uint8_t buf[3 + 8 + 8];
      std::memcpy(buf, "ccw", 3);

      uint8_t *p = buf + 3;
      for (int i = 0; i < 8; ++i)
        p[i] = uint8_t(BTC_CHAIN_ID >> (i * 8));
      p += 8;
      for (int i = 0; i < 8; ++i)
        p[i] = uint8_t(BTC_NATIVE_ASSET_ID >> (i * 8));

      Crypto::Hash h;
      Crypto::blake2b(buf, sizeof(buf), h.data.data(), h.data.size());
      return h;
    }

    //  ---------------------------------------------------------------------
    //  Sanity assertions
    //  ---------------------------------------------------------------------
    //
    //  These fire at compile time if a constant is ever changed to a
    //  value that breaks a downstream assumption.

    static_assert(BTC_SOURCE_DECIMALS == BTC_CLARITY_DECIMALS,
                  "BTC and Clarity decimals must match under the "
                  "value-preserving design: a satoshi and a wBTC atomic "
                  "unit are the same number. If a future chain needs "
                  "scaling, that is a different adapter.");
    static_assert(BTC_CONFIRMATION_DEPTH >= 1,
                  "At least one Bitcoin confirmation is required; six "
                  "is the standard exchange depth, but the assert only "
                  "enforces the meaningfulness floor.");
  } // namespace BitcoinBridge
} // namespace Core