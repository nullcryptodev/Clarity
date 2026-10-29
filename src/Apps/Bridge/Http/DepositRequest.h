// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

#include "Session/Session.h"

namespace Bridge
{
  //  The result of a POST /bridge/deposit-address request.
  //
  //  Three statuses, matching the HTTP contract:
  //
  //    "ok"              destination is registered; address and index
  //                      are set, confirmation_depth is the chain's.
  //
  //    "not_registered"  no registration exists for (authority,
  //                      destination). The front end should submit a
  //                      BridgeRegisterDeposit tx and call again.
  //
  //    "pending"         a registration exists in the mempool or in
  //                      a block that hasn't confirmed yet.
  //                      registration_tx is set if we saw the tx in
  //                      the authority's registration list (which
  //                      only shows confirmed registrations, so
  //                      this status is currently only returned when
  //                      an in-flight registration was observed via
  //                      the authority's pending view — see the
  //                      implementation).
  //
  //  error is non-empty only for unexpected failures (unreachable
  //  Clarity, malformed bech32, no custody installed). The handler
  //  maps those to the appropriate HTTP status.
  struct DepositRequestResult
  {
    std::string status;                 // "ok" | "not_registered" | "pending"
    std::string index_hex;              // set iff status == "ok"
    std::string address;                // set iff status == "ok"
    std::string confirmation_depth_hex; // set iff status == "ok"
    std::string registration_tx;        // set iff status == "pending" and we know the txid
    std::string error;                  // set iff unexpected failure
  };

  //  Core logic for the deposit-address endpoint. Looks up
  //  (authority, destination) among the chain's on-chain
  //  registrations, derives the address, returns the result.
  //
  //  Lookup path:
  //
  //    1. Cache: rt.btc_deposit_index_by_authority, keyed by
  //       (authority, destination). Populated by
  //       refreshBridgeDeposits on every scan poll, so it's
  //       fresh within SCAN_POLL_INTERVAL.
  //
  //    2. On cache miss: call getBridgeDepositsForAuthority
  //       directly. That returns the authoritative list
  //       (confirmed registrations). If the destination is
  //       there, add to the cache and return "ok". If not,
  //       return "not_registered".
  //
  //  There is no "pending" path today: getBridgeDepositsForAuthority
  //  only returns confirmed records, so an in-flight registration
  //  is indistinguishable from no registration. The "pending"
  //  status exists so the front end can support it later without
  //  a protocol change; for now it is never returned.
  //
  //  The bridge does not sign anything. The on-chain
  //  BridgeRegisterDeposit tx is the authority's, submitted by
  //  the front end's wallet.
  DepositRequestResult handleDepositRequest(
      WatcherSession &session,
      const std::string &destination_bech32m,
      const std::string &authority_bech32m);
} // namespace Bridge