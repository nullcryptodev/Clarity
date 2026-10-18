// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

#include "../ChainAdapter.h"

namespace Bridge
{
  // =========================================================================
  // CcxAdapter
  //
  // The ChainAdapter implementation for Conceal (CCX). Everything
  // the bridge app needs to know about CCX lives here:
  //
  // - the CCX RPC surface: /getinfo and /get_raw_transactions_by_heights
  // are raw HTTP handlers (POST with a plain JSON body, no JSON-RPC
  // envelope); f_block_json, f_transaction_json, getblockcount, and
  // getblockheaderbyheight are JSON-RPC methods (POST to / with the
  // {"jsonrpc":"2.0","method":...,"params":...} envelope). Both
  // shapes are needed, and Wallet::RpcClient only speaks the second.
  // This file therefore contains its own tiny HTTP helpers, one per
  // shape, duplicating ~80 lines of transport code from RpcClient.
  // See the comment above those helpers for the reasoning.
  //
  // - the CCX deposit-detection scheme: CCX has one bridge address
  // (spend + view pubkey), one fixed payment ID (BRIDGE_CCX_PAYMENT_ID),
  // and every deposit is "a transaction paying to the view pubkey
  // with paymentId == BRIDGE_CCX_PAYMENT_ID". The payment ID is
  // the identity; the view key is the filter. There are no
  // per-deposit addresses.
  //
  // - the CCX address codec: an address is a 64-byte blob (spend
  // pubkey || view pubkey), and validation is just "is the length
  // right and are neither key null". No base58, no checksum — the
  // raw pubkey pair is exactly what a CCX transaction output
  // needs, and it's what a BridgeBurn's destination blob carries.
  //
  // - the decimal conversion: CCX has 6 source decimals, the
  // wrapped token on Clarity has 5. The ratio is 10:1, and the
  // rounding is source → clarity = floor, clarity → source = exact.
  // Both conversions are in the header (inline) because they're
  // pure arithmetic.
  //
  // The class is stateless across calls. The only state is one
  // per-chain payment-ID constant, which is a compile-time
  // constant. This means a single CcxAdapter instance can safely
  // serve any number of ChainRuntime objects — v1 runs one, but
  // the design doesn't assume it.
  //
  // The header is deliberately thin: every method is declared here
  // and implemented in the .cpp. The only inline member is the
  // tiny sizeof-style constant helper. Everything nontrivial
  // (HTTP, JSON parsing, payment-ID extraction) lives in the .cpp
  // so the header stays focused on the interface contract.
  // =========================================================================
  class CcxAdapter : public ChainAdapter
  {
  public:
    CcxAdapter() = default;
    ~CcxAdapter() override = default;

    // ---- Identity ----

    std::string name() const override;
    std::string short_name() const override;
    uint64_t source_chain_id() const override;

    // ---- Defaults ----

    std::string default_rpc_endpoint() const override;
    uint16_t default_confirmation_depth() const override;
    uint8_t source_decimals() const override;

    // ---- RPC ----

    bool probe_rpc(Wallet::RpcClient &rpc,
                   std::string *error_out = nullptr) const override;

    ChainStatus fetch_status(Wallet::RpcClient &rpc) const override;

    // Scan blocks [from_height, to_height] on the CCX chain for
    // deposits whose payment ID equals BRIDGE_CCX_PAYMENT_ID.
    //
    // The bridge_view_pubkey parameter is accepted for interface
    // symmetry with other adapters (which may need it to filter by
    // output key), but CCX's scan uses the payment ID exclusively:
    // the payment ID is what the bridge chose when it created the
    // bridge address, so filtering on it is both necessary and
    // sufficient. The pubkey is unused in this adapter.
    //
    // The scan is idempotent: scanning the same range twice yields
    // the same deposits, in the same order.
    void scan_deposits(
        Wallet::RpcClient &rpc,
        const Crypto::PublicKey &bridge_view_pubkey,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const override;

    // Build and submit a CCX transaction that releases the given
    // withdrawal amount to the destination blob's address.
    //
    // The signature_block argument is the CCX-format signature
    // block the signing service produced. This adapter does NOT
    // sign — signing is out of scope for v1 (see the note in the
    // design docs; the signing service is a separate process).
    //
    // The submission path is conceald's raw /sendrawtransaction
    // handler: POST {"tx_as_hex": "..."} to /sendrawtransaction.
    ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const override;

    // ---- Conversion ----

    uint64_t to_clarity_atomic(uint64_t amount_source_atomic,
                               uint8_t clarity_decimals) const override;

    uint64_t to_source_atomic(uint64_t amount_clarity_atomic,
                              uint8_t clarity_decimals) const override;

    // ---- Destination validation ----

    bool validate_destination(
        const std::vector<uint8_t> &destination_blob) const override;
  };

} // namespace Bridge