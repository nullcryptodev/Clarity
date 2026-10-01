// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include "Core/Transaction.h"
#include "Crypto/Types.h"
#include "RpcClient.h"

namespace Wallet
{
  //  WalletOperations
  //
  //  High-level operations that combine an RpcClient with the wallet's
  //  transaction-building and signing. These are the operations the
  //  interactive wallet's command handlers call, and the operations
  //  that a future scripted wallet would call.
  //
  //  Everything here is synchronous. Timeouts are per-operation and
  //  passed explicitly where they matter.

  struct AccountState
  {
    uint64_t balance{0};
    uint64_t nonce{0};
  };

  //  The result of polling for a transaction's receipt. Distinguishes
  //  "committed successfully" from "committed with a Failure receipt"
  //  from "not yet in a block."
  struct ReceiptOutcome
  {
    enum class Kind
    {
      Confirmed, // receipt exists and status == Success
      Failed,    // receipt exists and status == Failure
      Pending,   // timeout expired, transaction not yet in a block
    };

    Kind kind{Kind::Pending};
    Common::Json receipt; // populated iff kind == Confirmed or Failed
  };

  //  Fetch an account's balance and nonce in two RPC calls. If either
  //  fails, returns nullopt and populates error_out.
  //
  //  Note: this is two round trips, not one. The RPC surface doesn't
  //  expose a combined "get account" that returns both. If it ever
  //  does, switch to that.
  std::optional<AccountState> fetchAccountState(
      RpcClient &rpc,
      const std::string &address_bech32m,
      std::string *error_out = nullptr);

  //  Submit a signed transaction. Serializes the transaction, hex-
  //  encodes it, and calls clrty_sendRawTransaction (bare name:
  //  "sendRawTransaction").
  //
  //  On success, returns the tx_hash as a hex string (with 0x prefix).
  //  A successful return means the tx was accepted into the mempool;
  //  it does NOT mean the tx has been confirmed.
  std::optional<std::string> submitSigned(
      RpcClient &rpc,
      const Core::Transaction &tx,
      std::string *error_out = nullptr);

    //  Poll for a transaction receipt until either it appears or the
  //  timeout expires.
  //
  //  Returns:
  //    - ReceiptOutcome with kind == Confirmed : tx is in a block and succeeded
  //    - ReceiptOutcome with kind == Failed    : tx is in a block and failed
  //    - ReceiptOutcome with kind == Pending   : tx is not yet in a block
  //    - std::nullopt                           : the RPC layer failed
  //
  //  On std::nullopt, error_out is populated. On Pending, error_out is
  //  empty — "not yet confirmed" is not an error.
  //
  //  The poll interval starts at 500 ms and doubles up to 4 s, so an
  //  early confirmation is detected quickly and a slow one doesn't
  //  hammer the node.
  std::optional<ReceiptOutcome> waitForReceipt(
      RpcClient &rpc,
      const std::string &txid_hex,
      std::chrono::seconds timeout,
      std::string *error_out = nullptr);

  //  Inspect a receipt object from the server and determine whether it
  //  reports success or failure. Returns true for Success, false for
  //  Failure, throws std::runtime_error for a malformed receipt (which
  //  indicates a server bug, not a transaction outcome).
  bool receiptSucceeded(const Common::Json &receipt);

} // namespace Wallet