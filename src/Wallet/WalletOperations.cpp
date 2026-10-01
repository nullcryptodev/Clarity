// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletOperations.h"

#include <chrono>
#include <thread>

namespace Wallet
{
  namespace
  {
    std::string bytesToHex(const uint8_t *data, size_t len)
    {
      static const char hex[] = "0123456789abcdef";
      std::string out;
      out.reserve(len * 2);
      for (size_t i = 0; i < len; ++i)
      {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
      }
      return out;
    }

    std::string serializeTxToHex(const Core::Transaction &tx)
    {
      const auto bytes = tx.serialize();
      return "0x" + bytesToHex(bytes.data(), bytes.size());
    }
  } // anonymous namespace

  //  ---- fetchAccountState ----

  std::optional<AccountState> fetchAccountState(
      RpcClient &rpc,
      const std::string &address_bech32m,
      std::string *error_out)
  {
    AccountState state;

    {
      std::string err;
      auto balance = getBalance(rpc, address_bech32m, &err);
      if (!balance.has_value())
      {
        if (error_out)
          *error_out = "getBalance: " + err;
        return std::nullopt;
      }
      state.balance = *balance;
    }

    {
      std::string err;
      auto nonce = getNonce(rpc, address_bech32m, &err);
      if (!nonce.has_value())
      {
        if (error_out)
          *error_out = "getNonce: " + err;
        return std::nullopt;
      }
      state.nonce = *nonce;
    }

    return state;
  }

  //  ---- submitSigned ----

  std::optional<std::string> submitSigned(
      RpcClient &rpc,
      const Core::Transaction &tx,
      std::string *error_out)
  {
    const std::string hex = serializeTxToHex(tx);

    std::string err;
    auto txid = sendRawTransaction(rpc, hex, &err);
    if (!txid.has_value())
    {
      if (error_out)
        *error_out = err;
      return std::nullopt;
    }

    return txid;
  }

  //  ---- receiptSucceeded ----

  bool receiptSucceeded(const Common::Json &receipt)
  {
    if (!receipt.is_object())
      throw std::runtime_error("receipt is not a JSON object");

    if (!receipt.contains("status"))
      throw std::runtime_error("receipt missing 'status' field");

    const auto &status = receipt["status"];
    if (!status.is_string())
      throw std::runtime_error("receipt 'status' is not a string");

    const std::string s = status.get<std::string>();
    if (s == "success")
      return true;
    if (s == "failure")
      return false;

    throw std::runtime_error("receipt 'status' has unknown value: " + s);
  }

  //  ---- waitForReceipt ----

  std::optional<ReceiptOutcome> waitForReceipt(
      RpcClient &rpc,
      const std::string &txid_hex,
      std::chrono::seconds timeout,
      std::string *error_out)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;

    auto interval = std::chrono::milliseconds(500);
    const auto max_interval = std::chrono::milliseconds(4000);

    while (std::chrono::steady_clock::now() < deadline)
    {
      bool not_found = false;
      std::string err;

      auto receipt = getTransactionReceipt(rpc, txid_hex, &not_found, &err);

      if (receipt.has_value())
      {
        //  We have a receipt. Decide success vs failure from the
        //  status field.
        ReceiptOutcome outcome;
        outcome.receipt = *receipt;

        try
        {
          outcome.kind = receiptSucceeded(*receipt)
                             ? ReceiptOutcome::Kind::Confirmed
                             : ReceiptOutcome::Kind::Failed;
        }
        catch (const std::exception &e)
        {
          if (error_out)
            *error_out = std::string("malformed receipt: ") + e.what();
          return std::nullopt;
        }

        return outcome;
      }

      if (!not_found)
      {
        if (error_out)
          *error_out = err.empty() ? "getTransactionReceipt failed" : err;
        return std::nullopt;
      }

      //  Not yet confirmed. Sleep, then retry.
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              deadline - std::chrono::steady_clock::now());

      if (remaining <= std::chrono::milliseconds::zero())
        break;

      const auto sleep_for = std::min(interval, remaining);
      std::this_thread::sleep_for(sleep_for);
      interval = std::min(interval * 2, max_interval);
    }

    //  Timed out. The tx is not confirmed within the timeout window.
    ReceiptOutcome outcome;
    outcome.kind = ReceiptOutcome::Kind::Pending;
    return outcome;
  }
} // namespace Wallet