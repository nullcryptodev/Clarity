// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chrono>
#include <thread>

#include "WalletOperations.h"
#include "AddressCodec.h"

#include "Core/Account.h"

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

    //  Extract the raw 32-byte public key from a bech32m address
    //  string. Fails if the string isn't a valid address for the
    //  given network.
    std::optional<std::vector<uint8_t>> addressBytesForProof(
        const std::string &address_bech32m,
        Network network)
    {
      auto addr = Wallet::decodeAddress(address_bech32m, network);
      if (!addr.has_value())
        return std::nullopt;

      std::vector<uint8_t> out(32);
      std::memcpy(out.data(), addr->data.data(), 32);
      return out;
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

  std::optional<TrustedRoot> fetchTrustedRoot(
      RpcClient &primary,
      RpcClient *peer,
      std::string *error_out)
  {
    std::string err;
    auto primary_header = getCurrentHeader(primary, &err);
    if (!primary_header.has_value())
    {
      if (error_out)
        *error_out = "primary header fetch failed: " + err;
      return std::nullopt;
    }

    TrustedRoot result;
    result.root = primary_header->state_root;
    result.height = primary_header->height;
    result.peer_verified = false;

    if (peer == nullptr)
      return result;

    //  Peer is configured: fetch its header at the *same height* and
    //  compare roots. We can't just fetch its current header, because
    //  the peer may be at a different height than the primary. What
    //  we're checking is "do two independent nodes agree on the state
    //  root at height H" — that's a stronger statement than "do they
    //  agree on the current root", because it catches a peer that's
    //  lying about its height too.
    auto peer_header = getCurrentHeader(*peer, &err);
    if (!peer_header.has_value())
    {
      if (error_out)
        *error_out = "peer header fetch failed: " + err;
      return std::nullopt;
    }

    if (peer_header->height != primary_header->height)
    {
      if (error_out)
        *error_out = "peer is at a different height (" +
                     std::to_string(peer_header->height) +
                     ") than primary (" +
                     std::to_string(primary_header->height) + ")";
      return std::nullopt;
    }

    if (peer_header->state_root != primary_header->state_root)
    {
      if (error_out)
        *error_out = "peer and primary disagree on state root at height " +
                     std::to_string(primary_header->height);
      return std::nullopt;
    }

    result.peer_verified = true;
    return result;
  }

  std::optional<VerifiedBalance> fetchVerifiedBalance(
      RpcClient &primary,
      RpcClient *peer,
      const std::string &address_bech32m,
      Network network,
      std::string *error_out)
  {
    //  Step 1: trusted root.
    std::string err;
    auto trusted = fetchTrustedRoot(primary, peer, &err);
    if (!trusted.has_value())
    {
      if (error_out)
        *error_out = err;
      return std::nullopt;
    }

    //  Step 2: address bytes for the key descriptor.
    auto addr_bytes = addressBytesForProof(address_bech32m, network);
    if (!addr_bytes.has_value())
    {
      if (error_out)
        *error_out = "invalid address for this network: " + address_bech32m;
      return std::nullopt;
    }

    //  Step 3: request the proof. Ask for the *trusted height*, so
    //  the proof we get back is at the same version as the root
    //  we're verifying against.
    auto proof = getProof(primary,
                          State::ProofKeyType::Account,
                          *addr_bytes,
                          trusted->height,
                          &err);
    if (!proof.has_value())
    {
      if (error_out)
        *error_out = "getProof failed: " + err;
      return std::nullopt;
    }

    //  Step 4: the server's claimed root must match the trusted
    //  root. A mismatch means either the server produced a proof
    //  against a different version, or it's lying about which root
    //  the proof is against. Either way, we refuse.
    if (proof->state_root != trusted->root)
    {
      if (error_out)
        *error_out = "proof is against a different root than the trusted root";
      return std::nullopt;
    }

    //  Step 5: local verification. This is the pure-function call
    //  that makes the whole thing work — no DB, no signature, just
    //  Blake2b over the sibling chain. If it fails, the server lied
    //  about the value and we don't return it.
    if (!State::verifyProof(trusted->root, proof->proof))
    {
      if (error_out)
        *error_out = "proof failed local verification";
      return std::nullopt;
    }

    //  Step 6: decode the leaf.
    VerifiedBalance out;
    out.state_root = trusted->root;
    out.version = proof->version;
    out.peer_verified = trusted->peer_verified;

    if (!proof->proof.value.has_value())
    {
      //  Non-inclusion: the account has never been touched. Balance
      //  is zero by construction.
      out.balance = 0;
      out.is_empty = true;
      return out;
    }

    Core::Account account;
    if (!Core::Account::deserializeState(proof->proof.value->data(),
                                         proof->proof.value->size(),
                                         account))
    {
      if (error_out)
        *error_out = "verified proof carries an undecodable account record";
      return std::nullopt;
    }

    out.balance = account.balance;
    out.is_empty = false;
    return out;
  }
} // namespace Wallet