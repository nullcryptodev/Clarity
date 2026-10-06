// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "Common/Json.h"

#include "State/ProofKeys.h"
#include "State/SmtProof.h"

namespace Wallet
{
  //  RpcClient
  //
  //  Minimal synchronous JSON-RPC 2.0 client over HTTP/1.1. One POST
  //  per call, no connection reuse, no retries. A `call()` either
  //  returns a result or an error; it never throws.
  //
  //  The client is deliberately small. The wallet needs four methods
  //  — getBalance, getNonce, sendRawTransaction, getTransactionReceipt
  //  — and this class exposes exactly the machinery to call them.
  //
  //  Transport: Boost.Beast over an asio io_context constructed per
  //  call. The overhead of setting up a socket per RPC call is
  //  irrelevant given the wallet makes at most a handful of calls per
  //  user command.
  //
  //  Thread safety: none. Each instance is meant to be used from one
  //  thread. The interactive wallet is single-threaded, so this is
  //  fine.

  struct RpcEndpoint
  {
    std::string host{"127.0.0.1"};
    uint16_t port{9633};
  };

  //  An error returned by the server (in the JSON-RPC "error" field)
  //  or synthesized by the transport layer.
  //
  //  Transport errors use code = 0 and a message from the underlying
  //  HTTP/asio layer ("connection refused", "read timeout", "HTTP 500").
  //  Server errors use whatever code the RpcMethodError carried, and
  //  the server's message.
  struct RpcError
  {
    int code{0};
    std::string message;
    Common::Json data; // server-supplied structured detail, or null

    //  True if this is a transport-level failure (no server response
    //  was received), as opposed to a server-returned error object.
    bool is_transport_error{false};
  };

  //  The result of an RPC call: either a JSON result value or an
  //  error. Exactly one of {result, error} is meaningful; check ok().
  struct RpcResult
  {
    Common::Json result;
    std::optional<RpcError> error;

    bool ok() const noexcept { return !error.has_value(); }
  };

  class RpcClient
  {
  public:
    explicit RpcClient(RpcEndpoint endpoint);
    ~RpcClient();

    RpcClient(const RpcClient &) = delete;
    RpcClient &operator=(const RpcClient &) = delete;

    //  Call a JSON-RPC method. `params` should be a JSON object (the
    //  RPC surface uses named-parameter calls exclusively) or an
    //  array (for methods that take positional args, of which there
    //  are currently none).
    //
    //  Never throws. On any failure, `result.error` is populated and
    //  `result.result` is a JSON null.
    RpcResult call(const std::string &method,
                   const Common::Json &params);

    const RpcEndpoint &endpoint() const noexcept { return endpoint_; }

    //  Set the read timeout for a single call. Default is 5 seconds.
    //  Applies to the connect phase and to the response read.
    void set_timeout_seconds(int seconds) noexcept
    {
      timeout_seconds_ = seconds;
    }

  private:
    RpcEndpoint endpoint_;
    int timeout_seconds_{5};
  };

  //  ---- Typed helpers ----
  //
  //  Thin wrappers that call the RPC method and parse the result into
  //  the types the wallet uses. Every one of them returns std::nullopt
  //  on failure and populates error_out with a human-readable message.
  //
  //  These are the ONLY functions the wallet's command handlers call.
  //  Direct use of RpcClient::call is for diagnostics and for future
  //  methods that don't yet have a typed wrapper.

  //  Fetch an account's balance in atomic units.
  //
  //  Sends: { "address": <bech32m>, "token_id": "0x0" }
  //  Expects: { "balance": "0x..." }
  //
  //  Returns nullopt on transport error, RPC error, or malformed
  //  response. The error_out message distinguishes them.
  std::optional<uint64_t> getBalance(
      RpcClient &rpc,
      const std::string &address_bech32m,
      std::string *error_out = nullptr);

  //  Fetch an account's nonce.
  //
  //  Sends: { "address": <bech32m> }
  //  Expects: { "nonce": "0x..." }
  std::optional<uint64_t> getNonce(
      RpcClient &rpc,
      const std::string &address_bech32m,
      std::string *error_out = nullptr);

  //  Submit a signed transaction.
  //
  //  Sends: { "tx": "0x..." }
  //  Expects: { "tx_hash": "0x...", "accepted": true }
  //
  //  On success, returns the tx_hash hex string (with 0x prefix).
  //  The server throws RpcMethodError for any mempool rejection, so a
  //  successful return here means the tx was accepted into the mempool.
  std::optional<std::string> sendRawTransaction(
      RpcClient &rpc,
      const std::string &signed_hex,
      std::string *error_out = nullptr);

  //  Fetch a transaction receipt. Returns the receipt JSON on success,
  //  nullopt on failure.
  //
  //  The caller must distinguish "not yet confirmed" from a real
  //  error. `is_receipt_not_found` is set to true if the server
  //  returned the ReceiptNotFound error code, in which case the
  //  transaction is simply not confirmed yet — retry later.
  //
  //  Sends: { "hash": "0x..." }
  //  Expects: a receipt object.
  std::optional<Common::Json> getTransactionReceipt(
      RpcClient &rpc,
      const std::string &txid_hex,
      bool *is_receipt_not_found,
      std::string *error_out = nullptr);

  //  Fetch a validator record by its reward address.
  //
  //  Sends: { "address": <bech32m> }
  //  Expects: a validator JSON object, or ValidatorNotFound.
  //
  //  On ValidatorNotFound, `is_not_found` is set to true and the
  //  function returns nullopt. On other errors, `is_not_found` is
  //  false and error_out carries the message.
  std::optional<Common::Json> getValidatorByAddress(
      RpcClient &rpc,
      const std::string &address_bech32m,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  Fetch the node's current chain height and state root. Two
  //  RPC calls: `blockNumber` for the height, then
  //  `getBlockHeaderByNumber` for the header at that height.
  //
  //  Returns nullopt on transport error, RPC error, or malformed
  //  response.
  //
  //  This is the *trusting* half of the light-client verification:
  //  the caller is trusting the node to report its own current root
  //  honestly. To distrust, call this against two independent
  //  endpoints and require agreement — see
  //  WalletOperations::fetchTrustedRoot.
  struct HeaderInfo
  {
    uint64_t height{0};
    Crypto::Hash state_root{};
  };

  //  The result of a getProof call. Mirrors the P2P ProofMessage's
  //  status enum, but flattened for RPC use — the RPC method returns
  //  an error code instead of a status field for the non-ok cases.
  struct ProofResult
  {
    Crypto::Hash state_root{};
    uint64_t version{0};
    State::SmtProof proof{};
  };

  std::optional<HeaderInfo> getCurrentHeader(
      RpcClient &rpc,
      std::string *error_out = nullptr);

  //  Fetch a proof from the node's RPC. `key_type` and `key_bytes`
  //  use the same layouts as the P2P GetProof message.
  //
  //  Returns nullopt on any failure and populates error_out with a
  //  human-readable message. A successful return means the server
  //  produced a proof; the caller must still verify it with
  //  State::verifyProof(state_root, proof) against a root it
  //  trusts.
  std::optional<ProofResult> getProof(
      RpcClient &rpc,
      State::ProofKeyType key_type,
      const std::vector<uint8_t> &key_bytes,
      uint64_t version,
      std::string *error_out = nullptr);
} // namespace Wallet