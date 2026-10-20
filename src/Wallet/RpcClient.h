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

    //  Optional HTTP Basic auth. When `user` is empty, no
    //  Authorization header is sent. The password is intentionally
    //  a plain string (not a file path) — the caller is responsible
    //  for reading it from wherever it lives (file, env, prompt)
    //  and for not logging it. The endpoint is normally constructed
    //  once at startup, used by RpcClient for the lifetime of the
    //  process, and destroyed on shutdown; it is not part of any
    //  serialization format.
    std::string user;
    std::string password;
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

  //  Fetch a single NFT by id.
  //
  //  Sends: { "nft_id": "0x..." }
  //  Expects: an NftInfo JSON object, or NftNotFound.
  //
  //  On NftNotFound, `is_not_found` is set to true and the function
  //  returns nullopt. On other errors, `is_not_found` is false and
  //  error_out carries the message.
  std::optional<Common::Json> getNft(
      RpcClient &rpc,
      uint64_t nft_id,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  List NFTs owned by an address.
  //
  //  Sends: { "address": <bech32m>, "limit": "0x...", "offset": "0x..." }
  //  Expects: { "nfts": [...], "count": ..., "offset": ..., "limit": ... }
  std::optional<Common::Json> getNftsForOwner(
      RpcClient &rpc,
      const std::string &address_bech32m,
      uint64_t limit,
      uint64_t offset,
      std::string *error_out = nullptr);

  //  List NFTs in a collection.
  //
  //  Sends: { "collection_id": "0x...", "limit": "0x...", "offset": "0x..." }
  //  Expects: { "nfts": [...], "count": ..., ... }, or NftCollectionNotFound.
  std::optional<Common::Json> getNftsForCollection(
      RpcClient &rpc,
      uint64_t collection_id,
      uint64_t limit,
      uint64_t offset,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  Fetch a single collection by id.
  //
  //  Sends: { "collection_id": "0x..." }
  //  Expects: an NftCollection JSON object, or NftCollectionNotFound.
  std::optional<Common::Json> getCollection(
      RpcClient &rpc,
      uint64_t collection_id,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  List all collections.
  //
  //  Sends: { "limit": "0x...", "offset": "0x..." }
  //  Expects: { "collections": [...], "count": ..., ... }
  std::optional<Common::Json> getAllCollections(
      RpcClient &rpc,
      uint64_t limit,
      uint64_t offset,
      std::string *error_out = nullptr);

  //  Fetch a single token's metadata.
  //
  //  Sends: { "token_id": "0x..." }
  //  Expects: a TokenInfo JSON object, or TokenNotFound.
  //
  //  On TokenNotFound, `is_not_found` is set to true and the function
  //  returns nullopt. On other errors, `is_not_found` is false and
  //  error_out carries the message.
  std::optional<Common::Json> getTokenInfo(
      RpcClient &rpc,
      uint64_t token_id,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  Fetch a token's current supply.
  //
  //  Sends: { "token_id": "0x..." }
  //  Expects: { "token_id": ..., "supply": "0x..." }
  //
  //  Works for the native token (id 0) and for user tokens.
  std::optional<Common::Json> getTokenSupply(
      RpcClient &rpc,
      uint64_t token_id,
      std::string *error_out = nullptr);

  //  List all tokens known to the node.
  //
  //  Sends: { "limit": "0x...", "offset": "0x..." }
  //  Expects: { "tokens": [...], "count": ..., ... }
  std::optional<Common::Json> getAllTokens(
      RpcClient &rpc,
      uint64_t limit,
      uint64_t offset,
      std::string *error_out = nullptr);

  //  List every token balance held by an address.
  //
  //  Sends: { "address": <bech32m> }
  //  Expects: { "tokens": [ { "token_id": ..., "balance": ... }, ... ], ... }
  //
  //  This is the "what do I hold" call — the counterpart to
  //  getBalance, which returns one balance. Useful for the wallet's
  //  `tokens` command, which prints everything at once.
  std::optional<Common::Json> getTokensForAddress(
      RpcClient &rpc,
      const std::string &address_bech32m,
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

  //  =========================================================================
  //  Bridge RPC wrappers
  //
  //  Typed accessors for the bridge state the watcher daemon needs
  //  to drive submission. All of these call Clarity JSON-RPC
  //  methods that the node exposes.
  //
  //  None of these are used by the wallet app today; they are
  //  added here so the bridge app can share the same transport,
  //  timeout, and auth configuration as the rest of the wallet's
  //  RPC surface.
  //  =========================================================================

  //  Fetch the BridgeChainRegistration for a given source chain
  //  id. Used by the daemon to (a) check the chain is registered
  //  before submitting a mint, and (b) obtain the wrapped token id
  //  for the burn path.
  //
  //  Sends: { "source_chain_id": "0x..." }
  //  Expects: a BridgeChainRegistration JSON object.
  //
  //  On BridgeChainNotRegistered, `is_not_registered` is set to
  //  true and the function returns nullopt.
  std::optional<Common::Json> getBridgeChainRegistration(
      RpcClient &rpc,
      uint64_t source_chain_id,
      bool *is_not_registered,
      std::string *error_out = nullptr);

  //  Fetch a single bridge withdrawal record by id.
  //
  //  Sends: { "withdrawal_id": "0x..." }
  //  Expects: a BridgeWithdrawal JSON object.
  //
  //  On BridgeWithdrawalNotFound, `is_not_found` is set to true
  //  and the function returns nullopt.
  std::optional<Common::Json> getBridgeWithdrawal(
      RpcClient &rpc,
      uint64_t withdrawal_id,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  List the active watchers for a source chain. Used to
  //  resolve the signer set when building a mint attestation.
  //
  //  Sends: { "source_chain_id": "0x...", "height": "0x..." }
  //  Expects: { "watchers": [ { "id": ..., "validator_id": ...,
  //                            "reward_address": ... }, ... ] }
  //
  //  The height parameter selects the active set as of that
  //  height, matching the executor's resolution at
  //  ctx.current_height. Pass 0 for "current head".
  std::optional<Common::Json> getActiveWatchers(
      RpcClient &rpc,
      uint64_t source_chain_id,
      uint64_t height,
      std::string *error_out = nullptr);

  //  Resolve a reward address to its bridge watcher id, if
  //  registered. Used by the startup path to fill in
  //  WatcherSession::watcher_id without operator intervention.
  //
  //  Sends: { "address": <bech32m> }
  //  Expects: { "watcher_id": "0x..." }
  //
  //  On BridgeWatcherNotFound, `is_not_found` is set to true and
  //  the function returns nullopt. A null watcher_id (0) is
  //  treated the same as not-found: the caller should fall back
  //  to prompting.
  std::optional<Common::Json> getBridgeWatcherIdByAddress(
      RpcClient &rpc,
      const std::string &address_bech32m,
      bool *is_not_found,
      std::string *error_out = nullptr);

  //  Check whether a specific deposit has already been minted.
  //  Used by the submission loop to short-circuit before
  //  submitting a transaction the executor would reject anyway.
  //
  //  Sends: { "source_chain_id": "0x...",
  //           "source_tx_hash": "0x...",
  //           "source_output_index": "0x..." }
  //  Expects: { "consumed": true|false,
  //             "mint_height": "0x..." (present iff consumed) }
  //
  //  Returns the mint height on success (with consumed=true), 0
  //  on success with consumed=false, or nullopt on RPC failure.
  //  The `is_consumed` out-param distinguishes "not consumed" from
  //  "RPC call failed" — both return nullopt otherwise.
  std::optional<uint64_t> getBridgeConsumed(
      RpcClient &rpc,
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      bool *is_consumed,
      std::string *error_out = nullptr);

  std::optional<Common::Json> getBridgeAttestations(
      RpcClient &rpc,
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      std::string *error_out = nullptr);

  //  Fetch all ack attestations for a specific withdrawal.
  //
  //  Sends: { "withdrawal_id": "0x..." }
  //  Expects: { "withdrawal_id": ..., "count": ...,
  //             "attestations": [ { validator_id, signer_index,
  //                                attested_at_height, signature }, ... ] }
  //
  //  This is what the submission loop reads after enough attestations
  //  have accumulated, to decide whether quorum has been reached and
  //  to assemble the `[2] count || N*66` block for a
  //  BridgeAckWithdrawal. The function does not attempt to build the
  //  block — that's Bridge::Signing::AssembleBlock's job once the
  //  caller has selected a quorum-sized subset.
  std::optional<Common::Json> getBridgeAckAttestations(
      RpcClient &rpc,
      uint64_t withdrawal_id,
      std::string *error_out = nullptr);

  //  List withdrawals that have been burned but not yet released.
  //
  //  Sends: { "from_height": "0x...", "limit": "0x...",
  //           "offset": "0x..." }
  //  Expects: { "withdrawals": [ { ...withdrawal fields...,
  //                                ack_attestation_count,
  //                                active_watcher_count,
  //                                ack_quorum,
  //                                ack_quorum_reached }, ... ],
  //             "count": ..., "height": ..., ... }
  //
  //  The per-entry `ack_quorum_reached` boolean lets the caller
  //  skip a second RPC round-trip per withdrawal to compute quorum.
  //  The quorum itself is computed against the active watcher set
  //  at the current head height.
  //
  //  `from_height == 0` means "from genesis". Use a nonzero
  //  value on incremental scans to avoid re-fetching withdrawals
  //  the loop has already processed.
  std::optional<Common::Json> getPendingWithdrawals(
      RpcClient &rpc,
      uint64_t from_height,
      uint64_t limit,
      uint64_t offset,
      std::string *error_out = nullptr);

  //  Fetch the aggregate BridgeStats for a source chain.
  //
  //  Sends: { "source_chain_id": "0x..." }
  //  Expects: { initialized, total_minted, total_burned,
  //             total_released, deposit_count, withdrawal_count,
  //             released_withdrawal_count, last_mint_height,
  //             last_burn_height, last_release_height,
  //             registered_at_height, outstanding_liability }
  //
  //  A chain that has been registered but has never seen a bridge
  //  operation returns `initialized: false` with all counters zero.
  //  This is not an error — the call still succeeds; a monitoring
  //  dashboard gets a clean zero rather than a 404.
  //
  //  `outstanding_liability` is derived (total_burned -
  //  total_released) and included so the caller doesn't have to
  //  recompute the invariant.
  std::optional<Common::Json> getBridgeStats(
      RpcClient &rpc,
      uint64_t source_chain_id,
      std::string *error_out = nullptr);
} // namespace Wallet