// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "Adapters/ChainAdapter.h"
#include "Common/Json.h"
#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

namespace Bridge
{
  //  Which protocol the adapter uses to talk to the Bitcoin
  //  source chain. Two transports, deliberately:
  //
  //    BitcoindRpc  — a self-hosted bitcoind (or a provider that
  //                   speaks bitcoind's JSON-RPC, e.g. Chainstack,
  //                   QuickNode). Free if you run your own node,
  //                   full data, no rate limits.
  //
  //    MempoolSpace — mempool.space's free public REST API
  //                   (Esplora-shaped). No API key, no signup,
  //                   generous rate limits for read traffic.
  //                   Third-party dependency, so a deployment
  //                   that can run a node should.
  //
  //  Adding a third transport later is additive (a new enum
  //  case, a new per-transport branch in the four public
  //  methods, a new parser above it) — not a change to the
  //  ChainAdapter interface.
  enum class BitcoinTransport
  {
    BitcoindRpc,
    MempoolSpace,
  };

  struct BitcoinConfig
  {
    BitcoinTransport transport{BitcoinTransport::BitcoindRpc};

    //  ---- BitcoindRpc fields ----
    //
    //  RPC host and port. bitcoind mainnet is 8332, testnet
    //  18332, regtest 18443. Empty host means "not configured";
    //  the adapter's methods fail with a clear error rather than
    //  attempting to reach an empty endpoint.
    std::string rpc_host;
    uint16_t rpc_port{0};

    //  RPC credentials. bitcoind accepts rpcuser/rpcpassword
    //  (the fields here) or a cookie file (which the adapter
    //  does not implement — the operator supplies credentials).
    std::string rpc_user;
    std::string rpc_password;

    //  ---- MempoolSpace fields ----
    //
    //  Base URL for mempool.space's REST API. Defaults to the
    //  public instance; a deployment that runs a private
    //  mempool.space instance (or a compatible instance) points
    //  this at its own URL. The path suffix "/api" is included;
    //  the adapter appends the endpoint path ("/blocks/tip/height",
    //  etc.) to it.
    std::string mempool_url{"https://mempool.space/api"};

    //  Reserved: a future private mempool.space instance that
    //  gates access could accept an API key here. The public
    //  instance does not use it; sending one is harmless.
    std::string mempool_api_key;
  };

  //  Bitcoin source-chain adapter.
  //
  //  The second implementation of ChainAdapter, and the proof that
  //  the interface is genuinely chain-agnostic: adding this class
  //  required no change to Scan/, Release/, Repl/, or Cli/.
  //
  //  Bitcoin differs from CCX in every place the interface was
  //  designed to absorb:
  //
  //    - Address model: base58/bech32 scriptPubKey, not a 64-byte
  //      spend‖view blob. parse_deposit_address returns the script;
  //      validate_destination checks it parses.
  //
  //    - Release model: a signed transaction from a bitcoind-held
  //      key (or, for mempool.space, a raw transaction broadcast
  //      through the public /tx endpoint). Same "a key signs a tx"
  //      custody shape, different tooling.
  //
  //    - No view key: deposits are addressed directly. set_deposit_
  //      ident_secret is a no-op.
  //
  //    - No payment ID: releases carry no payment-ID tag. find_
  //      existing_release is left at the default (nullopt), and
  //      the scan loop's double-release check is a no-op for
  //      Bitcoin.
  //
  //    - Finality: confirmation-based, same as CCX's, but Bitcoin's
  //      depth is 6 rather than 20.
  //
  //    - Two transports: bitcoind JSON-RPC (self-hosted or a
  //      provider) or mempool.space REST (free public). The
  //      transport is selected by config, and the daemon never
  //      sees the choice.
  class BitcoinAdapter : public ChainAdapter
  {
  public:
    BitcoinAdapter() = default;
    ~BitcoinAdapter() override = default;

    std::string name() const override;
    std::string short_name() const override;
    uint64_t source_chain_id() const override;

    std::string default_rpc_endpoint() const override;
    uint16_t default_confirmation_depth() const override;
    uint8_t source_decimals() const override;

    bool probe_rpc(Wallet::RpcClient &rpc,
                   std::string *error_out = nullptr) const override;

    ChainStatus fetch_status(Wallet::RpcClient &rpc) const override;

    void scan_deposits(
        Wallet::RpcClient &rpc,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const override;

    ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const override;

    std::optional<uint64_t> fetch_release_height(
        Wallet::RpcClient &rpc,
        const Crypto::Hash &tx_hash) const override;

    bool validate_destination(
        const std::vector<uint8_t> &destination_blob) const override;

    std::optional<std::vector<uint8_t>>
    parse_deposit_address(const std::string &address_str,
                          std::string *error_out) const override;

    bool validate_deposit_address(
        const std::vector<uint8_t> &blob) const override;

    std::string deposit_address_display() const override;

    void set_deposit_address(
        const std::vector<uint8_t> &blob) override;

    //  Configure the Bitcoin wallet RPC endpoint. For bitcoind,
    //  chain reads and wallet operations share one port; the
    //  endpoint is the same as the daemon RPC. Populates the
    //  BitcoindRpc half of the config, so a deployment that only
    //  sets wallet_rpc_host / wallet_rpc_port continues to work
    //  without a "transport" field.
    void set_wallet_rpc_endpoint(
        const std::string &host,
        uint16_t port,
        const std::string &user = {},
        const std::string &password = {}) override;

    //  Configure the adapter's source-chain transport from a JSON
    //  config block. Reads "transport" ("bitcoind-rpc" or
    //  "mempool"), "mempool_url", "mempool_api_key". A config
    //  that omits "transport" leaves the adapter on BitcoindRpc,
    //  which the existing wallet_rpc_* fields configure.
    //
    //  "esplora" is accepted as an alias for "mempool" (and
    //  "esplora_url" / "esplora_api_key" as aliases for
    //  "mempool_url" / "mempool_api_key"), so a config that was
    //  written before the rename keeps working.
    void set_transport_config(const Common::Json &config) override;

    //  ---- Registration support ----
    //
    //  Bitcoin is not genesis-registered: the genesis writer
    //  registers CCX only. The bridge daemon registers BTC via
    //  `register-chain btc`, which builds a BridgeRegisterChain
    //  tx from these values. The fingerprint, decimals, and
    //  confirmation depth all come from Core/Bridge/Bitcoin.h so
    //  there is one source of truth.
    bool supports_registration() const override { return true; }
    Crypto::Hash wrapped_token_fingerprint() const override;
    std::pair<uint8_t, uint8_t> registration_blob_bounds() const override;
    uint32_t registration_active_validator_min() const override;

private:
    //  The deposit scriptPubKey, decoded from the configured
    //  address string. Empty until set_deposit_address is called.
    std::vector<uint8_t> deposit_script_;

    //  Transport configuration. Populated by
    //  set_wallet_rpc_endpoint (BitcoindRpc half) and
    //  set_transport_config (both halves).
    BitcoinConfig config_;

    //  Per-transport implementations. The public methods dispatch
    //  on config_.transport; a future transport adds a third
    //  pair here without touching the public methods.
    void scan_deposits_bitcoind(
        Wallet::RpcClient &rpc,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const;

    void scan_deposits_mempool(
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const;

    std::optional<uint64_t> fetch_release_height_bitcoind(
        Wallet::RpcClient &rpc,
        const Crypto::Hash &tx_hash) const;

    std::optional<uint64_t> fetch_release_height_mempool(
        const Crypto::Hash &tx_hash) const;

    //  Decode a base58/bech32 address to its scriptPubKey via
    //  mempool.space's /api/v1/validate-address endpoint. Used by
    //  parse_deposit_address when the transport is MempoolSpace;
    //  a bitcoind deployment passes the scriptPubKey hex
    //  directly, which the parse_deposit_address path handles
    //  first.
    std::optional<std::vector<uint8_t>> decodeAddressViaMempool(
        const std::string &address, std::string *error_out) const;

    uint64_t default_start_height() const override { return 0; };
  };

} // namespace Bridge