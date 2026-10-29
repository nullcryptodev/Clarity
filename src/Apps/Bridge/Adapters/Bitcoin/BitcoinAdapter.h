// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "Adapters/ChainAdapter.h"
#include "Adapters/Bitcoin/Custody.h"
#include "Common/Json.h"
#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

namespace Bridge
{
  //  Which protocol the adapter uses to talk to the Bitcoin
  //  source chain. Two transports, deliberately:
  //
  //    BitcoindRpc  — a self-hosted bitcoind (or a provider that
  //                   speaks bitcoind's JSON-RPC).
  //
  //    MempoolSpace — mempool.space's free public REST API
  //                   (Esplora-shaped).
  enum class BitcoinTransport
  {
    BitcoindRpc,
    MempoolSpace,
  };

  struct BitcoinConfig
  {
    BitcoinTransport transport{BitcoinTransport::BitcoindRpc};

    //  ---- BitcoindRpc fields ----
    std::string rpc_host;
    uint16_t rpc_port{0};
    std::string rpc_user;
    std::string rpc_password;

    //  ---- MempoolSpace fields ----
    std::string mempool_url{"https://mempool.space/api"};
    std::string mempool_api_key;
  };

  //  Bitcoin source-chain adapter.
  //
  //  Deposits go to per-registration derived addresses. The
  //  adapter does not hold a static deposit script; it consults
  //  the per-runtime BitcoinCustody (set_custody) to find the set
  //  of scripts it is watching, and the per-runtime deposit cache
  //  (set_deposit_cache) to resolve a matched index to the
  //  rclrty1 destination the user registered.
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

    //  Scan Bitcoin blocks for deposits.
    //
    //  Requires custody_ (set by set_custody). For each vout in
    //  each tx, matches the scriptPubKey against custody's
    //  scriptsInWindow(); on a hit, looks up the index in the
    //  deposit cache and, if found, emits ObservedDeposit with
    //  the cache's destination.
    //
    //  A vout whose script is in the custody window but not in
    //  the cache is "unresolved": the registration is on-chain
    //  but the cache hasn't been refreshed yet. The adapter sets
    //  highestFullyResolvedHeight() to hold the cursor at the
    //  last fully-resolved block, exactly like CcxAdapter.
    void scan_deposits(
        Wallet::RpcClient &rpc,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const override;

    //  The highest height at which every in-window vout resolved
    //  to a cache entry. nullopt means "the first chunk stalled";
    //  the scan loop clamps its cursor to this value.
    std::optional<uint64_t> highestFullyResolvedHeight() const override
    {
      return highest_fully_resolved_height_;
    }

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

    void set_wallet_rpc_endpoint(
        const std::string &host,
        uint16_t port,
        const std::string &user = {},
        const std::string &password = {}) override;

    void set_transport_config(const Common::Json &config) override;

    //  ChainAdapter override. Returns the bech32 deposit address
    //  for `index`, derived from custody_. Returns nullopt if
    //  custody is not installed.
    std::optional<std::string> deriveDepositAddress(
        uint64_t index,
        std::string *error_out = nullptr) const override;

    //  Install the per-runtime custody state. Non-owning; the
    //  ChainRuntime owns the BitcoinCustody and outlives the
    //  adapter pointer. Set by cmd_start before Scan::startScan.
    void set_custody(BitcoinCustody *custody) noexcept
    {
      custody_ = custody;
    }

    //  Install the per-runtime deposit cache: index -> destination.
    //  Non-owning; owned by ChainRuntime, populated by
    //  refreshBridgeDeposits. Set by cmd_start before
    //  Scan::startScan, mirroring CcxAdapter::set_bridge_deposits_cache.
    void set_deposit_cache(
        const std::map<uint64_t, Crypto::Address> *cache) noexcept
    {
      deposit_cache_ = cache;
    }

    //  ---- Registration support ----
    bool supports_registration() const override { return true; }
    Crypto::Hash wrapped_token_fingerprint() const override;
    std::pair<uint8_t, uint8_t> registration_blob_bounds() const override;
    uint32_t registration_active_validator_min() const override;

  private:
    std::vector<uint8_t> deposit_script_;
    BitcoinConfig config_;

    BitcoinCustody *custody_{nullptr};
    const std::map<uint64_t, Crypto::Address> *deposit_cache_{nullptr};

    mutable std::optional<uint64_t> highest_fully_resolved_height_;

    //  After a `highestFullyResolvedHeight` read, this flag tells
    //  cmd_start (via ScanRegistry, on the next poll) whether the
    //  deposit cache should be refreshed before the next scan.
    //  Currently unused; refreshBridgeDeposits is called each
    //  poll anyway. Retained for symmetry with CcxAdapter.
    mutable bool cache_miss_detected_{false};

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

    std::optional<std::vector<uint8_t>> decodeAddressViaMempool(
        const std::string &address, std::string *error_out) const;

    uint64_t default_start_height() const override { return 0; }
  };
} // namespace Bridge