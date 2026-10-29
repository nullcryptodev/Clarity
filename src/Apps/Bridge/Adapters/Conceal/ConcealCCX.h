// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "../ChainAdapter.h"

#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

namespace Bridge
{
  class CcxAdapter : public ChainAdapter
  {
  public:
    CcxAdapter() = default;
    ~CcxAdapter() override = default;

    std::string name() const override;
    std::string short_name() const override;
    uint64_t source_chain_id() const override;

    std::string default_rpc_endpoint() const override;
    uint16_t default_confirmation_depth() const override;
    uint8_t source_decimals() const override;

    bool probe_rpc(Wallet::RpcClient &rpc,
                   std::string *error_out = nullptr) const override;

    ChainStatus fetch_status(Wallet::RpcClient &rpc) const override;

    //  Scan CCX blocks for deposits.
    //
    //  Uses per-output reverse derivation (Crypto::reverseDeriveCandidate)
    //  against each vout's on-chain output pubkey. A vout matches if
    //  the reverse-derived spend pubkey is in the registered-subaddress
    //  cache installed via set_bridge_deposits_cache. On a match the
    //  deposit is emitted with its destination (from the cache entry).
    //
    //  Cache misses (a vout whose candidate is not in the cache) do
    //  NOT emit a deposit and are reported through the adapter's
    //  highestFullyResolvedHeight() mechanism: the scan loop uses that
    //  to avoid advancing its cursor past a block whose vouts couldn't
    //  all be resolved, so the next poll after refreshBridgeDeposits
    //  re-scans and matches.
    //
    //  Preconditions: set_deposit_address (64-byte custody blob) and
    //  set_deposit_ident_secret (view key) must have been called;
    //  otherwise this method throws. The cache may be null, in which
    //  case no deposits are emitted (fail-closed).
    void scan_deposits(
        Wallet::RpcClient &rpc,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const override;

    //  The highest height at which the most recent scan_deposits call
    //  fully resolved every vout it examined. nullopt means "no scan
    //  has run yet, or the last scan was stalled at its very first
    //  block." The scan loop clamps its cursor to this value (if
    //  present and < the requested to_height) so it doesn't skip
    //  past a cache-miss block.
    //
    //  Overrides ChainAdapter::highestFullyResolvedHeight, which
    //  returns nullopt for adapters that don't have this concept
    //  (Bitcoin).
    std::optional<uint64_t> highestFullyResolvedHeight() const override
    {
      return highest_fully_resolved_height_;
    }

    //  Release request. Delegates to the configured CCX wallet RPC
    //  (conceal-wallet-rpc or compatible) because the CCX daemon
    //  itself cannot build, sign, or submit a transaction — it can
    //  only relay a raw one. The wallet RPC's `transfer` method
    //  builds and signs the release tx with the custody spend key
    //  and blocks until the tx is confirmed. See set_wallet_rpc_endpoint.
    //
    //  The signature_block is deliberately not sent to the wallet
    //  RPC: it is the quorum-of-acks audit record, not the
    //  authorization for the spend. The wallet RPC's authority is
    //  the spend key it holds; the ack block lives on Clarity and is
    //  the public audit trail for the release.
    //
    //  The payment ID sent with the transfer is
    //  Blake2b("back" || LE64(withdrawal_id)), which anyone can
    //  compute from the withdrawal id alone. It is what makes the
    //  release tx discoverable on-chain via get_payments, and what
    //  ties the CCX tx to its withdrawal in a way that survives a
    //  bridge restart.
    //
    //  On success, ReleaseSubmission::source_tx_hash carries the CCX
    //  tx hash and ReleaseSubmission::ok is true. On failure, ok is
    //  false and reason describes the failure.
    ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const override;

    //  Look up the block height of a CCX transaction that is
    //  already in a block. Returns std::nullopt if the tx is
    //  not in a block (still in the mempool, or unknown).
    std::optional<uint64_t> fetch_release_height(
        Wallet::RpcClient &rpc,
        const Crypto::Hash &tx_hash) const override;

    bool validate_destination(
        const std::vector<uint8_t> &destination_blob) const override;

    //  Parse a CCX base58 address into the 64-byte
    //  (spend ‖ view) pubkey pair. The blob's layout matches
    //  what set_deposit_address consumes:
    //    [0..32)   spend pubkey
    //    [32..64)  view pubkey
    std::optional<std::vector<uint8_t>>
    parse_deposit_address(const std::string &address_str,
                          std::string *error_out) const override;

    //  A deposit-address blob is valid iff it's exactly 64 bytes
    //  and neither 32-byte half is all-zero.
    bool validate_deposit_address(
        const std::vector<uint8_t> &blob) const override;

    //  Store the parsed deposit-address blob. Also re-derives
    //  custody_spend_pub_ if the view key is already set (either
    //  call order works).
    void set_deposit_address(
        const std::vector<uint8_t> &blob) override;

    //  Store the custody wallet's private view key. Also derives
    //  custody_spend_pub_ from bridge_deposit_address_ if it's
    //  already set.
    //
    //  IMPORTANT: the view key must be a *reduced scalar* (the
    //  output of sc_reduce32), not the ed25519 seed. In a CCX
    //  wallet, `query_key` returns the reduced scalar; the mnemonic
    //  or `get_seed` returns the seed and will NOT work here. If
    //  the caller passes a seed, generateKeyDerivation's sc_check
    //  will fail and no deposits will ever be detected — the scan
    //  loop reports this once, but it is a configuration error the
    //  operator must fix.
    void set_deposit_ident_secret(
        const Crypto::SecretKey &secret) override;

    //  Configure the CCX wallet RPC endpoint used by submit_release.
    //  Separate from the daemon RPC because the two are different
    //  services: the daemon (default port 16000) provides chain
    //  reads; the wallet (default port 16001) provides transaction
    //  construction and signing.
    void set_wallet_rpc_endpoint(const std::string &host,
                                 uint16_t port,
                                 const std::string &user = {},
                                 const std::string &password = {});

    //  Configure the CCX address network prefix byte (varint prefix
    //  at the start of a decoded base58 address). Default: 0x13
    //  (mainnet; addresses begin with "ccx7").
    void set_network_prefix(uint64_t prefix);

    //  Set the custody address string (base58) alongside the
    //  already-stored blob. Called by cmd_start after
    //  parse_deposit_address succeeds, or by config load.
    void set_custody_address_string(const std::string &addr)
    {
      custody_address_string_ = addr;
    }

    std::optional<Crypto::Hash> find_existing_release(
        const Crypto::Hash &payment_id) const override;

    //  Install the cache of registered deposit subaddresses. The
    //  adapter stores a non-owning pointer to the caller's map; the
    //  caller (ChainRuntime) owns it and must keep it alive for the
    //  adapter's lifetime. Passing nullptr clears the cache, and
    //  scan_deposits will then emit no deposits (fail-closed, not
    //  fail-open: without a cache, nothing can be matched).
    //
    //  The map is keyed by the derived subaddress's spend pubkey,
    //  which is what the scanner reverse-derives for each vout.
    void set_bridge_deposits_cache(
        const BridgeDepositCache *cache) noexcept
    {
      bridge_deposits_by_spend_ = cache;
    }

    //  Test-visible helper. Same as the one scan_deposits uses
    //  internally; exposed so the scanner's per-tx logic can be
    //  tested without going through HTTP. Not part of the
    //  ChainAdapter interface and not meant for external callers.
    static bool populateDepositsFromJson(
        const Common::Json &tx,
        const BridgeDepositCache *cache,
        const std::vector<uint8_t> &bridge_deposit_address,
        const std::optional<Crypto::SecretKey> &custody_view_key,
        std::vector<ObservedDeposit> &out,
        bool &had_unresolved_vout);

  private:
    std::vector<uint8_t> bridge_deposit_address_;

    //  The custody address in base58 form, exactly as the operator
    //  supplied it on --bridge-address (or in config). Used by
    //  submit_release for sourceAddresses / changeAddress, so no
    //  base58 encoding is needed.
    std::string custody_address_string_;

    std::optional<Crypto::SecretKey> custody_view_key_;
    std::optional<Crypto::PublicKey> custody_spend_pub_;

    //  CCX wallet RPC endpoint. Empty host means "not configured".
    Wallet::RpcEndpoint wallet_rpc_endpoint_{"", 0};

    //  CCX address network prefix byte. Default: mainnet (0x13).
    uint64_t ccx_network_prefix_{0x13};

    //  Non-owning pointer to ChainRuntime::bridge_deposits_by_spend.
    //  Set by cmd_start (or by refreshBridgeDeposits) after the
    //  cache is populated. Null means "no cache" — scan_deposits
    //  emits nothing and every vout is treated as unresolved.
    //
    //  The map's lifetime is ChainRuntime's, which outlives the
    //  adapter (both are owned by WatcherSession and destroyed
    //  together). A raw pointer here avoids the ownership
    //  ambiguity of shared_ptr<unordered_map> for a map that's
    //  never really shared.
    const BridgeDepositCache *bridge_deposits_by_spend_{nullptr};

    //  Mutable state written by scan_deposits and read by
    //  highestFullyResolvedHeight. Reset at the top of each
    //  scan_deposits call; populated as the scanner walks blocks.
    //  `mutable` because scan_deposits is a const method (the
    //  ChainAdapter interface requires it) and this is
    //  observational cache state, not logical state.
    mutable std::optional<uint64_t> highest_fully_resolved_height_;
  };

} // namespace Bridge