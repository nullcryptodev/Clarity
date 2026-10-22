// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
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

    void scan_deposits(
        Wallet::RpcClient &rpc,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const override;

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
    //
    //  Used by the withdrawal scan loop's Released phase to
    //  populate the release_height field that
    //  buildBridgeAckWithdrawal requires. Without it, the
    //  BridgeAckWithdrawal tx can't be built (release_height
    //  must be non-zero) and the Clarity-side audit record
    //  stays unpopulated.
    //
    //  The lookup goes through the CCX daemon's /gettransactions
    //  endpoint (not the wallet RPC — the wallet can already tell
    //  us this via get_transfers, but that's a much heavier call
    //  and requires the wallet to be in a state where the transfer
    //  is visible, which it always is by the time submit_release
    //  returns). The daemon endpoint is cheap and direct.
    //
    //  Uses the daemon RPC configured on this adapter via its
    //  Wallet::RpcClient argument, matching probe_rpc and
    //  fetch_status.
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
    void set_deposit_ident_secret(
        const Crypto::SecretKey &secret) override;

    //  Configure the CCX wallet RPC endpoint used by submit_release.
    //  Separate from the daemon RPC because the two are different
    //  services: the daemon (default port 16000) provides chain
    //  reads; the wallet (default port 16001) provides transaction
    //  construction and signing.
    //
    //  The password is supplied as a plain string for the same
    //  reason Wallet::RpcEndpoint supplies it that way — the
    //  caller is responsible for reading it from wherever it lives
    //  and for not logging it.
    //
    //  Calling this with an empty host disables submit_release;
    //  it will report "no CCX wallet RPC configured" and return
    //  ok=false. That's the intended behaviour for a deployment
    //  that has not yet provisioned a wallet RPC.
    void set_wallet_rpc_endpoint(const std::string &host,
                                 uint16_t port,
                                 const std::string &user = {},
                                 const std::string &password = {});

    //  Configure the CCX address network prefix byte.
    //
    //  This is the varint written at the start of a decoded CCX
    //  address. It is a *deployment* property: mainnet and testnet
    //  share a chain id (as the bridge sees it) but use different
    //  prefix bytes, and the CCX wallet RPC on the other side will
    //  reject an address whose prefix doesn't match its own network.
    //
    //  Common values:
    //    - CCX mainnet: 0x13 (addresses begin with "ccx7")
    //    - CCX testnet: 0x53 (addresses begin with "ccxT")
    //
    //  If you are unsure which value your wallet uses, decode one of
    //  its own addresses with `parse_deposit_address` and inspect the
    //  varint (or just ask the wallet: `get_address`). Getting this
    //  wrong causes releases to fail with a "wrong address" error
    //  from the wallet RPC, not a silent fund loss — but it will
    //  block all withdrawals until fixed.
    //
    //  Default: 0x13 (CCX mainnet).
    void set_network_prefix(uint64_t prefix);

    //  Set the custody address string (base58) alongside the
    //  already-stored blob. Called by cmd_start after
    //  parse_deposit_address succeeds, or by config load.
    void set_custody_address_string(const std::string &addr)
    {
      custody_address_string_ = addr;
    }

    std::optional<Crypto::Hash> find_existing_release(const Crypto::Hash &payment_id) const override;

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
  };

} // namespace Bridge