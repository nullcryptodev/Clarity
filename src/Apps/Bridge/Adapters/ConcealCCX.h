// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

#include "../ChainAdapter.h"

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
        const Crypto::PublicKey &bridge_view_pubkey,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const override;

    ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const override;

    uint64_t to_clarity_atomic(uint64_t amount_source_atomic,
                               uint8_t clarity_decimals) const override;

    uint64_t to_source_atomic(uint64_t amount_clarity_atomic,
                              uint8_t clarity_decimals) const override;

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

  private:
    std::vector<uint8_t> bridge_deposit_address_;
    std::optional<Crypto::SecretKey> custody_view_key_;
    std::optional<Crypto::PublicKey> custody_spend_pub_;
  };

} // namespace Bridge