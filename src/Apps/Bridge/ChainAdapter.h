// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

namespace Bridge
{
  class BridgeError : public std::runtime_error
  {
  public:
    explicit BridgeError(const std::string &what)
        : std::runtime_error("BridgeError: " + what) {}
  };

  struct ObservedDeposit
  {
    uint64_t source_chain_id{0};
    Crypto::Hash source_tx_hash{};
    uint32_t source_output_index{0};
    uint64_t amount_source_atomic{0};
    uint64_t block_height{0};
    std::vector<uint8_t> deposit_blob;
  };

  struct ReleaseRequest
  {
    uint64_t withdrawal_id{0};
    uint64_t source_chain_id{0};
    uint64_t amount_clarity_atomic{0};
    std::vector<uint8_t> destination_blob;
  };

  struct ReleaseSubmission
  {
    bool ok{false};
    std::string reason;
    Crypto::Hash source_tx_hash{};
    uint64_t block_height{0};
  };

  struct ChainStatus
  {
    uint64_t current_height{0};
    uint64_t best_peer_height{0};
    bool reachable{false};
    std::string daemon_version;
  };

  class ChainAdapter
  {
  public:
    virtual ~ChainAdapter() = default;

    virtual std::string name() const = 0;
    virtual std::string short_name() const = 0;
    virtual uint64_t source_chain_id() const = 0;

    virtual std::string default_rpc_endpoint() const = 0;
    virtual uint16_t default_confirmation_depth() const = 0;
    virtual uint8_t source_decimals() const = 0;

    virtual bool probe_rpc(Wallet::RpcClient &rpc,
                           std::string *error_out = nullptr) const = 0;

    virtual ChainStatus fetch_status(Wallet::RpcClient &rpc) const = 0;

    virtual void scan_deposits(
        Wallet::RpcClient &rpc,
        const Crypto::PublicKey &bridge_view_pubkey,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const = 0;

    virtual ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const = 0;

    virtual uint64_t to_clarity_atomic(
        uint64_t amount_source_atomic,
        uint8_t clarity_decimals) const = 0;

    virtual uint64_t to_source_atomic(
        uint64_t amount_clarity_atomic,
        uint8_t clarity_decimals) const = 0;

    virtual bool validate_destination(
        const std::vector<uint8_t> &destination_blob) const = 0;

    //  Parse a chain-specific deposit-address string into the
    //  opaque blob this adapter uses for deposit detection. The
    //  default returns nullopt with a diagnostic, meaning "this
    //  adapter has no deposit-address concept" (e.g. a chain that
    //  identifies deposits by contract event rather than by
    //  recipient address).
    virtual std::optional<std::vector<uint8_t>>
    parse_deposit_address(const std::string &address_str,
                          std::string *error_out) const
    {
      (void)address_str;
      if (error_out)
        *error_out = "adapter '" + short_name() +
                     "' does not support deposit addresses";
      return std::nullopt;
    }

    //  Validate a deposit-address blob. Default: false (an adapter
    //  with no deposit-address concept has no valid blobs).
    virtual bool validate_deposit_address(
        const std::vector<uint8_t> & /*blob*/) const
    {
      return false;
    }

    //  Deliver a parsed deposit-address blob to the adapter. Called
    //  by cmd_start after parse_deposit_address succeeds, or after
    //  a blob is loaded from config. Default: no-op.
    virtual void set_deposit_address(
        const std::vector<uint8_t> & /*blob*/)
    {
    }

    //  Deliver a deposit-identification secret (CryptoNote view
    //  key, or an adapter-defined equivalent) to the adapter.
    //  Default: no-op.
    virtual void set_deposit_ident_secret(
        const Crypto::SecretKey & /*secret*/)
    {
    }
  };

  class ChainAdapterRegistry
  {
  public:
    static std::vector<std::shared_ptr<ChainAdapter>> all();
    static std::shared_ptr<ChainAdapter> find(const std::string &short_name);
    static bool registerAdapter(std::shared_ptr<ChainAdapter> adapter);

  private:
    static std::vector<std::shared_ptr<ChainAdapter>> &storage();
  };

} // namespace Bridge