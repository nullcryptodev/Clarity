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

#include "Common/Json.h"
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

    //  The 64-byte (spend ‖ view) destination blob, as stored in
    //  the BridgeWithdrawal record.
    std::vector<uint8_t> destination_blob;

    //  The base58 destination address, as stored in the record.
    //  This is what the CCX wallet RPC uses; the blob is only used
    //  for validation.
    std::string destination_address;
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
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const = 0;

    virtual ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const = 0;

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

    //  Human-readable form of the deposit address, for display in
    //  cmd_status. Returns an empty string if the adapter has no
    //  deposit address configured. Concrete adapters override this
    //  to return whatever textual form makes sense for their chain
    //  (base58 for CCX, bech32m for anything EVM-adjacent, etc.).
    virtual std::string deposit_address_display() const { return {}; }

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

    //  =========================================================================
    //  Withdrawal release configuration and helpers
    //  =========================================================================
    //
    //  The Commands.cpp scan loop drives the release pipeline
    //  generically; it does not know which chain adapter it is
    //  talking to. These three methods let a chain adapter
    //  participate in the release pipeline (by overriding them),
    //  or opt out cleanly (by leaving the defaults, which disable
    //  the release path for that chain).
    //
    //  A deposit-only chain leaves all three at their defaults:
    //    - set_wallet_rpc_endpoint: no-op
    //    - set_network_prefix:  no-op
    //    - fetch_release_height:    returns nullopt
    //
    //  The scan loop then logs "cannot determine release height;
    //  marking Done without the Clarity-side record" for each
    //  withdrawal it can't complete, which is the correct
    //  behavior for a chain that has no on-chain release record.

    //  Configure the wallet RPC endpoint used by submit_release.
    //  For CCX this is conceal-wallet-rpc; for a chain whose
    //  daemon can build and sign transactions itself, it might be
    //  the daemon RPC or unused entirely.
    //
    //  Default: no-op. submit_release's default implementation
    //  returns ok=false with "release not supported", so a watcher
    //  configured for a deposit-only chain simply skips releases.
    virtual void set_wallet_rpc_endpoint(
        const std::string & /*host*/,
        uint16_t /*port*/,
        const std::string & /*user*/ = {},
        const std::string & /*password*/ = {})
    {
    }

    //  Configure the chain's address network prefix. For CCX this
    //  is the varint version byte written at the start of a
    //  decoded base58 address. Other chains use it differently or
    //  ignore it.
    //
    //  Default: no-op.
    virtual void set_network_prefix(uint64_t /*prefix*/)
    {
    }

    //  Look up the block height of a source-chain transaction that
    //  is already in a block. Returns std::nullopt if the tx is
    //  not in a block (mempool, unknown, or the adapter has no
    //  height-lookup capability).
    //
    //  Used by the scan loop's Released phase to populate the
    //  release_height that BridgeAckWithdrawal requires.
    //
    //  Default: return nullopt.
    virtual std::optional<uint64_t> fetch_release_height(
        Wallet::RpcClient & /*rpc*/,
        const Crypto::Hash & /*tx_hash*/) const
    {
      return std::nullopt;
    }

    virtual std::optional<Crypto::Hash> find_existing_release(const Crypto::Hash &/*payment_id*/) const {
      return std::nullopt;
    }

    //  Configure the adapter's source-chain transport from a
    //  JSON config block. The default implementation is a no-op;
    //  an adapter whose transport is already fully configured by
    //  the existing setters (CcxAdapter) leaves it alone, and an
    //  adapter with a richer transport model (BitcoinAdapter)
    //  parses the JSON.
    virtual void set_transport_config(const Common::Json & /*config*/) {}

    //  A hint for where a fresh deployment should start scanning
    //  if no cursor has been set. 0 means "no hint; scan from
    //  genesis" (the historic behaviour). A non-zero value is a
    //  recent height the adapter was written against; the
    //  operator should override it with `start_height` in the
    //  config if they care about a specific range.
    virtual uint64_t default_start_height() const { return 0; }

    //  =========================================================================
    //  Registration support (for `register-chain`)
    //  =========================================================================
    //
    //  A chain adapter that can be registered on Clarity returns
    //  the values `register-chain` needs to build the 55-byte
    //  BridgeChainRegistration blob. An adapter that is
    //  genesis-registered (CCX) or that has no bridge concept at
    //  all leaves the defaults: supports_registration() returns
    //  false and register-chain refuses with a clear message.
    //
    //  The blob itself is built by cmd_register_chain from these
    //  three values plus the caller-supplied wrapped_token_id;
    //  the adapter is not responsible for byte layout. This keeps
    //  the byte layout in exactly one place (the REPL command,
    //  mirroring BridgeChainRegistration::serializeState) rather
    //  than duplicated across every adapter.

    //  True if this adapter can be registered via BridgeRegisterChain.
    virtual bool supports_registration() const { return false; }

    //  The wrapped-token fingerprint this adapter's chain uses.
    //  Only meaningful if supports_registration() is true.
    virtual Crypto::Hash wrapped_token_fingerprint() const
    {
      return Crypto::Hash{};
    }

    //  The destination blob bounds this adapter enforces. Only
    //  meaningful if supports_registration() is true.
    //
    //  Defaults (1, 255) match a variable-length destination like
    //  a Bitcoin scriptPubKey. A fixed-length destination (CCX's
    //  64-byte spend‖view blob) overrides this to (64, 64).
    virtual std::pair<uint8_t, uint8_t> registration_blob_bounds() const
    {
      return {1, 255};
    }

    //  The minimum active validator set size for this chain to
    //  operate. Two is the BFT minimum; an adapter may raise it
    //  for a chain with a stricter quorum requirement.
    virtual uint32_t registration_active_validator_min() const
    {
      return 2;
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