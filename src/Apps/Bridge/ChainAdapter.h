// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Wallet/RpcClient.h"

namespace Bridge
{
  //  =========================================================================
  //  ChainAdapter
  //
  //  The interface every source chain implements. The bridge app is
  //  built once and linked against a set of adapters; each adapter
  //  encapsulates everything that is chain-specific about observing
  //  deposits, submitting releases, and probing its node.
  //
  //  The app never touches source-chain RPC directly. It asks the
  //  adapter. Everything the app knows about a source chain comes
  //  through this interface, which means adding a new chain is
  //  implementing this class and registering it — no app changes.
  //
  //  The interface is intentionally narrow and data-oriented:
  //
  //    - Adapters are stateless across calls. Per-watcher mutable
  //      state (last heights, pending queues, etc.) lives in the
  //      app's ChainRuntime, keyed by source chain id. An adapter
  //      instance is shared across every watcher of that chain.
  //
  //    - Adapters throw BridgeError on unrecoverable failures. The
  //      app catches, logs, and reports to the operator. Recoverable
  //      failures return a Result with ok=false and a reason; the
  //      app decides whether to retry, skip, or pause.
  //
  //    - Adapters have no side effects except the ones the interface
  //      declares: submitting a release transaction (which is the
  //      only outbound mutation an adapter is allowed to perform),
  //      and probing the node. Deposit scanning is read-only.
  //  =========================================================================

  //  Raised by an adapter for unrecoverable failures (wrong RPC
  //  version, malformed daemon response on a call that should
  //  always succeed, etc.). The app catches and reports; the
  //  session may be paused or terminated depending on where it
  //  fires.
  class BridgeError : public std::runtime_error
  {
  public:
    explicit BridgeError(const std::string &what)
        : std::runtime_error("BridgeError: " + what) {}
  };

  //  A deposit observed on the source chain. The shape is the
  //  interface between the adapter and the app; it is not the
  //  adapter's internal record of the deposit.
  struct ObservedDeposit
  {
    //  Source chain id (matches the adapter's source_chain_id()).
    uint64_t source_chain_id{0};

    //  Source chain transaction hash and output index. Together
    //  these are the identity of the deposit; the pair is what the
    //  Clarity-side consumed-deposit guard keys on.
    Crypto::Hash source_tx_hash{};
    uint32_t source_output_index{0};

    //  Amount in source-chain atomic units (e.g. CCX has 1e6
    //  atomic units per coin). The app is responsible for the
    //  conversion to Clarity atomic units; the adapter never
    //  assumes a specific target scale.
    uint64_t amount_source_atomic{0};

    //  Source-chain block height the deposit was observed at.
    uint64_t block_height{0};

    //  Opaque destination blob. The adapter defines its format;
    //  the app treats it as bytes and forwards it unchanged in
    //  the Clarity-side BridgeBurn if the shape ever needs to be
    //  reverse-mapped (it doesn't in v1 — the deposit's blob is
    //  the source-side deposit metadata, not the Clarity
    //  destination; that's determined by the deposit address
    //  convention).
    std::vector<uint8_t> deposit_blob;
  };

  //  A withdrawal record read from Clarity. The app populates it
  //  from the Clarity RPC; the adapter consumes it to build the
  //  release transaction.
  struct ReleaseRequest
  {
    uint64_t withdrawal_id{0};
    uint64_t source_chain_id{0};

    //  Amount in Clarity atomic units. The adapter is responsible
    //  for converting to source-chain atomic units before
    //  building the release transaction.
    uint64_t amount_clarity_atomic{0};

    //  Opaque destination blob (from BridgeWithdrawal). The
    //  adapter knows how to decode it.
    std::vector<uint8_t> destination_blob;
  };

  //  The result of a release submission. Success is reported by the
  //  source chain's transaction id (opaque to the app); the app
  //  records it in the withdrawal's "submitted" state and hands it
  //  to the Clarity-side BridgeAckWithdrawal later.
  struct ReleaseSubmission
  {
    bool ok{false};
    std::string reason;            // populated if !ok
    Crypto::Hash source_tx_hash{}; // populated if ok
    uint64_t block_height{0};      // the height the release landed at
  };

  //  Discovery: what the adapter reports about the state of its
  //  chain, at scan time.
  struct ChainStatus
  {
    uint64_t current_height{0};
    uint64_t best_peer_height{0};
    bool reachable{false};
    std::string daemon_version;
  };

  //  =========================================================================
  //  The adapter interface.
  //
  //  A single adapter instance is created once at app startup and
  //  shared across every watcher of the same chain. It must be
  //  thread-safe for concurrent scan() calls (the app may have
  //  more than one watcher of the same chain when multi-watcher
  //  becomes real; v1 runs one watcher per chain, but the interface
  //  doesn't assume that).
  //  =========================================================================
  class ChainAdapter
  {
  public:
    virtual ~ChainAdapter() = default;

    //  Human-readable name, e.g. "Conceal CCX". Used in the
    //  wizard's adapter list and in `chains` output.
    virtual std::string name() const = 0;

    //  Short identifier, e.g. "ccx". Used as the per-chain
    //  subdirectory under the state directory and as the `use`
    //  target in the REPL.
    virtual std::string short_name() const = 0;

    //  The source_chain_id as seen by Clarity's bridge registry.
    //  This is the value that appears in BridgeChainRegistration
    //  and in the BridgeMint payload's source_chain_id field.
    virtual uint64_t source_chain_id() const = 0;

    //  Default RPC host:port for the source-chain daemon, used
    //  by the wizard as the prompt default.
    virtual std::string default_rpc_endpoint() const = 0;

    //  Default confirmation depth. The wizard uses this as the
    //  prompt default; the operator can raise it.
    virtual uint16_t default_confirmation_depth() const = 0;

    //  Decimal scale of the source chain (e.g. 6 for CCX). Used
    //  by the app to compute the conversion to Clarity atomic
    //  units when reporting deposit values to the operator.
    virtual uint8_t source_decimals() const = 0;

    //  Probe the adapter's RPC endpoint. Returns true if the
    //  endpoint is reachable and speaks a compatible protocol;
    //  false otherwise. Must not throw for network errors — those
    //  are what "unreachable" means — only for programming errors.
    virtual bool probe_rpc(Wallet::RpcClient &rpc,
                           std::string *error_out = nullptr) const = 0;

    //  Read the current chain status (height, best peer height,
    //  daemon version). Used for `status` output and for the
    //  startup probe. Throws BridgeError on malformed response
    //  from a reachable daemon.
    virtual ChainStatus fetch_status(Wallet::RpcClient &rpc) const = 0;

    //  Scan blocks [from_height, to_height] on the source chain,
    //  yielding every deposit addressed to the given bridge view
    //  address. The adapter knows how to interpret a source-chain
    //  block; the app does not.
    //
    //  The callback returns true to continue, false to stop early
    //  (used for `stop`). The adapter must be idempotent: scanning
    //  the same range twice yields the same deposits.
    virtual void scan_deposits(
        Wallet::RpcClient &rpc,
        const Crypto::PublicKey &bridge_view_pubkey,
        uint64_t from_height,
        uint64_t to_height,
        const std::function<bool(const ObservedDeposit &)> &on_deposit)
        const = 0;

    //  Submit a release transaction on the source chain, paying
    //  `amount_source_atomic` of the source asset to the destination
    //  blob's address, with `signature_block` (a source-chain
    //  format that the adapter defines) as authorization.
    //
    //  The app has already collected the signatures via its
    //  signing service and converted the amount; the adapter is
    //  responsible only for the chain-specific transaction
    //  construction and submission.
    virtual ReleaseSubmission submit_release(
        Wallet::RpcClient &rpc,
        const ReleaseRequest &request,
        uint64_t amount_source_atomic,
        const std::vector<uint8_t> &signature_block) const = 0;

    //  Convert a source-chain atomic amount to Clarity atomic
    //  units, using the on-chain registration's decimal scale.
    //  The adapter enforces the conversion direction and the
    //  rounding policy; the app never computes it.
    virtual uint64_t to_clarity_atomic(
        uint64_t amount_source_atomic,
        uint8_t clarity_decimals) const = 0;

    //  Convert a Clarity-atomic amount back to source-chain
    //  atomic units. Mirror of to_clarity_atomic.
    virtual uint64_t to_source_atomic(
        uint64_t amount_clarity_atomic,
        uint8_t clarity_decimals) const = 0;

    //  Validate a destination blob for BridgeBurn. The adapter
    //  knows the source chain's address format; the app forwards
    //  the blob from a BridgeBurn and asks the adapter whether
    //  it's well-formed. Returns true if the blob is a valid
    //  destination on this chain.
    virtual bool validate_destination(
        const std::vector<uint8_t> &destination_blob) const = 0;
  };

  //  =========================================================================
  //  ChainAdapterRegistry
  //
  //  The set of adapters compiled into (or discovered by) the
  //  running app. Populated at startup; the wizard reads it to
  //  offer the operator a menu.
  //
  //  The default `all()` returns every adapter linked into the
  //  binary. A future plugin-based discovery appends to this list;
  //  the app doesn't care which is which.
  //  =========================================================================
  class ChainAdapterRegistry
  {
  public:
    //  Return every adapter the app knows about, in a stable
    //  order (alphabetical by short_name).
    static std::vector<std::shared_ptr<ChainAdapter>> all();

    //  Look up an adapter by short_name. Returns nullptr if not
    //  found.
    static std::shared_ptr<ChainAdapter> find(const std::string &short_name);

    //  Register an adapter with the process-wide registry.
    //
    //  Called by each adapter .cpp's static registrar at startup.
    //  Idempotent by short_name: if an adapter with the same
    //  short_name is already registered, the new one replaces it.
    //  In practice each adapter registers exactly once and short
    //  names are unique, so replacement never happens at runtime —
    //  the idempotency is only a safety against static-init
    //  ordering surprises.
    //
    //  Returns true if the adapter was registered (either newly or
    //  as a replacement).
    static bool registerAdapter(std::shared_ptr<ChainAdapter> adapter);

  private:
    //  The set is built once and cached. Registered by
    //  registration in Bridge/CcxAdapter.cpp (and any future
    //  adapter .cpp) via a static initializer.
    static std::vector<std::shared_ptr<ChainAdapter>> &storage();
  };

} // namespace Bridge