// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "Crypto/Types.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/KeyStore.h"
#include "Wallet/LocalSigner.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletTypes.h"

#include "ChainAdapter.h"
#include "WatcherConfig.h"

namespace Bridge
{
  // =========================================================================
  // ChainRuntime
  //
  // Per-chain mutable state for one enabled chain. One of these
  // exists for every chain the operator enabled; the map lives on
  // the session, keyed by the adapter's short_name ("ccx").
  //
  // The adapter itself (ChainAdapter) is stateless and shared.
  // ChainRuntime holds everything that is specific to this
  // watcher-of-this-chain: which heights it has processed, how
  // many deposits/withdrawals it has queued, whether it is
  // currently running.
  //
  // Field-by-field rationale:
  //
  // adapter shared_ptr — shared with other runtimes of
  // the same chain (there is at most one per
  // chain in v1, but the container allows more
  // so multi-watcher doesn't need a redesign).
  //
  // config the ChainWatcherConfig this runtime was
  // built from. Copied, not referenced: the
  // wizard may run again on the same session,
  // and re-reading a mutable field is how you
  // get heisenbugs.
  //
  // rpc per-chain Wallet::RpcClient pointed at the
  // adapter's daemon. Owned: it's cheap, and
  // shutting it down when the runtime is
  // destroyed is the correct lifetime.
  //
  // last_height cursors. Not persisted here — persistence
  // goes through state_subdir (TODO in this
  // batch: on-disk cursor persistence is v1.1
  // work, tracked but not implemented; for now
  // a restart rewinds the scan, which is
  // idempotent and correct).
  //
  // pending counters, not queues. The actual queues are
  // on disk under state_subdir; these are
  // cached counts for status output. On a
  // fresh session they read 0 until the first
  // scan populates them.
  //
  // enabled set by the wizard. A runtime with
  // enabled=false is inert: it never starts,
  // never scans, never shows in status. It
  // exists only because the wizard may pre-
  // populate a list and let the user confirm.
  //
  // running set by start/stop. Independent of
  // enabled — an enabled chain that hasn't
  // been started yet is "configured but idle".
  //
  // connected updated by the probe. May go stale; every
  // command that touches the chain re-probes.
  //
  // started_at a timestamp, for status ("running for
  // Xh Ym"). 0 means never started.
  // =========================================================================
  struct ChainRuntime
  {
    std::shared_ptr<ChainAdapter> adapter;
    ChainWatcherConfig config;

    std::unique_ptr<Wallet::RpcClient> rpc;

    uint64_t last_source_height{0};
    uint64_t last_clarity_height{0};

    uint64_t pending_deposits{0};
    uint64_t pending_withdrawals{0};

    bool enabled{false};
    bool running{false};
    bool connected{false};

    int64_t started_at{0};

    // Short name, cached so command output doesn't have to reach
    // through adapter (which may be null during teardown).
    std::string chain_short_name() const
    {
      return adapter ? adapter->short_name() : std::string{};
    }

    // Display name, cached similarly.
    std::string chain_display_name() const
    {
      return adapter ? adapter->name() : std::string{};
    }

    // Recreate the RPC client from the current config. Used by the
    // connect command and by the wizard when the operator
    // changes the endpoint.
    void reconnect()
    {
      Wallet::RpcEndpoint ep;
      ep.host = config.rpc_host;
      ep.port = config.rpc_port;
      rpc = std::make_unique<Wallet::RpcClient>(ep);
      connected = false;
    }
  };

  // =========================================================================
  // WatcherSession
  //
  // The state carried across commands in a single interactive
  // bridge-app session. Mirrors Wallet::WalletSession (see
  // Apps/Wallet/Session.h) in shape and conventions, with one
  // structural difference: instead of one RPC endpoint, it holds a
  // map of ChainRuntimes, one per enabled chain.
  //
  // Not persistent: each bridge-app invocation is a fresh session.
  // The keystore and the per-chain state directories are the only
  // things that survive across invocations.
  //
  // The current_chain field is the "selected" chain for commands
  // that act on one chain (deposits, withdrawals, start,
  // stop, rescan, state). status and chains ignore it
  // and report all chains. use <chain> changes it.
  // =========================================================================
  struct WatcherSession
  {
    // ---- Clarity RPC (one per session, not per chain) ----
    Wallet::RpcEndpoint clarity_endpoint;
    std::unique_ptr<Wallet::RpcClient> clarity_rpc;

    // True if the Clarity endpoint responded to the initial probe.
    // Set by the wizard; may go stale, every command that touches
    // Clarity re-checks.
    bool clarity_connected{false};

    // ---- Keystore (one per session, shared across all chains) ----
    //
    // Same five fields as Wallet::WalletSession, populated together
    // on open and cleared together on close. signer wraps
    // keystore, so it must be destroyed first.
    std::string keystore_path;
    std::unique_ptr<Wallet::KeyStore> keystore;
    std::unique_ptr<Wallet::LocalSigner> signer;
    std::optional<Crypto::Address> address;
    std::string address_bech32m;
    std::optional<Wallet::Network> network;

    // The watcher's id on Clarity. Resolved at startup from the
    // keystore's reward address (a Clarity RPC call, TODO until
    // the RPC exposes it), or supplied by the operator via
    // --watcher-id. 0 means unresolved.
    uint64_t watcher_id{0};

    // ---- Chains ----
    //
    // Keyed by the adapter's short_name ("ccx"). The map is
    // populated by the wizard before the REPL starts. Iteration
    // order is not guaranteed; commands that print chains sort
    // first (see chains and status).
    //
    // current_chain is the short_name of the selected chain.
    // Empty before the wizard runs; set by the wizard on success.
    // Commands that require a selection check it and error out if
    // empty.
    std::unordered_map<std::string, ChainRuntime> chains;
    std::string current_chain;

    // ---- Session state ----

    // Whether the REPL loop should continue. Set to false by the
    // exit and quit commands.
    bool running{true};

    // ---- Helpers ----

    // True if a keystore is open.
    bool hasKeystore() const noexcept { return keystore != nullptr; }

    // The current network, or Mainnet as a fallback.
    Wallet::Network currentNetwork() const noexcept
    {
      return network.value_or(Wallet::Network::Mainnet);
    }

    // Look up the currently selected chain. Returns nullptr if no
    // chain is selected or the name is stale. The pointer is
    // valid until the session's chains map is modified.
    ChainRuntime *current() noexcept;

    // Const overload.
    const ChainRuntime *current() const noexcept;

    // Look up a chain by short_name. Returns nullptr if not found.
    ChainRuntime *findChain(const std::string &short_name) noexcept;

    const ChainRuntime *findChain(const std::string &short_name) const noexcept;

    // Switch the current chain. Returns false (and leaves
    // current_chain unchanged) if the name is unknown or the
    // runtime is not enabled.
    bool selectChain(const std::string &short_name);

    // Enable a chain from the given adapter + config. Creates a
    // ChainRuntime and inserts it under the adapter's short_name.
    // If a runtime for that chain already exists, it is replaced
    // (the wizard runs once; commands like connect mutate the
    // existing runtime directly and do not call this).
    //
    // Returns a pointer to the newly-created runtime, or nullptr
    // on error (duplicate short_name with a different adapter is
    // a programming error — the registry guarantees uniqueness).
    ChainRuntime *enableChain(std::shared_ptr<ChainAdapter> adapter,
                              ChainWatcherConfig config);

    // Count how many chains are enabled. Used by the wizard's
    // summary banner and by chains.
    size_t enabledChainCount() const noexcept;

    // Number of enabled chains. Shorthand for the above.
    size_t chainCount() const noexcept { return enabledChainCount(); }

    // Enable a chain from its short_name by looking up the adapter
    // in the registry. Used by the CLI path (--chain ccx) and by
    // the wizard once the operator selects a chain. Returns
    // nullptr if the adapter isn't found in the registry, or if
    // the chain is already enabled and replace_existing is false.
    ChainRuntime *enableChainByShortName(const std::string &short_name,
                                         bool replace_existing = false);

    // Adapter defaults for a chain, without enabling it. Used by
    // the wizard to show "the defaults are X" before committing.
    // Returns std::nullopt if the adapter isn't found.
    std::optional<ChainWatcherConfig> defaultConfigFor(
        const std::string &short_name) const;

    // Clear the whole session. Called by main() on clean exit, and
    // by close (the command only closes the keystore; it doesn't
    // touch the chain runtimes).
    void reset();
  };

  // =========================================================================
  // Keystore open / close
  //
  // Same contract as Wallet::openKeystore / Wallet::closeKeystore,
  // with two differences:
  //
  // - openKeystore also attempts to resolve the watcher_id from
  // the Clarity node (via RPC), if the RPC is connected and
  // watcher_id == 0. If the RPC method doesn't exist yet, it
  // silently leaves watcher_id at 0.
  //
  // - openKeystore does NOT cross-check chain id. A Clarity
  // keystore is for the watcher's identity and for its own
  // BridgeAckWithdrawal submissions — it doesn't sign CCX
  // transactions and doesn't have a chain id to check.
  // =========================================================================
  bool openKeystore(WatcherSession &session,
                    const std::string &path,
                    const std::string &password_file);

  void closeKeystore(WatcherSession &session);

  // =========================================================================
  // Watcher-id resolution
  //
  // Ask the Clarity node for the watcher id associated with the
  // given reward address. Returns the id, or 0 if the RPC method
  // isn't available or the address isn't a registered watcher.
  //
  // This is exposed separately from openKeystore so info and
  // state can call it after the operator opens a keystore.
  // =========================================================================
  uint64_t resolveWatcherId(Wallet::RpcClient &clarity_rpc,
                            const Crypto::Address &address) noexcept;

  // =========================================================================
  // Chain runtime helpers
  //
  // Free functions that operate on a ChainRuntime. Kept separate
  // from the struct's methods so the session's map handling and
  // the per-runtime work don't get entangled.
  // =========================================================================

  // Create the RPC client and probe the endpoint. Returns true on
  // a successful probe. Updates runtime.connected and
  // runtime.rpc. Uses the adapter's probe_rpc, which for CCX
  // hits /getinfo.
  bool probeChain(ChainRuntime &runtime);

  // Apply the adapter's defaults to a config that's missing
  // fields. Used by enableChain to fill in the confirmation depth
  // and RPC endpoint for a chain that's being enabled by short_name
  // without CLI overrides. config is updated in place; missing
  // or zero fields are replaced with the adapter's defaults.
  void applyAdapterDefaults(ChainAdapter &adapter, ChainWatcherConfig &config);

} // namespace Bridge