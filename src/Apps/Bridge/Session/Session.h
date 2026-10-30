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

#include "../Adapters/ChainAdapter.h"
#include "../Adapters/Bitcoin/Custody.h"
#include "WatcherConfig.h"

namespace Bridge
{
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

    //  Human-readable form of the deposit address, as passed to
    //  --bridge-address on the start command. Authoritative 64-byte
    //  blob lives on the adapter. This string exists so cmd_status
    //  can display it. Empty until configured.
    std::string bridge_deposit_address;

    //  ---- Bridge deposit-destination cache ----
    //
    //  Populated by refreshBridgeDeposits when the chain is CCX.
    //  Keyed by the derived subaddress spend_pub, since that is
    //  what 6.4's reverse-derivation check uses: for an on-chain
    //  output pubkey P and per-tx derivation D, the scanner
    //  computes P - Hs(D, i)*G and looks up the result here.
    //
    //  The cache is owned by this ChainRuntime and outlives the
    //  adapter. The adapter holds a non-owning pointer installed by
    //  cmd_start via set_bridge_deposits_cache; subsequent
    //  refreshes mutate this map in place and the adapter sees the
    //  new entries on the next scan_deposits call without needing
    //  to be re-installed.
    BridgeDepositCache bridge_deposits_by_spend;

    //  Highest index the cache knows about. Used by
    //  refreshBridgeDeposits to page from this + 1.
    uint64_t bridge_deposits_high_index{0};

    //  Height at which the cache was last refreshed.
    uint64_t bridge_deposits_cached_at_height{0};

    //  The custody wallet's spend pubkey (from the parsed
    //  bridge_deposit_address's first 32 bytes) and its view
    //  private key (from session.custody_view_key). Both required
    //  for subaddress derivation. Only populated for CCX.
    //
    //  NOTE: bridge_custody_view_priv must be the *reduced scalar*
    //  (the output of sc_reduce32), not the ed25519 seed. The
    //  bridge scanner passes it to Crypto::generateKeyDerivation,
    //  which calls sc_check — a seed will fail and no deposits will
    //  be detected. If the operator's --view-key-file contains a
    //  seed, refreshBridgeDeposits will derive no subaddresses and
    //  the scanner will report "unresolved deposits" per poll
    //  forever. The config load should reject that at startup (see
    //  loadViewKeyFromFile in main.cpp).
    std::optional<Crypto::PublicKey> bridge_custody_spend_pub;
    std::optional<Crypto::SecretKey> bridge_custody_view_priv;

    //  Bitcoin custody: the per-runtime derived-address state.
    //  Populated by cmd_start when the chain's adapter is a
    //  BitcoinAdapter and its raw_json carries an xpub block.
    //  BitcoinAdapter holds a non-owning pointer to this, set via
    //  set_custody; see BitcoinCustody.h for why per-runtime.
    std::unique_ptr<BitcoinCustody> btc_custody;

    //  Bitcoin deposit cache: index -> destination, populated by
    //  refreshBridgeDeposits for BTC chains. The BitcoinAdapter
    //  holds a non-owning pointer (set_deposit_cache) exactly as
    //  CcxAdapter holds one to bridge_deposits_by_spend.
    std::map<uint64_t, Crypto::Address> btc_deposit_cache;

    //  (authority, destination) -> index, for the deposit-address
    //  API. Populated by refreshBridgeDeposits alongside
    //  btc_deposit_cache. Exists so the API can answer "what is
    //  the index for this user's destination?" without an RPC
    //  round-trip on every call.
    std::map<std::pair<Crypto::Address, Crypto::Address>, uint64_t>
        btc_deposit_index_by_authority;

    std::string chain_short_name() const
    {
      return adapter ? adapter->short_name() : std::string{};
    }

    std::string chain_display_name() const
    {
      return adapter ? adapter->name() : std::string{};
    }

    void reconnect()
    {
      Wallet::RpcEndpoint ep;
      ep.host = config.rpc_host;
      ep.port = config.rpc_port;
      ep.user = config.rpc_user;
      ep.password = config.rpc_password;
      rpc = std::make_unique<Wallet::RpcClient>(ep);
      connected = false;
    }
  };

  struct WatcherSession
  {
    Wallet::RpcEndpoint clarity_endpoint;
    std::unique_ptr<Wallet::RpcClient> clarity_rpc;
    bool clarity_connected{false};

    //  The password used to unlock `keystore`. Cached so the
    //  custody-key generator can encrypt its own file under the
    //  same password without re-prompting. Zeroed on close/reset.
    std::string keystore_password;
    std::string keystore_path;
    std::unique_ptr<Wallet::KeyStore> keystore;
    std::unique_ptr<Wallet::LocalSigner> signer;
    std::optional<Crypto::Address> address;
    std::string address_bech32m;
    std::optional<Wallet::Network> network;

    //  The daemon's validator id on Clarity. Resolved from the
    //  keystore address via getValidatorByAddress. Under the
    //  validator-is-watcher model this is the only identity the
    //  daemon needs: there is no per-chain watcher id, no separate
    //  watcher registration, and no separate watcher stake.
    //
    //  Cached for display only. The authoritative lookup is
    //  re-done for each attestation (see resolveValidatorId and
    //  resolveSignerIndex below) because the active validator set
    //  can rotate at epoch boundaries.
    uint64_t validator_id{0};

    std::unordered_map<std::string, ChainRuntime> chains;
    std::string current_chain;

    //  Consensus secret key for signing deposit attestations.
    //  Loaded by cmd_start or main.cpp.
    std::optional<Crypto::SecretKey> consensus_key;

    //  Custody wallet's private view key. Loaded by main.cpp from
    //  --view-key-file, handed to the adapter in cmd_start.
    //
    //  NOTE: must be the reduced scalar (sc_reduce32 output), not
    //  the ed25519 seed. See ChainRuntime::bridge_custody_view_priv.
    std::optional<Crypto::SecretKey> custody_view_key;

    //  Root state directory, expanded (no leading "~"). Set by
    //  main.cpp after expandHome(); used by cmd_start to place the
    //  Bitcoin custody file under <state_dir>/<chain>/, matching
    //  where the scan cursor lives. Empty until main.cpp sets it.
    std::string state_dir;

    //  Port the deposit-address HTTP API actually bound to, or 0
    //  if the API is disabled or the bind failed. Written once by
    //  main.cpp's startHttpApi() after a successful bind, read by
    //  cmd_status. Not atomic: written on the main thread before the
    //  REPL loop starts, read only from the REPL thread thereafter.
    uint16_t deposit_api_bound_port{0};

    //  Bind address the deposit-address HTTP API actually used, or
    //  empty if the API is disabled or the bind failed. Written by
    //  main.cpp's startHttpApi() alongside deposit_api_bound_port;
    //  read by cmd_status. Not cleared on keystore close/reset —
    //  it's process config, not session state.
    std::string deposit_api_bind;

    bool running{true};

    bool hasKeystore() const noexcept { return keystore != nullptr; }

    Wallet::Network currentNetwork() const noexcept
    {
      return network.value_or(Wallet::Network::Regtest);
    }

    ChainRuntime *current() noexcept;
    const ChainRuntime *current() const noexcept;

    ChainRuntime *findChain(const std::string &short_name) noexcept;
    const ChainRuntime *findChain(const std::string &short_name) const noexcept;

    bool selectChain(const std::string &short_name);

    ChainRuntime *enableChain(std::shared_ptr<ChainAdapter> adapter,
                              ChainWatcherConfig config);

    size_t enabledChainCount() const noexcept;

    size_t chainCount() const noexcept { return enabledChainCount(); }

    ChainRuntime *enableChainByShortName(const std::string &short_name,
                                         bool replace_existing = false);

    std::optional<ChainWatcherConfig> defaultConfigFor(
        const std::string &short_name) const;

    void reset();
  };

  bool openKeystore(WatcherSession &session,
                    const std::string &path,
                    const std::string &password_file);

  void closeKeystore(WatcherSession &session);

  //  Resolve the daemon's validator id from its reward address, at
  //  the current chain tip. Returns 0 if the address is not a
  //  registered validator (not an error on a chain that hasn't
  //  registered the daemon yet).
  //
  //  Takes the session's network so the bech32m encoding it does
  //  internally matches what the RPC handler compares against.
  uint64_t resolveValidatorId(Wallet::RpcClient &clarity_rpc,
                              const Crypto::Address &address,
                              Wallet::Network network) noexcept;

  //  Resolve the daemon's signer index: its position in the sorted
  //  active validator id list at `height`. Returns std::nullopt if
  //  the validator is not in the active set at that height.
  //
  //  Must be re-resolved for each attestation, not cached: the set
  //  rotates at epoch boundaries.
  std::optional<uint16_t> resolveSignerIndex(
      Wallet::RpcClient &clarity_rpc,
      uint64_t validator_id,
      uint64_t height) noexcept;

  bool probeChain(ChainRuntime &runtime);

  //  ---- Per-chain scan cursor persistence ----
  //
  //  The scan cursor is the highest source-chain height that has
  //  been fully processed. It is persisted so a restart resumes
  //  from where the last run left off, not from `start_height`
  //  every time. The file lives at
  //  <state_subdir>/<chain_short_name>/cursor and contains a
  //  single decimal integer followed by a newline.
  //
  //  Both functions return false only on I/O or parse errors that
  //  the caller cannot recover from by ignoring the cursor (a
  //  missing file, or a malformed file, are both "false" — the
  //  caller falls back to start_height).
  //
  //  Writes are atomic: the cursor is written to a temp file and
  //  renamed into place, so a crash mid-write leaves either the
  //  old value or the new value, never a partial line.
  bool readChainCursor(const ChainRuntime &rt, uint64_t &out_height);
  bool writeChainCursor(const ChainRuntime &rt, uint64_t height);

  void applyAdapterDefaults(ChainAdapter &adapter,
                            ChainWatcherConfig &config);

  //  Refresh the CCX deposit-destination cache on `rt` by fetching
  //  every registration from (last_cached + 1) onward via
  //  getBridgeDepositsForChain. No-op for non-CCX chains.
  //
  //  On success, populates rt.bridge_deposits_by_spend, updates
  //  rt.bridge_deposits_high_index and
  //  rt.bridge_deposits_cached_at_height, and returns true.
  //
  //  On any failure (missing custody keys, RPC error, bad address
  //  in a registration), returns false and leaves the cache in
  //  whatever partial state it reached. Partial state is
  //  consistent (each successfully-derived subaddress is in the
  //  map); only the high-water mark may need a re-fetch of the
  //  malformed entry.
  //
  //  This is called from ScanRegistry::startScan before the scan
  //  thread is spawned, and by the scan loop after each cache-miss
  //  detection. It is not called by refreshBridgeDeposits
  //  recursively.
  bool refreshBridgeDeposits(WatcherSession &session,
                             ChainRuntime &rt);

} // namespace Bridge