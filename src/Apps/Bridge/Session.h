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

    std::vector<uint8_t> bridge_deposit_address;

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

    std::string keystore_path;
    std::unique_ptr<Wallet::KeyStore> keystore;
    std::unique_ptr<Wallet::LocalSigner> signer;
    std::optional<Crypto::Address> address;
    std::string address_bech32m;
    std::optional<Wallet::Network> network;

    uint64_t watcher_id{0};

    std::optional<Crypto::SecretKey> consensus_key;

    std::optional<Crypto::SecretKey> custody_view_key;

    std::optional<Crypto::Address> mint_destination;

    std::unordered_map<std::string, ChainRuntime> chains;
    std::string current_chain;

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

  uint64_t resolveWatcherId(Wallet::RpcClient &clarity_rpc,
                            const Crypto::Address &address,
                            Wallet::Network network) noexcept;

  bool probeChain(ChainRuntime &runtime);

  void applyAdapterDefaults(ChainAdapter &adapter, ChainWatcherConfig &config);

} // namespace Bridge