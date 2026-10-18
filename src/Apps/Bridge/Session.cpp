// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Session.h"

#include "ChainAdapter.h"
#include "WatcherConfig.h"

#include "Common/Base.h"
#include "Common/PasswordPrompt.h"
#include "Common/StringTools.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"

#include <chrono>
#include <iostream>
#include <string>

namespace Bridge
{

  namespace
  {
    void reportWalletError(const char *prefix, const Wallet::WalletStatus &st)
    {
      std::cerr << "error: " << prefix << ": ";
      if (!st.detail.empty())
        std::cerr << st.detail;
      else
        std::cerr << Wallet::walletErrorMessage(st.code);
      std::cerr << "\n";
    }

    bool parseEndpointSpec(const std::string &spec,
                           std::string &host_out,
                           uint16_t &port_out)
    {
      const size_t colon = spec.find(':');
      if (colon == std::string::npos || colon == 0 ||
          colon + 1 >= spec.size())
        return false;

      const std::string host = spec.substr(0, colon);
      const std::string port_str = spec.substr(colon + 1);

      char *end = nullptr;
      const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
      if (end == port_str.c_str() || *end != '\0' ||
          port == 0 || port > 65535)
        return false;

      host_out = host;
      port_out = static_cast<uint16_t>(port);
      return true;
    }
  } // anonymous namespace

  ChainRuntime *WatcherSession::current() noexcept
  {
    if (current_chain.empty())
      return nullptr;
    auto it = chains.find(current_chain);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  const ChainRuntime *WatcherSession::current() const noexcept
  {
    if (current_chain.empty())
      return nullptr;
    auto it = chains.find(current_chain);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  ChainRuntime *WatcherSession::findChain(const std::string &short_name) noexcept
  {
    auto it = chains.find(short_name);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  const ChainRuntime *WatcherSession::findChain(
      const std::string &short_name) const noexcept
  {
    auto it = chains.find(short_name);
    if (it == chains.end())
      return nullptr;
    return &it->second;
  }

  bool WatcherSession::selectChain(const std::string &short_name)
  {
    auto it = chains.find(short_name);
    if (it == chains.end())
      return false;
    if (!it->second.enabled)
      return false;
    current_chain = short_name;
    return true;
  }

  ChainRuntime *WatcherSession::enableChain(
      std::shared_ptr<ChainAdapter> adapter,
      ChainWatcherConfig config)
  {
    if (!adapter)
      return nullptr;

    const std::string short_name = adapter->short_name();

    applyAdapterDefaults(*adapter, config);

    ChainRuntime rt;
    rt.adapter = std::move(adapter);
    rt.config = std::move(config);
    rt.bridge_deposit_address = rt.config.bridge_deposit_address;
    rt.enabled = true;
    rt.reconnect();

    auto [it, inserted] = chains.insert_or_assign(short_name, std::move(rt));

    if (current_chain.empty())
      current_chain = short_name;

    return &it->second;
  }

  ChainRuntime *WatcherSession::enableChainByShortName(
      const std::string &short_name, bool replace_existing)
  {
    if (!replace_existing)
    {
      auto existing = chains.find(short_name);
      if (existing != chains.end() && existing->second.enabled)
        return &existing->second;
    }

    auto adapter = ChainAdapterRegistry::find(short_name);
    if (!adapter)
      return nullptr;

    ChainWatcherConfig cfg;
    cfg.chain_short_name = short_name;
    cfg.enabled = true;

    return enableChain(std::move(adapter), std::move(cfg));
  }

  std::optional<ChainWatcherConfig> WatcherSession::defaultConfigFor(
      const std::string &short_name) const
  {
    auto adapter = ChainAdapterRegistry::find(short_name);
    if (!adapter)
      return std::nullopt;

    ChainWatcherConfig cfg;
    cfg.chain_short_name = short_name;
    cfg.enabled = true;
    applyAdapterDefaults(*adapter, cfg);
    return cfg;
  }

  size_t WatcherSession::enabledChainCount() const noexcept
  {
    size_t n = 0;
    for (const auto &[name, rt] : chains)
    {
      (void)name;
      if (rt.enabled)
        ++n;
    }
    return n;
  }

  void WatcherSession::reset()
  {
    closeKeystore(*this);

    chains.clear();
    current_chain.clear();

    clarity_rpc.reset();
    clarity_endpoint = Wallet::RpcEndpoint{};
    clarity_connected = false;

    running = true;
    consensus_key.reset();
  }

  bool openKeystore(WatcherSession &session,
                    const std::string &path,
                    const std::string &password_file)
  {
    if (session.hasKeystore())
    {
      std::cerr << "error: a keystore is already open ("
                << session.keystore_path << "). Use 'close' first.\n";
      return false;
    }

    Wallet::WalletStatus st;
    auto ks = Wallet::EncryptedKeyStore::open(path, &st);
    if (!ks.has_value())
    {
      reportWalletError("cannot open keystore", st);
      return false;
    }

    std::string password;
    if (!password_file.empty())
    {
      auto pw = Apps::readPasswordFile(password_file);
      if (!pw.has_value())
      {
        std::cerr << "error: cannot read password file: "
                  << password_file << "\n";
        return false;
      }
      password = *pw;
    }
    else
    {
      auto pw = Apps::promptForPassword("Keystore password: ");
      if (!pw.has_value())
      {
        std::cerr << "error: could not read password\n";
        return false;
      }
      password = *pw;
    }

    const Wallet::WalletError err = (*ks)->unlock(password);
    if (!password.empty())
    {
      for (auto &c : password)
        c = '\0';
    }

    if (err != Wallet::WalletError::Ok)
    {
      Wallet::WalletStatus unlock_err =
          Wallet::WalletStatus::fail(err, "");
      reportWalletError("cannot unlock keystore", unlock_err);
      return false;
    }

    auto from_addr = Wallet::decodeAddress((*ks)->address(), (*ks)->network());
    if (!from_addr.has_value())
    {
      std::cerr << "error: keystore address is not decodable: "
                << (*ks)->address() << "\n";
      return false;
    }

    session.keystore_path = path;
    session.keystore = std::move(*ks);
    session.signer =
        std::make_unique<Wallet::LocalSigner>(*session.keystore);
    session.address = *from_addr;
    session.address_bech32m = session.keystore->address();
    session.network = session.keystore->network();

    std::cout << "Unlocked " << path
              << " (" << session.address_bech32m
              << ") — " << Wallet::networkName(session.currentNetwork())
              << "\n";

    if (session.watcher_id == 0 && session.clarity_rpc)
    {
      const uint64_t resolved =
          resolveWatcherId(*session.clarity_rpc, *session.address, *session.network);
      if (resolved != 0)
      {
        session.watcher_id = resolved;
        std::cout << "Watcher id: " << resolved << "\n";
      }
    }

    return true;
  }

  void closeKeystore(WatcherSession &session)
  {
    if (!session.hasKeystore())
      return;

    session.keystore->lock();

    session.signer.reset();
    session.keystore.reset();
    session.keystore_path.clear();
    session.address.reset();
    session.address_bech32m.clear();
    session.network.reset();
    session.watcher_id = 0;

    std::cout << "Keystore closed.\n";
  }

  uint64_t resolveWatcherId(Wallet::RpcClient &clarity_rpc,
                            const Crypto::Address &address,
                            Wallet::Network network) noexcept
  {
    try
    {
      const std::string bech32m = Wallet::encodeAddress(address, network);
      if (bech32m.empty())
        return 0;

      bool not_found = false;
      std::string err;
      auto res = Wallet::getBridgeWatcherIdByAddress(
          clarity_rpc, bech32m, &not_found, &err);

      if (not_found)
        return 0;
      if (!res.has_value())
        return 0;
      if (!res->is_object())
        return 0;
      if (!res->contains("watcher_id"))
        return 0;
      if (!(*res)["watcher_id"].is_string())
        return 0;

      const std::string s = (*res)["watcher_id"].get<std::string>();
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if (i >= s.size())
        return 0;

      uint64_t v = 0;
      for (; i < s.size(); ++i)
      {
        const char c = s[i];
        int nib;
        if (c >= '0' && c <= '9')
          nib = c - '0';
        else if (c >= 'a' && c <= 'f')
          nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
          nib = c - 'A' + 10;
        else
          return 0;
        v = (v << 4) | static_cast<uint64_t>(nib);
      }
      return v;
    }
    catch (...)
    {
      return 0;
    }
  }

  bool probeChain(ChainRuntime &runtime)
  {
    if (!runtime.adapter || !runtime.rpc)
    {
      runtime.connected = false;
      return false;
    }

    std::string error;
    const bool ok = runtime.adapter->probe_rpc(*runtime.rpc, &error);
    runtime.connected = ok;
    if (!ok && !error.empty())
    {
      std::cerr << " probe failed: " << error << "\n";
    }
    return ok;
  }

  void applyAdapterDefaults(ChainAdapter &adapter,
                            ChainWatcherConfig &config)
  {
    if (config.rpc_host.empty() || config.rpc_port == 0)
    {
      std::string host;
      uint16_t port = 0;
      if (parseEndpointSpec(adapter.default_rpc_endpoint(), host, port))
      {
        if (config.rpc_host.empty())
          config.rpc_host = host;
        if (config.rpc_port == 0)
          config.rpc_port = port;
      }
    }

    if (config.confirmation_depth == 0)
      config.confirmation_depth = adapter.default_confirmation_depth();

    if (config.state_subdir.empty())
      config.state_subdir = "state/" + adapter.short_name();
  }

} // namespace Bridge