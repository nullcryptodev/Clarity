// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Session.h"

#include "Common/PasswordPrompt.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>

namespace Bridge
{
  ChainRuntime *WatcherSession::current() noexcept
  {
    if (current_chain.empty())
      return nullptr;
    auto it = chains.find(current_chain);
    if (it == chains.end() || !it->second.enabled)
      return nullptr;
    return &it->second;
  }

  const ChainRuntime *WatcherSession::current() const noexcept
  {
    if (current_chain.empty())
      return nullptr;
    auto it = chains.find(current_chain);
    if (it == chains.end() || !it->second.enabled)
      return nullptr;
    return &it->second;
  }

  ChainRuntime *WatcherSession::findChain(
      const std::string &short_name) noexcept
  {
    auto it = chains.find(short_name);
    if (it == chains.end() || !it->second.enabled)
      return nullptr;
    return &it->second;
  }

  const ChainRuntime *WatcherSession::findChain(
      const std::string &short_name) const noexcept
  {
    auto it = chains.find(short_name);
    if (it == chains.end() || !it->second.enabled)
      return nullptr;
    return &it->second;
  }

  bool WatcherSession::selectChain(const std::string &short_name)
  {
    if (!findChain(short_name))
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

    const std::string name = adapter->short_name();

    auto it = chains.find(name);
    if (it != chains.end() && it->second.enabled)
      return &it->second;

    ChainRuntime rt;
    rt.adapter = std::move(adapter);
    rt.config = std::move(config);
    rt.enabled = true;
    rt.reconnect();

    auto [inserted, ok] = chains.emplace(name, std::move(rt));
    if (!ok)
      return nullptr;
    return &inserted->second;
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

  ChainRuntime *WatcherSession::enableChainByShortName(
      const std::string &short_name,
      bool replace_existing)
  {
    auto adapter = ChainAdapterRegistry::find(short_name);
    if (!adapter)
      return nullptr;

    if (!replace_existing)
    {
      auto it = chains.find(short_name);
      if (it != chains.end() && it->second.enabled)
        return &it->second;
    }

    ChainWatcherConfig cfg;
    cfg.chain_short_name = short_name;
    cfg.enabled = true;
    applyAdapterDefaults(*adapter, cfg);

    return enableChain(adapter, cfg);
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

  void WatcherSession::reset()
  {
    for (auto &[name, rt] : chains)
    {
      (void)name;
      if (rt.running)
        rt.running = false;
    }

    chains.clear();
    current_chain.clear();

    if (signer)
      signer.reset();
    if (keystore)
    {
      keystore->lock();
      keystore.reset();
    }
    address.reset();
    address_bech32m.clear();
    keystore_path.clear();
    network.reset();
    validator_id = 0;
    consensus_key.reset();
    custody_view_key.reset();
    mint_destination.reset();

    if (clarity_rpc)
      clarity_rpc.reset();
    clarity_connected = false;

    running = true;
  }

  bool openKeystore(WatcherSession &session,
                    const std::string &path,
                    const std::string &password_file)
  {
    if (session.keystore)
    {
      std::cerr << "error: a keystore is already open; close it first\n";
      return false;
    }

    std::string password;
    if (!password_file.empty())
    {
      auto pw = Apps::readPasswordFile(password_file);
      if (!pw.has_value())
      {
        std::cerr << "error: cannot read password file '"
                  << password_file << "'\n";
        return false;
      }
      password = std::move(*pw);
    }
    else
    {
      auto pw = Apps::promptForPassword("Keystore password: ");
      if (!pw.has_value())
      {
        std::cerr << "error: password entry aborted\n";
        return false;
      }
      password = std::move(*pw);
    }

    if (password.empty())
    {
      std::cerr << "error: empty password\n";
      return false;
    }

    Wallet::WalletStatus open_st;
    auto ks = Wallet::openEncryptedKeyStore(path, &open_st);
    if (!ks.has_value())
    {
      std::cerr << "error: failed to open keystore: "
                << (open_st.detail.empty()
                        ? Wallet::walletErrorMessage(open_st.code)
                        : open_st.detail)
                << "\n";
      return false;
    }

    const Wallet::WalletError unlock_err = (*ks)->unlock(password);
    if (unlock_err != Wallet::WalletError::Ok)
    {
      std::cerr << "error: failed to unlock keystore: "
                << Wallet::walletErrorMessage(unlock_err) << "\n";
      return false;
    }

    const std::string bech = (*ks)->address();
    if (bech.empty())
    {
      std::cerr << "error: keystore has no address\n";
      (*ks)->lock();
      return false;
    }

    session.network = (*ks)->network();

    auto decoded = Wallet::decodeAddress(bech, session.currentNetwork());
    if (!decoded.has_value())
    {
      std::cerr << "error: keystore address is invalid bech32m: "
                << bech << "\n";
      (*ks)->lock();
      return false;
    }

    session.address = *decoded;
    session.address_bech32m = bech;
    session.keystore_path = path;
    session.keystore = std::move(*ks);
    session.signer = std::make_unique<Wallet::LocalSigner>(*session.keystore);

    if (session.clarity_rpc)
    {
      session.validator_id = resolveValidatorId(
          *session.clarity_rpc, *session.address, session.currentNetwork());
    }

    std::cout << "Keystore opened: " << session.address_bech32m << "\n";
    if (session.validator_id != 0)
      std::cout << "Validator id: " << session.validator_id << "\n";
    return true;
  }

  void closeKeystore(WatcherSession &session)
  {
    if (session.signer)
      session.signer.reset();

    if (session.keystore)
    {
      session.keystore->lock();
      session.keystore.reset();
    }

    session.address.reset();
    session.address_bech32m.clear();
    session.keystore_path.clear();
    session.validator_id = 0;
    session.consensus_key.reset();
    session.custody_view_key.reset();
    session.mint_destination.reset();

    std::cout << "Keystore closed.\n";
  }

  //  Helper: extract a 0x-prefixed hex uint64 from a JSON string.
  //  Returns std::nullopt on any parse failure. Local to this
  //  translation unit; the signer index resolution uses the same
  //  shape.
  namespace
  {
    std::optional<uint64_t> parseHexU64(const Common::Json &v)
    {
      if (!v.is_string())
        return std::nullopt;

      const std::string hex = v.get<std::string>();
      size_t i = 0;
      if (hex.size() >= 2 && hex[0] == '0' &&
          (hex[1] == 'x' || hex[1] == 'X'))
        i = 2;
      if (i == hex.size())
        return std::nullopt;

      uint64_t out = 0;
      for (; i < hex.size(); ++i)
      {
        const char c = hex[i];
        int nib = -1;
        if (c >= '0' && c <= '9')
          nib = c - '0';
        else if (c >= 'a' && c <= 'f')
          nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
          nib = c - 'A' + 10;
        if (nib < 0)
          return std::nullopt;
        out = (out << 4) | static_cast<uint64_t>(nib);
      }
      return out;
    }
  } // anonymous namespace

  uint64_t resolveValidatorId(Wallet::RpcClient &clarity_rpc,
                              const Crypto::Address &address,
                              Wallet::Network network) noexcept
  {
    try
    {
      const std::string bech = Wallet::encodeAddress(address, network);
      bool is_not_found = false;
      std::string err;

      auto res = Wallet::getValidatorByAddress(
          clarity_rpc, bech, &is_not_found, &err);
      if (is_not_found)
        return 0; // not a registered validator yet; not an error
      if (!res.has_value())
      {
        std::cerr << "resolveValidatorId: RPC failed: " << err << "\n";
        return 0;
      }

      const Common::Json &result = *res;
      if (!result.is_object() || !result.contains("id"))
        return 0;

      auto v = parseHexU64(result["id"]);
      return v.value_or(0);
    }
    catch (const std::exception &e)
    {
      std::cerr << "resolveValidatorId: exception: " << e.what() << "\n";
      return 0;
    }
  }

  std::optional<uint16_t> resolveSignerIndex(
      Wallet::RpcClient &clarity_rpc,
      uint64_t validator_id,
      uint64_t height) noexcept
  {
    try
    {
      std::string err;
      auto res = Wallet::getActiveSet(clarity_rpc, &err);
      if (!res.has_value())
      {
        std::cerr << "resolveSignerIndex: RPC failed: " << err << "\n";
        return std::nullopt;
      }

      const Common::Json &result = *res;
      if (!result.is_object() || !result.contains("ids") ||
          !result["ids"].is_array())
        return std::nullopt;

      std::vector<uint64_t> ids;
      ids.reserve(result["ids"].size());
      for (const auto &entry : result["ids"])
      {
        auto v = parseHexU64(entry);
        if (v.has_value())
          ids.push_back(*v);
      }

      std::sort(ids.begin(), ids.end());

      for (size_t i = 0; i < ids.size(); ++i)
      {
        if (ids[i] == validator_id)
          return static_cast<uint16_t>(i);
      }
      return std::nullopt;
    }
    catch (const std::exception &e)
    {
      std::cerr << "resolveSignerIndex: exception: " << e.what() << "\n";
      return std::nullopt;
    }
  }

  bool probeChain(ChainRuntime &runtime)
  {
    if (!runtime.adapter || !runtime.rpc)
      return false;

    try
    {
      const ChainStatus status =
          runtime.adapter->fetch_status(*runtime.rpc);
      runtime.connected = status.reachable;

      if (!status.reachable)
      {
        std::cerr << "[" << runtime.chain_short_name()
                  << "] probe failed: "
                  << (status.daemon_version.empty()
                          ? "(no detail)"
                          : status.daemon_version)
                  << "\n";
      }

      return status.reachable;
    }
    catch (const std::exception &e)
    {
      std::cerr << "[" << runtime.chain_short_name() << "] probe: "
                << e.what() << "\n";
      runtime.connected = false;
      return false;
    }
  }

  void applyAdapterDefaults(ChainAdapter &adapter,
                            ChainWatcherConfig &config)
  {
    if (config.rpc_host.empty())
    {
      const std::string ep = adapter.default_rpc_endpoint();
      const size_t colon = ep.find(':');
      if (colon != std::string::npos)
      {
        config.rpc_host = ep.substr(0, colon);
        config.rpc_port = static_cast<uint16_t>(
            std::strtoul(ep.c_str() + colon + 1, nullptr, 10));
      }
    }

    if (config.confirmation_depth == 0)
      config.confirmation_depth = adapter.default_confirmation_depth();

    if (config.state_subdir.empty())
      config.state_subdir = adapter.short_name();
  }

} // namespace Bridge