// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Session.h"

#include "Common/PasswordPrompt.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"

#include "Core/Bridge/ConcealCCX.h"
#include "Core/Bridge/Bitcoin.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>

namespace Bridge
{
  namespace
  {
    std::filesystem::path cursorFileFor(const ChainRuntime &rt)
    {
      return std::filesystem::path(rt.config.state_subdir) /
             rt.chain_short_name() / "cursor";
    }
  } // anonymous namespace

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
    session.keystore_password = password;
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

    std::fill(session.keystore_password.begin(),
              session.keystore_password.end(), '\0');
    session.keystore_password.clear();

    session.address.reset();
    session.address_bech32m.clear();
    session.keystore_path.clear();
    session.validator_id = 0;
    session.consensus_key.reset();
    session.custody_view_key.reset();

    std::cout << "Keystore closed.\n";
  }

  //  Helper: extract a 0x-prefixed hex uint64 from a JSON string.
  //  Returns std::nullopt on any parse failure.
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
        return 0;
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

  //  ===========================================================================
  //  refreshBridgeDeposits
  //
  //  Populate the per-chain deposit-destination cache from the
  //  chain's registration table (via Wallet::getBridgeDepositsForChain).
  //
  //  The cache shape depends on the chain:
  //
  //    CCX: keyed by the derived subaddress spend_pub. The scanner
  //         reverse-derives P - Hs(D, i)*G for each vout and looks
  //         up the result. See ChainRuntime::bridge_deposits_by_spend.
  //
  //    BTC: keyed by the registration index. The scanner matches a
  //         vout's scriptPubKey against BitcoinCustody's window
  //         (which yields the index), then looks up the destination
  //         here by index. See ChainRuntime::btc_deposit_cache.
  //
  //  Both caches live on ChainRuntime, both outlive the adapter's
  //  non-owning pointer, and both are populated by this function.
  //  A chain that is neither CCX nor BTC is a no-op (returns true):
  //  an adapter with no registration concept has no cache to fill.
  //
  //  Partial-success semantics: a registration whose record can't be
  //  parsed is skipped with a warning. The high-water mark is advanced
  //  only past registrations we successfully cached, so a subsequent
  //  call retries the failed ones. If a record is permanently
  //  malformed (a bug), the retry loop will spin — but the
  //  alternative is silently dropping the registration, which is
  //  worse.
  //  ===========================================================================
  bool refreshBridgeDeposits(WatcherSession &session,
                             ChainRuntime &rt)
  {
    if (!session.clarity_rpc || !rt.adapter)
      return false;

    const uint64_t chain_id = rt.adapter->source_chain_id();

    if (chain_id == Core::CcxBridge::CCX_CHAIN_ID)
    {
      if (!rt.bridge_custody_spend_pub.has_value() ||
          !rt.bridge_custody_view_priv.has_value())
      {
        std::cerr << "[" << rt.chain_short_name()
                  << "] refreshBridgeDeposits: custody keys not set "
                     "(bridge_deposit_address or view key missing)\n";
        return false;
      }

      const Wallet::Network net = session.currentNetwork();
      uint64_t from_index = rt.bridge_deposits_high_index + 1;

      for (;;)
      {
        std::string err;
        auto page = Wallet::getBridgeDepositsForChain(
            *session.clarity_rpc,
            Core::CcxBridge::CCX_CHAIN_ID,
            from_index,
            /*limit=*/1000,
            /*offset=*/0,
            &err);
        if (!page.has_value())
        {
          std::cerr << "[" << rt.chain_short_name()
                    << "] refreshBridgeDeposits: RPC failed: "
                    << err << "\n";
          return false;
        }

        if (page->deposits.empty())
          break;

        for (const auto &d : page->deposits)
        {
          auto dest = Wallet::decodeAddress(d.destination_bech32m, net);
          auto auth = Wallet::decodeAddress(d.authority_bech32m, net);
          if (!dest.has_value() || !auth.has_value())
          {
            std::cerr << "[" << rt.chain_short_name()
                      << "] refreshBridgeDeposits: bad address in "
                         "registration index "
                      << d.index << "\n";
            continue;
          }

          Crypto::PublicKey sub_spend, sub_view;
          if (!Core::CcxBridge::deriveSubaddress(
                  *rt.bridge_custody_spend_pub,
                  *rt.bridge_custody_view_priv,
                  Core::CcxBridge::CCX_CHAIN_ID,
                  d.index,
                  sub_spend, sub_view))
          {
            std::cerr << "[" << rt.chain_short_name()
                      << "] refreshBridgeDeposits: deriveSubaddress "
                         "failed for index "
                      << d.index << "\n";
            continue;
          }

          BridgeDepositCacheEntry entry;
          entry.index = d.index;
          entry.destination = *dest;
          entry.authority = *auth;
          entry.registered_at_height = d.registered_at_height;

          rt.bridge_deposits_by_spend[sub_spend] = entry;

          if (d.index > rt.bridge_deposits_high_index)
            rt.bridge_deposits_high_index = d.index;
        }

        if (page->deposits.size() < 1000)
          break;

        from_index = page->next_from_index;
      }

      std::string hdr_err;
      auto hdr = Wallet::getCurrentHeader(*session.clarity_rpc, &hdr_err);
      if (hdr.has_value())
        rt.bridge_deposits_cached_at_height = hdr->height;

      return true;
    }

    if (chain_id == Core::BitcoinBridge::BTC_CHAIN_ID)
    {
      if (rt.btc_custody == nullptr)
      {
        //  Custody not installed yet. This is not fatal — the
        //  scanner will refuse to scan without it, and cmd_start
        //  installs it before startScan — but logging it here makes
        //  the "why is nothing being minted" question answerable
        //  from a single log line.
        std::cerr << "[" << rt.chain_short_name()
                  << "] refreshBridgeDeposits: Bitcoin custody not "
                     "installed yet; skipping (no addresses to "
                     "watch)\n";
        return false;
      }

      //  We page from 0 every time rather than tracking a
      //  high-water mark: BTC registrations are indexed the same
      //  way CCX ones are, but the BTC scanner needs the full
      //  index -> destination map on every poll (the custody
      //  window can grow on demand, and a new index that
      //  appeared since the last refresh must be visible before
      //  the next scan). The table is bounded by
      //  MAX_BRIDGE_DEPOSITS_PER_CHAIN (100,000) and typical
      //  deployments will have orders of magnitude fewer. If
      //  this ever becomes a polling cost, add a
      //  btc_deposits_high_index field and page from there, same
      //  as CCX.
      const Wallet::Network net = session.currentNetwork();
      uint64_t from_index = 0;
      uint64_t highest_seen = 0;

      for (;;)
      {
        std::string err;
        auto page = Wallet::getBridgeDepositsForChain(
            *session.clarity_rpc,
            Core::BitcoinBridge::BTC_CHAIN_ID,
            from_index,
            /*limit=*/1000,
            /*offset=*/0,
            &err);
        if (!page.has_value())
        {
          std::cerr << "[" << rt.chain_short_name()
                    << "] refreshBridgeDeposits: RPC failed: "
                    << err << "\n";
          return false;
        }

        if (page->deposits.empty())
          break;

        for (const auto &d : page->deposits)
        {
          auto dest = Wallet::decodeAddress(d.destination_bech32m, net);
          if (!dest.has_value())
          {
            std::cerr << "[" << rt.chain_short_name()
                      << "] refreshBridgeDeposits: bad destination "
                         "address in BTC registration index "
                      << d.index << "\n";
            continue;
          }

          rt.btc_deposit_cache[d.index] = *dest;

          //  Also index by (authority, destination) so the
          //  deposit-address API can look up the index for a
          //  given user without an RPC. Auth is the authority's
          //  bech32m string; we decode it here to make the key
          //  type consistent with the deposit cache.
          {
            auto auth_addr = Wallet::decodeAddress(
                d.authority_bech32m, net);
            if (auth_addr.has_value())
            {
              rt.btc_deposit_index_by_authority[std::make_pair(*auth_addr, *dest)] = d.index;
            }
            else
            {
              std::cerr << "[" << rt.chain_short_name()
                        << "] refreshBridgeDeposits: bad authority "
                           "address in BTC registration index "
                        << d.index << "\n";
            }
          }

          //  Make sure the custody window covers this index, so
          //  the scanner is watching the corresponding script
          //  from the moment this refresh returns. Idempotent;
          //  a no-op for indices already in the window.
          if (!rt.btc_custody->ensureIndexInWindow(d.index))
          {
            std::cerr << "[" << rt.chain_short_name()
                      << "] refreshBridgeDeposits: could not extend "
                         "custody window for BTC index "
                      << d.index << "\n";
            //  Continue: the destination is cached, and the
            //  window will be retried next refresh. Holding the
            //  whole refresh on one derivation failure would
            //  stall every registration.
          }

          if (d.index > highest_seen)
            highest_seen = d.index;
        }

        if (page->deposits.size() < 1000)
          break;

        from_index = page->next_from_index;
      }

      std::string hdr_err;
      auto hdr = Wallet::getCurrentHeader(*session.clarity_rpc, &hdr_err);
      if (hdr.has_value())
        rt.bridge_deposits_cached_at_height = hdr->height;

      std::cerr << "[" << rt.chain_short_name()
                << "] refreshBridgeDeposits: BTC cache now has "
                << rt.btc_deposit_cache.size() << " entries, "
                << "highest index " << highest_seen << "\n";

      return true;
    }

    //  Chain has no registration concept; nothing to refresh.
    return true;
  }

  bool readChainCursor(const ChainRuntime &rt, uint64_t &out_height)
  {
    const std::filesystem::path file = cursorFileFor(rt);

    std::ifstream in(file);
    if (!in.good())
      return false;

    std::string line;
    if (!std::getline(in, line))
      return false;

    //  Trim trailing whitespace and any \r (Windows-style file
    //  transported to a Linux host).
    while (!line.empty() &&
           (line.back() == '\r' || line.back() == ' ' ||
            line.back() == '\t'))
      line.pop_back();

    if (line.empty())
      return false;

    //  Strict decimal parse. A malformed file is a hard "ignore
    //  the cursor" — we never guess.
    errno = 0;
    char *end = nullptr;
    const unsigned long long v = std::strtoull(line.c_str(), &end, 10);
    if (errno != 0 || end == line.c_str() || *end != '\0')
    {
      std::cerr << "[" << rt.chain_short_name()
                << "] cursor file " << file.string()
                << " is malformed; ignoring\n";
      return false;
    }

    out_height = static_cast<uint64_t>(v);
    return true;
  }

  bool writeChainCursor(const ChainRuntime &rt, uint64_t height)
  {
    const std::filesystem::path file = cursorFileFor(rt);

    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    if (ec)
    {
      std::cerr << "[" << rt.chain_short_name()
                << "] could not create cursor dir "
                << file.parent_path().string() << ": " << ec.message()
                << "\n";
      return false;
    }

    const std::filesystem::path tmp = file.string() + ".tmp";
    {
      std::ofstream out(tmp, std::ios::trunc);
      if (!out)
      {
        std::cerr << "[" << rt.chain_short_name()
                  << "] could not open " << tmp.string()
                  << " for writing\n";
        return false;
      }
      out << height << "\n";
      if (!out)
      {
        std::cerr << "[" << rt.chain_short_name()
                  << "] could not write " << tmp.string() << "\n";
        return false;
      }
    }

    std::filesystem::rename(tmp, file, ec);
    if (ec)
    {
      std::cerr << "[" << rt.chain_short_name()
                << "] could not rename " << tmp.string() << " to "
                << file.string() << ": " << ec.message() << "\n";
      return false;
    }

    return true;
  }
} // namespace Bridge