// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "DepositRequest.h"

#include "Adapters/Bitcoin/BitcoinAdapter.h"

#include "Core/Bridge/Bitcoin.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"

#include <iostream>

namespace Bridge
{
  namespace
  {
    std::string encodeU64Hex(uint64_t v)
    {
      static const char HEX[] = "0123456789abcdef";
      if (v == 0)
        return "0x0";
      std::string out;
      bool started = false;
      for (int i = 15; i >= 0; --i)
      {
        const uint8_t nib = uint8_t((v >> (i * 4)) & 0xF);
        if (!started && nib == 0)
          continue;
        started = true;
        out.push_back(HEX[nib]);
      }
      return "0x" + out;
    }

    //  (No parseHexU64 here: hex decoding of the RPC response
    //  happens inside Wallet::getBridgeDepositsForAuthority,
    //  which returns typed integers. This file no longer sees
    //  hex fields, so it doesn't need a parser for them.)
  } // anonymous namespace

  DepositRequestResult handleDepositRequest(
      WatcherSession &session,
      const std::string &destination_bech32m,
      const std::string &authority_bech32m)
  {
    DepositRequestResult out;

    //  ---- Locate the BTC chain ----
    ChainRuntime *rt = nullptr;
    for (auto &[name, chain] : session.chains)
    {
      if (!chain.enabled || !chain.adapter)
        continue;
      if (chain.adapter->source_chain_id() ==
          Core::BitcoinBridge::BTC_CHAIN_ID)
      {
        rt = &chain;
        break;
      }
    }

    if (rt == nullptr)
    {
      out.error = "no Bitcoin chain enabled on this bridge";
      return out;
    }
    if (rt->btc_custody == nullptr)
    {
      out.error = "Bitcoin custody is not installed; has `start btc` "
                  "been run?";
      return out;
    }

    //  ---- Decode bech32m addresses ----
    auto dest_addr = Wallet::decodeAddress(
        destination_bech32m, session.currentNetwork());
    auto auth_addr = Wallet::decodeAddress(
        authority_bech32m, session.currentNetwork());
    if (!dest_addr.has_value())
    {
      out.error = "destination is not a valid rclrty1... address for "
                  "the current network";
      return out;
    }
    if (!auth_addr.has_value())
    {
      out.error = "authority is not a valid rclrty1... address for "
                  "the current network";
      return out;
    }

    //  ---- Fast path: cache lookup ----
    //
    //  refreshBridgeDeposits maintains
    //  rt->btc_deposit_index_by_authority, which is
    //  (authority, destination) -> index. It's fresh within
    //  SCAN_POLL_INTERVAL of any on-chain change, so the vast
    //  majority of calls hit here. The lookup is O(log n) and
    //  involves no RPC.
    {
      const auto key = std::make_pair(*auth_addr, *dest_addr);
      auto it = rt->btc_deposit_index_by_authority.find(key);
      if (it != rt->btc_deposit_index_by_authority.end())
      {
        const uint64_t index = it->second;
        std::string derr;
        auto addr = rt->adapter->deriveDepositAddress(index, &derr);
        if (!addr.has_value())
        {
          out.error = "could not derive deposit address at index " +
                      std::to_string(index) + ": " + derr;
          return out;
        }
        out.status = "ok";
        out.index_hex = encodeU64Hex(index);
        out.address = *addr;
        out.confirmation_depth_hex =
            encodeU64Hex(rt->config.confirmation_depth);
        return out;
      }
    }

    //  ---- Slow path: authoritative lookup via Clarity ----
    //
    //  The cache is populated from refreshBridgeDeposits, which
    //  pages over getBridgeDepositsForChain. If we miss in the
    //  cache, it's either because the registration is very new
    //  (confirmed after the last refresh), or because it doesn't
    //  exist. One direct RPC resolves both cases.
    //
    //  The wrapper returns:
    //    - nullopt + error_out set         -> transport/RPC failure
    //    - value with empty `deposits`     -> no registrations for
    //                                          this authority
    //    - value with non-empty `deposits` -> the authority's
    //                                          registrations; scan for
    //                                          the matching destination
    if (!session.clarity_rpc)
    {
      out.error = "no Clarity RPC client; cannot look up registrations";
      return out;
    }

    {
      std::string err;
      auto page = Wallet::getBridgeDepositsForAuthority(
          *session.clarity_rpc,
          Core::BitcoinBridge::BTC_CHAIN_ID,
          authority_bech32m,
          &err);

      if (!page.has_value())
      {
        out.error =
            "getBridgeDepositsForAuthority failed: " + err;
        return out;
      }

      uint64_t match_index = 0;
      bool found = false;
      for (const auto &d : page->deposits)
      {
        if (d.destination_bech32m != destination_bech32m)
          continue;
        //  If the authority has multiple registrations to the
        //  same destination (re-registering the same pair is
        //  allowed by the executor), pick the highest index.
        //  That matches the fast-path cache policy (last write
        //  wins) and it's what a user expects: the most recent
        //  registration is the "current" one.
        if (!found || d.index > match_index)
        {
          match_index = d.index;
          found = true;
        }
      }

      if (!found)
      {
        out.status = "not_registered";
        return out;
      }

      //  Populate the cache so subsequent calls hit the fast path
      //  even if the next refreshBridgeDeposits hasn't run yet.
      rt->btc_deposit_index_by_authority[std::make_pair(*auth_addr, *dest_addr)] = match_index;

      //  Make sure the custody window covers this index, so the
      //  scanner is watching it before the user sends.
      rt->btc_custody->ensureIndexInWindow(match_index);

      std::string derr;
      auto addr =
          rt->adapter->deriveDepositAddress(match_index, &derr);
      if (!addr.has_value())
      {
        out.error = "could not derive deposit address at index " +
                    std::to_string(match_index) + ": " + derr;
        return out;
      }

      out.status = "ok";
      out.index_hex = encodeU64Hex(match_index);
      out.address = *addr;
      out.confirmation_depth_hex =
          encodeU64Hex(rt->config.confirmation_depth);
      return out;
    }
  }
} // namespace Bridge