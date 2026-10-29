// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Scan/ScanRegistry.h"

#include "Scan/ScanLoop.h"

#include "Session/Session.h"

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace Bridge
{
  namespace Scan
  {
    namespace
    {
      //  One running scan thread and the flag it polls. The
      //  shared_ptr<atomic<bool>> is shared between the registry
      //  and the thread, so the thread can outlive its map entry
      //  during stopScan (the join happens after the map entry
      //  has already been removed).
      struct ScanHandle
      {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> stop_requested;
      };

      std::mutex g_scans_mutex;
      std::map<std::string, ScanHandle> g_scans;
    } // anonymous namespace

    void startScan(WatcherSession &session, const std::string &chain_name)
    {
      std::lock_guard<std::mutex> lock(g_scans_mutex);

      if (g_scans.find(chain_name) != g_scans.end())
        return;

      //  Refresh the CCX deposit-destination cache before the scan
      //  thread is spawned. This is a no-op for Bitcoin (its
      //  refreshBridgeDeposits returns true immediately without
      //  touching state) and for any adapter that doesn't have a
      //  registration concept.
      //
      //  The cache lives on ChainRuntime and outlives the scan
      //  thread; refreshBridgeDeposits mutates it in place, so the
      //  adapter's non-owning pointer (installed in cmd_start via
      //  set_bridge_deposits_cache) stays valid and sees new
      //  registrations on subsequent refreshes without any
      //  re-installation.
      //
      //  A failed refresh is logged internally and does not abort
      //  the start — the scan thread runs with whatever cache was
      //  populated and its first poll will retry the refresh.
      if (ChainRuntime *rt = session.findChain(chain_name))
      {
        refreshBridgeDeposits(session, *rt);
      }

      auto stop = std::make_shared<std::atomic<bool>>(false);
      ScanHandle handle;
      handle.stop_requested = stop;
      handle.thread = std::thread(runScanLoop, &session, chain_name, stop);

      g_scans.emplace(chain_name, std::move(handle));
    }

    void stopScan(const std::string &chain_name)
    {
      std::thread to_join;
      {
        std::lock_guard<std::mutex> lock(g_scans_mutex);
        auto it = g_scans.find(chain_name);
        if (it == g_scans.end())
          return;

        it->second.stop_requested->store(true, std::memory_order_release);
        to_join = std::move(it->second.thread);
        g_scans.erase(it);
      }
      if (to_join.joinable())
        to_join.join();
    }

    void requestStopAllScans()
    {
      std::vector<std::thread> to_join;
      {
        std::lock_guard<std::mutex> lock(g_scans_mutex);
        for (auto &[name, handle] : g_scans)
        {
          (void)name;
          handle.stop_requested->store(true, std::memory_order_release);
          to_join.push_back(std::move(handle.thread));
        }
        g_scans.clear();
      }
      for (auto &t : to_join)
      {
        if (t.joinable())
          t.join();
      }
    }
  } // namespace Scan
} // namespace Bridge