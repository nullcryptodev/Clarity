// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ChainAdapter.h"

#include <algorithm>
#include <mutex>

namespace Bridge
{

  // ===========================================================================
  // Registry storage
  //
  // The process-wide adapter list. Every adapter file has a
  // static registrar that calls ChainAdapterRegistry::registerAdapter
  // once, at static-init time, before main() runs.
  //
  // static locals are initialized on first use, so the storage
  // exists by the time the first registrar fires (registrars are
  // also static-init, but their call to registerAdapter is a
  // function call, which triggers the static local's initialization
  // before the call completes). The guard mutex is because
  // C++11/14/17 static-init across translation units is not
  // ordered; two registrars firing concurrently is theoretically
  // possible on some platforms even though it isn't on Linux/GCC,
  // and the guard makes the registration safe regardless.
  //
  // After all static-init has completed (i.e. before main()),
  // the vector is read-only. all() and find() take the lock to
  // read it, which is correct in the presence of late
  // registration (a future plugin loader) and cheap (an uncontended
  // mutex is a few ns).
  // ===========================================================================

  namespace
  {
    std::mutex &registryMutex()
    {
      static std::mutex m;
      return m;
    }

    std::vector<std::shared_ptr<ChainAdapter>> &registryVector()
    {
      static std::vector<std::shared_ptr<ChainAdapter>> v;
      return v;
    }
  } // anonymous namespace

  // Exposed to the class body (declared private in ChainAdapter.h).
  // Returns the underlying vector. Not callable from outside the
  // class; registerAdapter, all(), and find() are the public
  // surface.
  std::vector<std::shared_ptr<ChainAdapter>> &
  ChainAdapterRegistry::storage()
  {
    return registryVector();
  }

  bool ChainAdapterRegistry::registerAdapter(
      std::shared_ptr<ChainAdapter> adapter)
  {
    if (!adapter)
      return false;

    std::lock_guard<std::mutex> lock(registryMutex());
    auto &v = registryVector();

    const std::string name = adapter->short_name();
    if (name.empty())
      return false;

    // Idempotent by short_name: replace if present, else append.
    for (auto &existing : v)
    {
      if (existing->short_name() == name)
      {
        existing = std::move(adapter);
        return true;
      }
    }

    v.push_back(std::move(adapter));
    return true;
  }

  std::vector<std::shared_ptr<ChainAdapter>> ChainAdapterRegistry::all()
  {
    std::lock_guard<std::mutex> lock(registryMutex());

    // Copy under the lock so a future concurrent registerAdapter
    // can't invalidate the caller's iteration.
    auto out = registryVector();

    // Sort by short_name for deterministic ordering. The wizard
    // and chains output both benefit from this; the test suite
    // relies on it.
    std::sort(out.begin(), out.end(),
              [](const std::shared_ptr<ChainAdapter> &a,
                 const std::shared_ptr<ChainAdapter> &b)
              {
                if (!a)
                  return false;
                if (!b)
                  return true;
                return a->short_name() < b->short_name();
              });

    return out;
  }

  std::shared_ptr<ChainAdapter> ChainAdapterRegistry::find(
      const std::string &short_name)
  {
    std::lock_guard<std::mutex> lock(registryMutex());

    for (const auto &adapter : registryVector())
    {
      if (adapter && adapter->short_name() == short_name)
        return adapter;
    }
    return nullptr;
  }

} // namespace Bridge