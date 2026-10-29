// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ChainAdapter.h"

//  Include the concrete adapter headers directly. This is what
//  forces the linker to keep BitcoinAdapter.cpp.o and
//  ConcealCCX.cpp.o in the final executable even when the adapters
//  are compiled into a static library — referencing a symbol from
//  each header that resolves to a definition in the corresponding
//  .cpp.
#include "Bitcoin/BitcoinAdapter.h"
#include "Conceal/ConcealCCX.h"

namespace Bridge
{
  //  Register every chain adapter compiled into this binary.
  //
  //  Idempotent: ChainAdapterRegistry::registerAdapter replaces by
  //  short_name, so calling this when the adapter's static-init
  //  registrar has already run is a no-op (the same shared_ptr is
  //  replaced with an equivalent one).
  //
  //  Call this from the first line of main() and from any test
  //  main() that constructs a ChainAdapterRegistry-dependent
  //  fixture. See the comment in Apps/Bridge/CMakeLists.txt for
  //  why both this function and the BridgeAdapters::AlwaysLoad
  //  interface target exist.
  void registerAllChainAdapters()
  {
    ChainAdapterRegistry::registerAdapter(
        std::make_shared<BitcoinAdapter>());
    ChainAdapterRegistry::registerAdapter(
        std::make_shared<CcxAdapter>());
  }
} // namespace Bridge