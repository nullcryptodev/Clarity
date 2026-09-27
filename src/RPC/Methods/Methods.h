// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

namespace Rpc
{
  class JsonRpcDispatcher;

  void registerChainMethods(JsonRpcDispatcher &d);
  void registerTxMethods(JsonRpcDispatcher &d);
  void registerStateMethods(JsonRpcDispatcher &d);
  void registerMempoolMethods(JsonRpcDispatcher &d);
  void registerConsensusMethods(JsonRpcDispatcher &d);
  void registerAmmMethods(JsonRpcDispatcher &d);
  void registerOrderMethods(JsonRpcDispatcher &d);
  void registerNodeMethods(JsonRpcDispatcher &d);
  void registerAdminMethods(JsonRpcDispatcher &d);
}