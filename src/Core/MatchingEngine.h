// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Core/Fill.h"
#include "Core/Order.h"
#include "State/StateAccess.h"

namespace Core
{
  //  One taker's outcome. The caller (TransactionExecutor) uses this
  //  to know whether to write a receipt, and how to update the
  //  transaction's result.
  struct MatchOutcome
  {
    //  Fills, in execution order. Empty if the taker did not cross.
    std::vector<Fill> fills;

    //  True if the taker has a remainder resting in the book after
    //  matching. The caller does not need to do anything with this —
    //  MatchingEngine has already written the book row and the
    //  companion sequence key — but the field is useful for the
    //  caller's receipt-building logic and for tests.
    bool taker_rests{false};

    //  Sum of qty_quote across all fills. Convenience for the caller.
    uint64_t total_quote{0};

    //  Sum of qty_base across all fills. Convenience for the caller.
    uint64_t total_base{0};
  };

  //  Match a taker order against the resting book.
  //
  //  Preconditions:
  //    - `taker` is a valid Order.
  //    - `taker.mode == OrderExecutionMode::Passive`. Active orders
  //      route to the AMM and never reach this function; the caller
  //      is responsible for the dispatch.
  //    - `taker.owner` is set and non-null.
  //    - The taker's sell-token lock has already been taken by the
  //      caller (TransactionExecutor) when the order was created.
  //    - `state` is bound to the block processor's write txn.
  //
  //  Postconditions:
  //    - Every fill has been written through `state`: maker and
  //      taker balances updated, maker and taker order records
  //      updated, book index rows removed for fully-filled makers.
  //    - If the taker has a remainder, it has been added to the book
  //      with a fresh sequence, and `taker_rests` is true.
  //    - If the taker is fully filled, its order record has been
  //      deleted and the SMT leaf removed.
  //    - No state outside `state` has been touched.
  //
  //  Determinism:
  //    - No wall-clock, no entropy, no peer state.
  //    - Every sequence drawn from `state.nextOrderSequence()`, which
  //      is an SMT global.
  //    - Every write is SMT-unconditional; the dry-run path and the
  //      apply path produce identical state roots.
  MatchOutcome matchPassiveOrder(State::StateAccess &state,
                                 Order &taker,
                                 uint64_t height,
                                 uint32_t tx_index_in_block);
} // namespace Core