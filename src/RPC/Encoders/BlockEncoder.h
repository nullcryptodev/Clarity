#pragma once

#include "Common/Json.h"
#include "Core/Block.h"

namespace Rpc
{
  //  Block / BlockHeader -> JSON
  //
  //  The header is encoded flat (not nested under a "header" key) on
  //  blocks, because every client expects `block.height`, `block.hash`,
  //  etc. `header` is exposed as a separate method that returns just
  //  the header object, for callers that don't want the tx list.
  //
  //  `include_transactions`:
  //    true  — block.transactions is an array of full tx objects
  //    false — block.transactions is an array of tx hashes
  //
  //  Encoded block fields:
  //    hash              (0x-prefixed)
  //    version           (number)
  //    chain_id          (number, fits in uint32)
  //    height            (hex string)
  //    parent_hash       (0x-prefixed)
  //    timestamp_ms      (hex string)
  //    proposer          (Bech32m)
  //    epoch             (hex string)
  //    rotation_index    (hex string)
  //    commit_round      (hex string; NOT part of the hash — see
  //                       BlockHeader.h)
  //    state_root        (0x-prefixed)
  //    tx_root           (0x-prefixed)
  //    receipts_root     (0x-prefixed)
  //    validator_set_root(0x-prefixed)
  //    total_fees        (hex string)
  //    tx_count          (number)
  //    active_validator_count (number)
  //    transactions      (array; shape depends on include_transactions)
  //    participants      (array of hex-string validator ids)

  Common::Json encodeBlockHeader(const Core::BlockHeader &header,
                                 const std::string &hrp);

  Common::Json encodeBlock(const Core::Block &block,
                           bool include_transactions,
                           const std::string &hrp);
}