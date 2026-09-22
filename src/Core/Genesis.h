// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Block.h"
#include "Crypto/Types.h"

namespace State
{
  class StateAccess;
}

namespace Core
{
  //  Genesis
  //
  //  Defines the initial state of the chain. The genesis block is height 0,
  //  has no parent, no transactions, and a deterministic state root.
  //
  //  Called once at node startup:
  //    - If the DB is empty, write genesis state and save the genesis block
  //    - If the DB has state, verify it against the genesis state root
  //
  //  Genesis parameters are network-specific (mainnet, testnet, regtest).

  struct GenesisAccount
  {
    Crypto::Address address;
    uint64_t balance_atomic;
    std::string label; // informational only
  };

  struct GenesisValidator
  {
    uint64_t id;
    Crypto::Address reward_address;
    Crypto::PublicKey node_key;
    bool is_seed;
  };

  struct GenesisConfig
  {
    uint64_t chain_id{0};
    uint64_t timestamp_ms{0};
    std::vector<GenesisAccount> accounts;
    std::vector<GenesisValidator> validators;

    // Initial values for global state.
    uint64_t initial_total_supply{0};
    uint32_t initial_active_set_size{0};
  };

  //  Network configurations

  GenesisConfig mainnetGenesis();
  GenesisConfig testnetGenesis();
  GenesisConfig regtestGenesis();

  //  Application

  // Write genesis state to a fresh StateAccess.
  //
  // Idempotency: if the state already contains genesis (state_root matches
  // the expected value), this is a no-op. Otherwise, it writes the genesis
  // state on top of whatever is there.
  //
  // Callers should only call this on an empty DB, or after verifying that
  // the DB is at genesis.
  void applyGenesis(State::StateAccess &state, const GenesisConfig &config);

  // Construct the genesis block header for the given config, without
  // touching state. Useful for validation: nodes can compute the expected
  // genesis hash and compare it to the header of block 0 in their DB.
  BlockHeader makeGenesisHeader(const GenesisConfig &config);

  // Compute the expected state root after applying genesis.
  //
  // This requires an empty StateDB. The function writes the genesis state
  // to a temporary DB (in memory if possible), reads the resulting root,
  // and then discards the DB.
  Crypto::Hash computeGenesisStateRoot(const GenesisConfig &config);

  //  Verification

  // Verify that the given state root matches the expected genesis state root.
  // Used at startup to detect a corrupted or mis-configured DB.
  bool verifyGenesis(State::StateAccess &state, const GenesisConfig &config);

  // Construct the complete genesis block (header + empty tx list +
  // empty quorum signature list).
  //
  // MUST BE CALLED AFTER applyGenesis(state, config).
  //
  // Why the ordering matters:
  //   The block header contains a `state_root` field that commits to the
  //   entire chain state after this block is applied. For genesis, "after
  //   this block is applied" means "after the genesis state has been
  //   written". So we cannot build the block until the state exists.
  //
  // What this function does:
  //   1. Calls makeGenesisHeader(config) to build the skeleton header
  //      (height 0, null parent, no proposer, zero roots).
  //   2. Collects the seed validator IDs from config.validators and
  //      computes validator_set_root over them.
  //   3. Reads state.stateRoot() — the actual root produced by
  //      applyGenesis — and writes it into the header's state_root field.
  //   4. Sets tx_root and receipts_root to NULL_HASH (there are no
  //      transactions and no receipts in the genesis block).
  //   5. Leaves transactions and quorum_signatures empty.
  //
  // The resulting Block, once hashed via .hash(), is the canonical
  // genesis block. Every node on the same network MUST produce the
  // exact same hash, or the node refuses to start.
  //
  // Typical usage at node startup (fresh DB):
  //
  //   auto cfg = mainnetGenesis();
  //   applyGenesis(state, cfg);
  //   state.commit(0);
  //
  //   Block genesis = makeGenesisBlock(state, cfg);
  //   Crypto::Hash genesis_hash = genesis.hash();
  //
  //   storeBlock(genesis, genesis_hash);
  //
  // The genesis hash can optionally be hard-coded in a later version to
  // detect accidental changes to the genesis config before they cause
  // a chain fork.
  Block makeGenesisBlock(State::StateAccess &state, const GenesisConfig &config);

} // namespace Core