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

    //  The validator's consensus signing key.
    //
    //  Placed at the END of the struct so existing brace-initializers
    //  of the form {id, reward_address, node_key, is_seed} continue to
    //  compile unchanged. Adding it before `node_key` would silently
    //  reassign the fields of every brace-init in Genesis.cpp and every
    //  test fixture.
    //
    //  Defaults to the zero key. When zero, applyGenesis writes the
    //  reward_address into ValidatorInfo::consensus_key — matching the
    //  pre-split convention where a validator's signing key was its
    //  reward address. Networks that want a distinct consensus key set
    //  this explicitly.
    Crypto::PublicKey consensus_key{};
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
  // Overwrite-safe, not check-safe. The function unconditionally writes
  // every account, validator, and global entry — it does not first check
  // whether the state already contains genesis. Calling it twice on the
  // same state produces the same result as calling it once, because every
  // write is an assignment (`balance = X`, `stake = Y`) rather than an
  // increment (`balance += X`). This is idempotency by construction, not
  // by a guard.
  //
  // If you change any write in this function from `=` to `+=`, calling it
  // twice stops being safe. Callers should still only call this on an
  // empty DB or after verifying the DB is at genesis.
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
  Block makeGenesisBlock(State::StateAccess &state, const GenesisConfig &config);

  // The expected genesis block hash for this network. Used at startup
  // to detect drift in genesis construction. See GlobalConfig.h for the
  // pinned values.
  Crypto::Hash expectedGenesisHash(const GenesisConfig &config) noexcept;
} // namespace Core