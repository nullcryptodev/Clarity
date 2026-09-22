# State Testing Notes

State is the persistence layer. It wraps MDBX (via `StateDB`),
implements the sparse Merkle tree (`SparseMerkleTree`), provides the
semantic layer that other modules use to read and write accounts,
tokens, validators, pools, orders, and global state (`StateAccess`),
and produces verifiable proofs (`SmtProof`).

### Raw storage (`StateDBTests.cpp`, ~25 tests)

- `rawPut`, `rawGet`, `rawDel`, `rawHas` — round-trip, overwrite,
  delete, missing-key behavior.
- Empty values and large values (16 KiB).
- Meta helpers: `putMeta`, `getMeta`, `removeMeta`.
- Write transactions: commit persists, abort discards, RAII
  destructor aborts.
- `TxnSeesOwnWrites`, `TxnDelWithinTxn`, `TxnHas`, `TxnIsOpen`.
- `BeginWriteFailsWithActiveTxn` — one write txn per DB.
- `TxnPutAfterCloseThrows` — operations on a closed txn throw.
- Persistence across close/reopen.
- Iteration: `forEachEntry` visits all keys, stops on false.
- `entryCount`.

### Sparse Merkle tree (`SparseMerkleTreeTests.cpp`, ~40 tests)

- Empty tree root equals `defaultHash(DEPTH)`.
- Default hash chain recomputation matches the implementation.
- Insert, update, remove — each returns a deterministic root.
- **Order independence.** Two tests insert the same keys forward
  and reverse and expect the same root. This is what guarantees
  consensus across nodes that process transactions in different
  orders.
- Scale: 100 leaves, 1000 leaves, 100 leaves with half removed.
- Similar keys (differing only in the last bit) are distinguished.
- Empty values are distinct from missing keys.
- Batch updates produce the same root as sequential updates.
- Versioned roots: `save(version)` and `rootAtVersion(version)`.
- Persistence: root and leaves survive save → close → reopen →
  load.
- `readChildren` on empty root fails, on populated root succeeds,
  on unknown hash fails.

### Semantic layer (`StateAccessTests.cpp`, ~50 tests)

- Accounts: round-trip, missing, `accountExists`, `deleteAccount`,
  multiple independent accounts.
- **Staker totals** (`total_staked`, `staker_count`,
  `staker_since_height`): transition from non-staker to staker,
  stake increase, opt-out. These tests exercise the fix for the bug
  where reads and writes went to different stores.
- Token balances, token metadata (with and without fingerprint).
- Validators.
- Orders (round-trip, delete).
- AMM pools and positions.
- Receipts.
- Global state.
- Raw SMT access.
- State root: changes on write, deterministic for same writes.
- Autocommit mode (no txn bound).
- Staker index: index, iterate, unindex.

### Proofs (`SmtProofTests.cpp`, ~30 tests)

- Inclusion proofs at 1, 10, 100 leaves; with deeply shared key
  prefixes.
- Non-inclusion proofs in empty tree, populated tree, adjacent key.
- Proof against stale root fails.
- Tamper detection: each field of a proof (sibling, value, key,
  inclusion flag, sibling count) is tampered with and verified to
  fail.
- Serialization: round-trip, size matches, truncated input rejected,
  oversized value-size field rejected.
- Scale: 50 proofs from one tree, each verified.
- Update and remove: proof for a key before and after an update,
  each verifying against its own root.
- **Cross-check with StateAccess:** write through `StateAccess`,
  build an SMT from the same DB, prove the same key, verify the
  proof against the `StateAccess`'s state root.
- Key helpers: `ProofKeys::forAccount` agrees with `Keys::account`,
  and the same for token balances and globals. Different token IDs
  produce different keys.

## The boundaries this module has

State sits between three important sets of boundaries:

- **State ↔ MDBX.** `StateDB` wraps MDBX. A bug in the wrapper —
  byte order in keys, missing commits, transaction leaks — would
  manifest as silent data corruption.
- **State ↔ semantic layer.** `StateAccess` reads and writes
  global counters that must agree with the sum of what's stored per
  account (`total_staked`, `staker_count`, the staker index). The
  bug found this session lived exactly here — the reads and writes
  went to different stores.
- **State ↔ proof layer.** `SmtProof` verifies that a value exists
  at a path in the tree, and the root it verifies against must be
  the same root that `StateAccess::stateRoot()` returns. The
  `SmtProofTests.cpp` cross-check tests (`ProveAccountViaStateAccess`,
  `ProveGlobalViaStateAccess`) are the guard against a divergence.
