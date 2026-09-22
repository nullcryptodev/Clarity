# Clarity Testing Notes

Clarity uses `gtest` to perform its tests.

### Table of contents (~850+ tests)

- `Crypto` — hashes, signatures, AEAD (25 tests)
- `Common` — encodings, hex, JSON accessors, varints (55 tests)
- `Serialization` — binary, KV-binary, and JSON serializers (42 tests)
- `State` — MDBX wrapper, SMT, semantic state layer, proofs (145 tests)
- `Core` — block/transaction structure, execution, processing, rewards (485 tests)
- `Consensus` — BFT state machine, wire format, multi-validator (97 tests)
- `P2P` — framing, address book, ban list, manager under real sockets (69 tests)
- `Node` — configuration, lifecycle, end-to-end daemon assembly (54 tests)

Each module's `TESTING.md` describes what is tested, and
the boundaries the module has.

## How to run tests

```
cd build
cmake -DBUILD_TESTS=ON ..
make -j$(nproc)
./src/Tests/clarity_tests
```

## What gets tested, and how

The suite uses four shapes of test. Each shape catches a different
class of bug.

### 1. Known-answer tests

**Where:** `Tests/Crypto`, `Tests/Core/RewardCalculator.cpp`,
`Tests/Core/ValidatorRotation.cpp`.

A fixed input and a fixed expected output, usually taken from an
external reference (RFC 8032 for Ed25519, RFC 4648 for Base64, the
IEEE 802.3 polynomial for CRC32). If the test fails, the primitive is
wrong and everything downstream is wrong.

The most important known-answer tests in the codebase are the three
Blake2b vectors in `Tests/Crypto/Blake2b.cpp`. If any of them
fail, every block hash, transaction hash, state root, merkle root, and
receipt hash in the codebase is wrong.

### 2. Round-trip tests

**Where:** every module with a serializer.

`serialize` then `deserialize` then compare. This catches the class of
bug where the writer and reader agree within a test but the writer
produces bytes the reader rejects from a network peer or from disk.

Round-trip tests exist for:
- `Account`, `ValidatorInfo`, `TokenInfo`, `Receipt`, `AmmPool`,
  `AmmPosition`, `Order` (Core)
- `Block`, `BlockHeader`, `Transaction` (Core)
- `Proposal`, `Vote` (Consensus)
- `Message` with framing (P2P)
- `VersionMessage` and other control messages (P2P)
- `SmtProof` (State)
- Every primitive and composite type in `Tests/Types.h`

### 3. Boundary tests

**Where:** `Tests/Common`, `Tests/Core`, `Tests/State`.

Tests that hit a specific boundary: 0, 1, `MAX`, `MAX - 1`, the byte
that flips a varint to one more byte, the key that shares 255 bits of
prefix with another. These catch the class of bug where a computation
is correct in the interior and wrong at the edges.

Examples:
- Varint boundaries at `0x7F` / `0x80`, `0x3FFF` / `0x4000`, and
  `0xFFFFFFFFFFFFFFFF` (`Tests/Common/Varint.cpp`).
- SMT keys that differ only in the last bit
  (`Tests/State/SparseMerkleTree.cpp`).
- `bftQuorum` pinned at 4→3, 7→5, 11→8, 21→15, 100→67
  (`Tests/Core/ValidatorRotation.cpp`).
- Token supply minting at exactly `maxSupply`, then one more
  (`Tests/Core/TransactionExecutor.cpp`).

### 4. Integration tests

**Where:** `Tests/Node/NodeEndToEnd.cpp`,
`Tests/Consensus/MultiValidator.cpp`,
`Tests/P2P/P2PManager.cpp`.

Tests that assemble two or more modules and drive them together. These
are the tests that find bugs living at component boundaries — the
class of bug that every other test shape misses.

`NodeEndToEnd.cpp` is the most complete: it constructs multiple
`Node` instances, wires their consensus engines together, drives a
full BFT round, applies the committed block through the real block
processor, persists to the real state and chain databases, and reads
back after a restart.

`MultiValidator.cpp` exercises four `BftConsensus` instances in
one process through a message queue, covering quorum formation, fault
tolerance, equivocation, and determinism.

`P2PManager.cpp` opens real TCP sockets on loopback and drives
the handshake, message exchange, disconnect, and self-connection
rejection paths.

## What this policy buys

The suite is not exhaustive. It doesn't cover every edge case in
every function. It doesn't have fuzzers, property-based tests, or
sustained-load tests. It has known-answer tests for the primitives
that must be right, boundary tests for the arithmetic that must be
exact, round-trip tests for the encodings that must survive the wire,
and integration tests for the boundaries where components meet.

The bugs that reach production in a codebase like this one are
rarely the ones a unit test would have caught. They are the ones
that only appear when two correct components are wired together
incorrectly, or when a component is correct in isolation and wrong
under a specific sequence of operations that no single-component
test exercises. That's the class of bug the integration tests are
for, and it's the class of bug the fix-everything-with-a-test rule
is meant to eliminate over time.
