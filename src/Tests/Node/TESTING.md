# Node Testing Notes

Node is the top of the dependency graph: it owns the state DB,
chain DB, mempool, P2P manager, and consensus engine, and drives them
through the block production and application lifecycle. The tests
here are the last layer of defense before a bug reaches production.

### Configuration (`ConfigTests.cpp`)

Every reject path in `NodeConfig::validateConfig` is covered:
empty data dir, block size bounds, zero tx count, poll interval
bounds, validator without a secret key. The chain-id fallback
(derive from network if zero) and the "don't override an explicit
chain id" behavior are pinned.

### Construction and pre-start state (`NodeTests.cpp`)

Construction with valid and invalid configs. Pre-start `status()`
reports `running == false`, height 0, chain id filled in, no
consensus. Pre-start `submitTransaction` fails cleanly. Pre-start
`stateRoot()` returns a null hash. `stop()` before start, `stop()`
twice, and the destructor without `start()` are all safe.

### Lifecycle and restart (`StartTests.cpp`)

Start, stop, restart on the same data dir. Genesis is applied on
first start; the second start skips it and recovers the state root
from disk. The state root after start matches
`computeGenesisStateRoot(regtestGenesis())`. Validator nodes
construct a consensus object; non-validators don't.

### Block application (`BlockTests.cpp`)

Applies blocks through `NodeTestAccess::applyBlock` (which calls
`Node::applyCommittedBlock`). Verifies height advance, head update,
state root update, persistence across restart, and rejection of
blocks with a corrupted state root or tx root. `StateRootChainAcrossBlocks`
applies three blocks in sequence and asserts that block N's recorded
state root matches the live state root after applying it.

### Full daemon assembly (`NodeEndToEndTests.cpp`)

The only file that assembles multiple `Node` instances and drives
consensus between them. Uses `NodeEndToEndFixture`, which builds
its own genesis config with controllable validator keys and its own
`BftConsensus` instances wired through a local message queue.

Nine tests:
1. Two validators commit one block.
2. Restart preserves the chain after a commit.
3. Four validators, one offline — three reach quorum, the block
   carries 4 participants and 3 signatures.
4. Four validators, two offline — no quorum, no commit.
5. A real signed transfer through submit → mempool → block →
   execution → balance update.
6. Committed transactions are removed from the mempool and cannot
   be replayed.
7. Two `StateView`s obtained in sequence are independently usable
   (regression for the previous thread_local bug).
8. State root and chain head agree after commit and after restart
   (invariant for the atomicity fix).
9. Consensus resumes correctly after a restart at height > 1.
10. Crash injection inside the txn leaves nothing persisted.

## The boundary this module has

Node touches every other module: Crypto for signatures, Core for
block processing, State for storage, Consensus for BFT, P2P for
network. Every boundary between `Node` and any of these is a place
a bug can hide. The class of bug that has appeared most often is
"the wrapped module works, the wiring to it doesn't" — the three
bugs above are all instances.

The end-to-end tests in `NodeEndToEndTests.cpp` are the guard
against this class. They are the only tests that assemble more than
one subsystem. When adding to `Node`, prefer tests that exercise
at least two subsystems through the `Node` interface — the raw
`NodeTestAccess::applyBlock` tests in `BlockTests.cpp` exercise
`Node` and `Core` together, which is why they catch things the
`Core` unit tests don't.