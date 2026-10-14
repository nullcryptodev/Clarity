# State

How Clarity commits to the state of the chain, how it stores that state, and how a node proves a fact about it.

This document describes the state layer from the bottom up: the storage engine, the Merkle tree that commits to the state, the access layer that the rest of the node uses, the proof system that lets a client verify a fact without trust, and the historical model that lets a node answer questions about the past. It is written for someone who needs to work on the state layer, extend it, or audit it.

## Table of contents

- [What state is](#what-state-is)
- [Storage](#storage)
  - [MDBX](#mdbx)
  - [The thirty-nine tables](#the-thirty-nine-tables)
  - [Single file](#single-file)
- [The compressed radix Merkle trie](#the-compressed-radix-merkle-trie)
  - [Node kinds](#node-kinds)
  - [Hash preimages](#hash-preimages)
  - [Default hashes](#default-hashes)
  - [Two invariants](#two-invariants)
  - [Insert, update, delete](#insert-update-delete)
  - [Height and write cost](#height-and-write-cost)
  - [Canonicity](#canonicity)
- [Key derivation](#key-derivation)
  - [Domain separation](#domain-separation)
  - [The namespaces](#the-namespaces)
  - [NFT custody addresses](#nft-custody-addresses)
- [StateAccess](#stateaccess)
  - [Two modes](#two-modes)
  - [Read dispatch](#read-dispatch)
  - [Write discipline](#write-discipline)
  - [The putX rule](#the-putx-rule)
- [Proofs](#proofs)
  - [The four terminal kinds](#the-four-terminal-kinds)
  - [Wire format](#wire-format)
  - [Verification](#verification)
  - [Generation](#generation)
  - [Key descriptors](#key-descriptors)
- [Versioning and historical reads](#versioning-and-historical-reads)
  - [What a version is](#what-a-version-is)
  - [Historical reads](#historical-reads)
  - [The four historical tables](#the-four-historical-tables)
- [The retention window](#the-retention-window)
  - [Why a window exists](#why-a-window-exists)
  - [How it works](#how-it-works)
  - [Where the window is set](#where-the-window-is-set)
  - [Pruning is atomic with the commit](#pruning-is-atomic-with-the-commit)
  - [Per-network defaults](#per-network-defaults)
- [The dry-run/apply invariant](#the-dry-runapply-invariant)
- [What state storage actually costs](#what-state-storage-actually-costs)
  - [Bounded components](#bounded-components)
  - [Unbounded components](#unbounded-components)
  - [Realistic sizes](#realistic-sizes)
- [What's not in this layer](#whats-not-in-this-layer)

## What state is

Clarity's state is the set of every persistent fact the chain knows: account balances, token metadata and balances, validator records and their key histories, orders, AMM pool reserves and LP positions, NFT records and collections, receipts, and a handful of named global values.

Every one of those facts is stored at a unique position in a **Merkle tree**. The root of that tree is a 32-byte hash called the **state root**. Every block header commits to the state root that results from applying the block. Any two nodes that agree on the entire contents of state will compute the same state root; any two nodes with different state produce different roots.

State is *not* the same thing as the chain. The chain is the sequence of blocks and their headers; the state is the set of facts those blocks have produced. The chain is append-only and grows forever; the state is a snapshot that changes with every block, and its *size* is bounded by what accounts, tokens, orders, and pools currently exist, not by how many blocks have been produced.

## Storage

### MDBX

State lives in an MDBX database. MDBX is a memory-mapped, ACID, single-writer / multi-reader key-value store; the same engine Bitcoin Core and Ethereum clients use for their chain and state databases. It offers MVCC snapshots, atomic multi-table transactions, and a per-table ordered cursor, all of which the state layer uses directly.

An MDBX environment is a single file on disk, memory-mapped into the process's address space. Reads go through the memory map and don't take a lock; writes are serialized by MDBX itself, and a write transaction is atomic across every table it touches. The state layer never opens a write transaction without knowing exactly which tables it will write to and what the invariant is across them.

### The thirty-nine tables

The environment contains thirty-nine named tables. They fall into five functional groups.

**SMT tables.** Six tables holding the Merkle tree itself:

- `smt_nodes` — the live internal nodes of the tree, keyed by node hash.
- `smt_leaves` — the live leaf values, keyed by leaf hash.
- `smt_nodes_hist` — the historical internal nodes, keyed by `(node_hash, version)`.
- `smt_leaves_hist` — the historical leaf values, keyed by `(leaf_hash, version)`.
- `smt_nodes_by_ver` — the by-version prune index for nodes, keyed by `(version, node_hash)`.
- `smt_leaves_by_ver` — the by-version prune index for leaves, keyed by `(version, leaf_hash)`.

The live tables are content-addressed: a node's row is keyed by its own hash, so re-writing the same node is an upsert, not a new row. The historical tables are keyed by `(hash, version)` and are deduplicated by content across versions — a node whose subtree didn't change between two versions is not re-stored at the second version.

**Entity tables.** The per-object records. Accounts, token balances, tokens, validators, orders, AMM pools, AMM positions, NFTs, NFT collections, receipts, blocks-by-hash, blocks-by-height, transactions-by-hash, the transaction index, the mempool, and the consensus WAL. These are the tables a reader scans to enumerate objects of a given kind.

**Index tables.** Enumerations used by RPC and by the state layer itself. Stakers, validators-by-id, order-expiry lists, orders-by-owner, orders-by-pair, orders-by-pool, balances-by-token, pools-by-token, positions-by-owner, transactions-by-address, transactions-by-token, transactions-by-type, blocks-by-producer. None of these participate in the state root — a node that never writes them still produces the same state root as one that does — but they make the state readable in ways the SMT alone doesn't allow.

**Application-specific tables.** The order book placement index (keyed by `pair_key || side || ~price || sequence`), the fill-history index (pair view and order view), the four NFT tables.

**Meta table.** `TBL_META` holds the current state root, per-version roots, the chain ID, the genesis hash, the fees-in-window counter, and a handful of other named values. It's the one table that isn't indexed by content; it's a bag of named entries.

### Single file

For v1, all thirty-nine tables live in a single MDBX file at `<data_dir>/state`. There is no separate chain database directory. Chain data — block indices, block bodies, receipts, the transaction index — shares the same file as state data.

This is a storage-layout decision, not a consensus-relevant one. Its motivation is atomicity: the block processor commits a block's transactions, the block's index entries, and the chain head update in a single MDBX write transaction. If chain data and state data were in separate files, that atomicity would have to be simulated with a two-phase commit. Keeping them together makes the invariant trivial: either the block and its state changes both commit, or neither does.

The trade-off is that MDBX's file-size accounting is per-environment, not per-table, so a naive read of the file size includes both the chain and the state. The metrics endpoint reports the total; per-table byte estimates are available through `mdbx_stat -a` and through `StateDB::tableStats`.

## The compressed radix Merkle trie

The tree is a **compressed radix Merkle trie** over 256-bit keys.

Keys are read one bit at a time, MSB first. A leaf sits at the end of a path; an internal node ("branch") sits at a point where two keys diverge. Path compression means that a chain of single-child internal nodes is collapsed into a single branch — the branch carries the shared prefix that all keys below it agree on, plus one branching bit, plus two children. There are no single-child internal nodes in a well-formed tree.

The result is that the tree's height is O(log N) in the number of leaves N, not the fixed 256 a non-compressed binary trie would require. A tree with a thousand leaves is about ten levels deep. A tree with a million leaves is about twenty.

### Node kinds

There are exactly three kinds of node:

**Leaf.** A key and a value hash.

```
leaf:
    key          32 bytes
    value_hash   32 bytes
```

The leaf's *value* is not part of the leaf; it's stored separately in `smt_leaves`, keyed by the leaf's hash. This separation lets the leaf's hash commit to the value without requiring the tree to hold the value bytes themselves — the tree stores 65-byte leaf preimages, and the value lives in a separate table.

**Branch.** A shared bit-prefix and two children.

```
branch:
    prefix_len       2 bytes (big-endian, 0..256)
    prefix_bits      ceil(prefix_len / 8) bytes, packed MSB-first
    left_hash        32 bytes
    right_hash       32 bytes
```

The two children are distinguished by the bit immediately following the prefix. If that bit is 0 the walk descends into `left_hash`; if 1 it descends into `right_hash`. The prefix bits and the branching bit together cover some number of key bits at the branch's position; the sum of these across a path from root to leaf equals the number of key bits consumed.

**Default.** The empty subtree at a given remaining depth. Represented by a precomputed hash. A default subtree is not a stored row; it's a *convention* — a specific 32-byte value that means "this subtree is empty". Two empty subtrees at the same depth always have the same hash.

The tree is sparse: most subtrees at most depths are empty, and are represented by their depth's default hash. A branch whose two children are both the default for their depth is itself the default for its own depth, so empty regions of the tree cost nothing to represent.

### Hash preimages

Every node kind has a distinct hash preimage, with a domain tag that makes cross-kind collisions impossible.

**Leaf hash.**

```
Blake2b(
    "leaf"        4 bytes
  || 0x00          1 byte
  || key           32 bytes
  || value_hash    32 bytes
)
```

**Branch hash.**

```
Blake2b(
    "brch"          4 bytes
  || 0x01            1 byte
  || prefix_len      2 bytes (big-endian)
  || prefix_bits     ceil(prefix_len / 8) bytes, trailing bits zeroed
  || left_hash       32 bytes
  || right_hash      32 bytes
)
```

**Default hash.**

```
defaultHash(0)     = Blake2b("dflt" || 0x02 || 0x0000)
defaultHash(d + 1) = Blake2b("dflt" || 0x02 || BE16(d + 1)
                             || defaultHash(d) || defaultHash(d))
```

The default-hash recursion has an important property: `defaultHash(d)` is the hash of an internal node whose two children are both `defaultHash(d - 1)`. This is what makes "a branch whose two children are both empty" *be* the empty subtree for the branch's depth, so the tree's sparse representation is exactly consistent with its hashing.

The tag `"leaf"`, `"brch"`, `"dflt"` are 4-byte ASCII strings, matching the convention used everywhere else in the codebase. The 1-byte tags `0x00`, `0x01`, `0x02` are the second layer of separation; a hash preimage for a leaf can never collide with a hash preimage for a branch, even if the payloads happened to align.

### Default hashes

There are 257 default hashes, one per depth from 0 to 256. They are computed once, lazily, on the first call to `defaultHash`. The computation is a `call_once` around a small loop; after the first call it's a table lookup.

The 257 entries are `defaultHash(0)` through `defaultHash(256)`. `defaultHash(0)` is the empty leaf; `defaultHash(256)` is the empty tree. A depth greater than 256 clamps to 256.

### Two invariants

The tree maintains two invariants that make it a canonical representation of a key set.

**Every branch consumes at least one bit.** A branch's prefix length plus one (the branching bit) is the number of key bits that branch consumes. Since prefix length is bounded by 256 and every descent consumes at least one bit, the height of a tree with N leaves is bounded by both 256 and by the number of distinct keys.

**No branch has a default child.** When one of a branch's children becomes default — as a result of a delete — the branch is *collapsed*: the branch is replaced by the surviving child with its prefix extended by the branch's prefix plus the branching bit. The result is that every branch in a well-formed tree has two non-default children.

These two invariants are what make the tree canonical. Two nodes with the same key set build the same tree, regardless of the order in which the keys were inserted.

### Insert, update, delete

The tree is walked recursively from the root. The recursion consumes key bits and descends until it reaches a leaf or the point where a new leaf belongs.

**Inserting a key into an empty subtree.** The empty subtree is replaced by a new leaf.

**Inserting a key that matches an existing leaf's key.** The leaf is replaced with a new leaf whose value hash reflects the new value. The tree's structure is unchanged.

**Inserting a key that differs from an existing leaf's key.** The two keys are compared to find the first bit where they differ. A new branch is created at that point, with the shared prefix, the branching bit, and the two leaves as children.

**Inserting a key whose path diverges from an existing branch's prefix.** The branch is split. A new branch is created at the divergence point, with the shared prefix up to that point, the branching bit, and two children: a new leaf for the inserted key, and the existing branch with its prefix shortened by the amount that was consumed by the new parent.

**Deleting a key.** The walk descends to the leaf, and the leaf is replaced by the default for its depth. On the way back up, any branch whose child is now default is collapsed into the surviving child, with the surviving child's prefix extended by the branch's prefix plus the branching bit.

The recursion tracks the remaining depth at each level, so prefix alignment is done relative to the current position, not from the start of the key. This is essential for correctness: a branch's stored prefix begins at its position in the key, not at bit 0.

### Height and write cost

For a tree with N leaves and uniformly distributed keys, the expected height is approximately `log2(N)`. A tree with 1,000 leaves is about 10 levels deep; a tree with 1,000,000 leaves is about 20.

Each `insert` or `delete` writes one row per level of the path it visits. In the worst case (a delete that triggers a collapse at every level) that's O(height) rows; in the typical case it's a bit more than O(height), because an insert that splits a leaf writes the new leaf, the new branch, and re-writes the old leaf.

For a tree with N leaves, an insert writes O(log N) rows. That's the fundamental cost property the tree was chosen for.

The tree also stores a per-node copy in the historical tables when writing at a non-zero version, so the historical cost per update is also O(log N).

### Canonicity

The tree's root is a pure function of its key set. Two nodes with the same accounts, tokens, orders, pools, and NFTs produce the same root, regardless of the order in which those objects were created or how many times they were updated.

This property is not accidental — it's the reason the tree is a radix trie rather than a sorted-list Merkle tree. A sorted-list Merkle tree has the same asymptotic proofs (O(log N) siblings) but its root depends on the *order* of the list, which is fine for a fixed set but a disaster for a state that's built by a stream of transactions. A radix trie's structure is determined by the keys' bits, so the same set of keys produces the same tree.

Canonicity is what makes the dry-run/apply invariant hold. A dry-run walks the same key set as an apply, using the same invariants, and produces the same root. If the tree weren't canonical, a dry-run and an apply would produce different roots and the proposer's block would be rejected by every other node.

## Key derivation

Every state object is keyed by a 32-byte hash derived from its identity. The derivation is `Blake2b(domain4 || payload)` where `domain4` is a 4-byte ASCII string and `payload` is the identifier for the object.

The 4-byte domain string prevents two different object kinds from ever colliding: an account address and a validator ID could hash to the same 32 bytes in principle, but their domain tags are different, so the keys are different. This is the same pattern used for the tree's node hashes, and it makes every key in the tree a `Blake2b` of a structured input.

### Domain separation

Every domain tag is exactly four bytes. Some end in a space to make the tag legible in hex dumps.

| Domain | Used for |
|---|---|
| `"acct"` | Account records, keyed by address |
| `"bal "` | Token balances, keyed by `(address, token_id)` |
| `"tok "` | Token metadata, keyed by token ID |
| `"tsup"` | Cumulative minted supply, keyed by token ID |
| `"val "` | Validator records, keyed by validator ID |
| `"vadr"` | Validator-by-address index, keyed by reward address |
| `"ord "` | Order records, keyed by order ID |
| `"oexh"` | Order expiry lists, keyed by expiry height |
| `"glob"` | Global state values, keyed by name (up to 64 bytes) |
| `"pool"` | AMM pool records, keyed by pool ID |
| `"pos "` | AMM position records, keyed by position ID |
| `"pidx"` | LP position index, keyed by `(owner, pool_id)` |
| `"rcpt"` | Receipts, keyed by transaction hash |
| `"oseq"` | Order-book sequence companion, keyed by order ID |
| `"vkey"` | Validator key-history companion, keyed by validator ID |
| `"nft "` | NFT records, keyed by NFT ID |
| `"ncol"` | NFT collection records, keyed by collection ID |

Once a domain tag is deployed, it must never change. Changing a tag would move every key in that namespace, orphaning the state it references.

### The namespaces

Each domain tag defines a namespace. The namespaces are independent: two objects in different namespaces can share an identifier (for example, a token ID and an order ID can both be 42) without their keys colliding.

Within a namespace, the payload identifies the object. For `"acct"`, the payload is the 32-byte address. For `"bal "`, the payload is the 32-byte address followed by the 4-byte little-endian token ID. For `"val "`, the payload is the 8-byte little-endian validator ID.

Payloads are little-endian because they're used as MDBX keys in a few places and little-endian is the codebase's convention for on-disk integers. This has no effect on the tree, which reads keys one bit at a time and is indifferent to endianness; it just makes the keys match what `Common::readU64` and its relatives expect if a caller ever needs to decode one.

### NFT custody addresses

A wrapped NFT holds an underlying balance at a virtual address derived from the NFT's ID:

```
Keys::nftAddress(nft_id) = Blake2b("nfa " || LE(nft_id))
```

The address is in the same 32-byte space as real Ed25519 public keys. This is deliberate: the token-balance table keys on address bytes, so the custody is an ordinary balance at an address the balance table has never heard of before. A client that wants to see a wrapped NFT's underlying amount calls `getBalance(nftAddress(id), token_id)`, the same call it makes for any other address.

NFT collections have a similar virtual address for their reward escrow:

```
Keys::nftCollectionAddress(collection_id) = Blake2b("nca " || LE(collection_id))
```

Same idea, different domain tag, so a collection's escrow and its NFTs' custody can never collide.

## StateAccess

`StateAccess` is the typed façade the rest of the node uses. It sits over the MDBX environment and the tree, and it exposes methods for the entities the chain has: `getAccount`, `putAccount`, `getToken`, `putToken`, `getValidator`, `putValidator`, `getOrder`, `putOrder`, and so on.

Every read that touches the tree goes through the tree's `get`, which walks from the current root down to the leaf. Every write goes through the tree's `update` or `remove`, which walks from the root down to the leaf and recomputes every hash on the way back up. The typed methods serialize and deserialize the records at each position; the tree only sees byte blobs.

### Two modes

`StateAccess` exists in two modes.

**Txn-bound mode.** The `StateAccess` was constructed over an existing MDBX write transaction, and every read and write goes through that transaction. The transaction is not owned by the `StateAccess`; the caller opened it, and the caller commits or aborts it. This is the mode the block processor uses: it opens one write transaction per block, wraps it in a `StateAccess`, applies the block's transactions, and commits the transaction at the end. Every read sees the transaction's own uncommitted writes; every write participates in the transaction's eventual commit or abort.

**Autocommit mode.** The `StateAccess` owns a single MDBX *read* transaction for its lifetime, and read methods route through it. Write methods on an autocommit `StateAccess` call `releaseReadTxnIfHeld` first — which destroys the held read transaction — and then open their own write transaction for the duration of the write. The next read after the write transparently opens a fresh read transaction.

Autocommit mode is what makes a tree walk cheap. A walk visits a dozen or so nodes, and each node read is a key-value lookup in MDBX. If every read opened its own read transaction, the walk would hold a dozen reader slots in sequence, and under concurrent RPC load the reader table could be exhausted. Holding one read transaction for the lifetime of the `StateAccess` means the entire walk is one reader.

### Read dispatch

A read method on `StateAccess` dispatches in order:

1. **Bound write transaction.** If the `StateAccess` was constructed in txn-bound mode, the read goes through the write transaction. The write transaction sees its own uncommitted writes, so a value written earlier in the same transaction is visible on the next read.

2. **Held read transaction.** If the `StateAccess` was constructed in autocommit mode and holds a read transaction, the read goes through it. This is the normal RPC path.

3. **Raw DB access.** If neither of the above applies, the read goes through `StateDB`'s raw accessors. `StateDB` itself checks a per-thread handle before opening a fresh read transaction, so a nested read from inside a `forEach` visitor reuses the outer iteration's transaction instead of trying to open a second one.

The dispatch is invisible to the caller. A single `StateAccess` can serve a read, then a write, then another read, and each call sees the right snapshot without the caller having to know about the underlying MDBX constraints.

### Write discipline

MDBX forbids opening a write transaction on a thread that already has a read transaction open. The state layer respects this with a discipline that's enforced at the write paths.

Every write method on `StateAccess` calls `releaseReadTxnIfHeld` before it does anything else. That method destroys the held `ReadTxn` (if any) and unbinds it from the tree. The next read after the write transparently acquires a fresh `ReadTxn`. The result is that a `StateAccess` in autocommit mode can interleave reads and writes freely, and each transition is handled by the `StateAccess` itself.

The discipline is a small cost — one extra transaction open/abort per read-write transition — but it makes the common case (read a value, write a value, read another value) work without the caller having to know that a write can't overlap a read.

### The putX rule

Every `putX` method on `StateAccess` is a pure write. It reads nothing before it writes.

This rule is not stylistic. A read inside a write path interleaves with the tree's content-addressed node update buffer in a way that can cause a subsequent update in the same or a later transaction to be computed against a stale root and silently dropped. The exact mechanics are subtle: the tree's update recursion is stateful across a single call, and a read between writes can leave the recursion with a stale view of the subtree it's about to modify.

The rule is enforced by construction: `putX` methods are pure writes, and callers that need to clean up an old record's index rows do so by reading the old record first and then calling a dedicated unindex method before the new put. For example, `TransferNft` reads the old `NftInfo`, calls `unindexNft(old)` to remove the old owner's index row, and then calls `putNft(new)` to write the new record and index.

The rule is documented on every `putX` method so a future change doesn't reintroduce the read-inside-write pattern.

## Proofs

A Merkle proof for a key is a list of sibling hashes, from the deepest branch on the key's path up to the root, plus a description of what the walk terminated on. Verification recomputes the root from the proof and compares; if the recomputed root matches the expected root, the proof is valid.

Proofs are a pure-function construction. `verifyProof(expected_root, proof)` performs no database access and no signature checks. A caller that holds only the state root can verify a proof without trusting the server that produced it. This is what makes light clients possible.

### The four terminal kinds

A proof's walk terminates at one of four things, and the proof carries an explicit descriptor for which one.

**Inclusion.** The walk reached a leaf whose key matches the proven key. The proof carries the value at that leaf. Verification hashes `(key, value)` to get the leaf hash, then walks up.

**Default.** The walk reached an empty subtree at some remaining depth. The proof carries no value, and the depth is derivable from the sibling list: the sum of `(prefix_len + 1)` over all siblings plus the terminal depth equals 256. Verification computes `defaultHash(depth)` and walks up.

**Different leaf.** The walk reached a leaf whose key is not the proven key. The proof carries the divergent leaf's key and value hash. Verification hashes `(divergent_key, divergent_value_hash)` to get the leaf hash, then walks up.

**Divergent branch.** The walk reached a branch whose prefix the proven key does not share. The proof carries the branch's prefix (length and bits) and both children's hashes. Verification computes the branch hash from those, then walks up.

The four kinds are necessary because the compressed tree's walk can stop at any of them, and each has different identifying information. An earlier design with only "inclusion or non-inclusion" couldn't distinguish the two kinds of non-inclusion that carry different data, and produced proofs that failed verification for the divergent-branch case. The explicit terminal descriptor fixes that.

### Wire format

```
proof:
    key                         32 bytes
    terminal_kind                1 byte  (0 = Inclusion, 1 = Default,
                                          2 = DifferentLeaf, 3 = DivergentBranch)
    terminal payload             (depends on kind)
    sibling_count                1 byte  (0..256)
    siblings                     sibling_count * variable

terminal payload for Inclusion:
    value_len                    4 bytes (little-endian)
    value                        value_len bytes

terminal payload for Default:
    (nothing; the depth is derivable)

terminal payload for DifferentLeaf:
    divergent_leaf_key          32 bytes
    divergent_leaf_value_hash   32 bytes

terminal payload for DivergentBranch:
    prefix_len                   2 bytes (big-endian)
    prefix_bits                  ceil(prefix_len / 8) bytes
    left_hash                   32 bytes
    right_hash                  32 bytes

sibling:
    prefix_len                   2 bytes (big-endian)
    prefix_bits                  ceil(prefix_len / 8) bytes
    sibling_hash                32 bytes
```

The wire format is self-describing and rejects trailing bytes. A proof's total length must equal exactly what its field values imply; any surplus is a decode failure. This prevents a future format extension from being silently read as a shorter proof with garbage past the end.

The sibling count is a `u8` capped at 256. A proof claiming more than 256 siblings is rejected before any allocation, so a hostile peer can't cause an unbounded allocation with a fake count.

### Verification

The verifier:

1. Computes the terminal hash from the terminal descriptor.
2. Walks the sibling list from deepest to shallowest, computing the parent's hash at each step from the current accumulated hash and the sibling's hash.
3. Compares the final computed root to the expected root.

The walk's direction is dictated by the key's bits. At each branch, the branching bit determines whether the current hash is the left or right child of the parent. If the bit is 0, the current hash is `left` and the sibling is `right`; if 1, the reverse. The branching bit position is `prefix_start + prefix_len`, where `prefix_start` is the number of key bits consumed by the branches above this one.

The `prefix_start` at each level is derived from the sibling list itself: it's the sum of `(prefix_len + 1)` over the siblings above, subtracted from 256. This is what lets the wire format omit an explicit depth per sibling.

### Generation

`proveAtRoot(tree, root, key)` walks from an explicit root down to the key's terminal, collecting sibling hashes and the terminal's identifying information. The walk and the terminal capture happen in the same recursion, so the value and the siblings are always consistent with the same root.

The alternative — reading the leaf separately from the current tree — would produce a proof whose value and siblings disagreed whenever the requested root was historical. The single-walk invariant is documented on `proveFromRoot`, and it's the reason `proveAtRoot` takes an explicit root rather than being a thin wrapper over `tree.get`.

### Key descriptors

A client that wants a proof of "Alice's balance" doesn't know that the underlying key is `Blake2b("acct" || alice_address)`. So the proof protocol accepts a typed descriptor and lets the server resolve it to the right SMT key.

The descriptors are:

- `Account` — a 32-byte address.
- `TokenBalance` — a 32-byte address followed by a 4-byte little-endian token ID.
- `Validator` — an 8-byte little-endian validator ID.
- `Global` — a UTF-8 name up to 64 bytes.
- `AmmPool` — an 8-byte little-endian pool ID.

The server resolves the descriptor via the same `Keys::*` functions the rest of the codebase uses, so the key the server walks to is exactly the key the client would have walked to if it had derived it directly.

## Versioning and historical reads

### What a version is

A **version** is a block height. When the block processor commits a block at height H, it applies the block's transactions and calls the tree's `save(H)`, which writes the current root to the `meta` table under the key `smt_root_at_<H>` and updates the current root under `smt_root`.

The tree also writes a historical row for every node and leaf it stores at version H — provided H is not 0. Version 0 is the bootstrap version: the state as it exists before any block has been applied, and it's not stored historically. Every block from 1 upward writes historical rows.

### Historical reads

`rootAtVersion(V)` retrieves the state root as it was at version V by reading `smt_root_at_<V>` from `meta`. It returns `nullopt` if that key isn't present, which means the version is either outside the retention window or was never saved.

`getAtVersion(key, V)` retrieves a key's value as it was at version V. It reads the root at V, then walks the tree from that root using the *historical* tables instead of the live ones. Every node fetched during the walk comes from `smt_nodes_hist` keyed by `(hash, V)` or `smt_leaves_hist` keyed by `(hash, V)`.

The live and historical trees are content-addressed, so a node that didn't change between V and the current version has the same hash at both and its row is stored once. A node that changed between V and now has different hashes at each version and its rows are stored separately. This is what keeps historical storage proportional to state *changes* rather than block count.

Typed historical reads are exposed on `StateAccess` as `getAccountAtVersion`, `getValidatorAtVersion`, and `getGlobalAtVersion`. The raw primitive is `getRawAtVersion`, which takes a raw SMT key. Historical reads work on NFT and collection keys as well, because the underlying `getAtVersion` is namespace-agnostic.

If a version is outside the retention window — that is, older than `current_height - smt_history_blocks` — `getAtVersion` returns `nullopt` immediately, before touching the DB. The window is enforced at the `StateAccess` level, not at the tree level, so a caller that knows the window can short-circuit the read itself.

### The four historical tables

Historical state lives in four tables:

- `smt_nodes_hist` — `(hash, version)` → node bytes.
- `smt_leaves_hist` — `(hash, version)` → leaf value.
- `smt_nodes_by_ver` — `(version, hash)` → empty (a prune index).
- `smt_leaves_by_ver` — `(version, hash)` → empty (a prune index).

The `_by_ver` tables exist so that pruning can be efficient. To prune all history older than `K`, the pruner scans `smt_nodes_by_ver` in ascending key order, stops at the first version ≥ K, and deletes the corresponding `smt_nodes_hist` rows. Because the `_by_ver` tables are keyed by version first, the scan visits versions in order and the stop is a genuine early termination — the pruning work is proportional to the amount being pruned, not to the total amount of history.

The `_hist` tables are the ones a historical read walks. The `_by_ver` tables are only used during pruning.

## The retention window

### Why a window exists

Clarity's consensus is BFT with immediate finality: no fork choice, no reorgs, no probabilistic finality. A block that reaches precommit quorum is canonical, and the chain's head is a monotonic sequence of committed blocks. There is no scenario in which a node needs historical state to make a consensus decision.

Historical state is only needed for two things:

1. **A block explorer** that wants to answer "what was Alice's balance at block 1,000?".
2. **A light client** that wants to prove a fact about a recent state without syncing the chain.

Both are useful. Neither requires indefinite history. A block explorer can run an indexer that scrapes the chain and stores its own history. A light client only needs proofs against the current root, or at worst against a root from a few minutes ago.

The retention window is the compromise: nodes keep enough history for a block explorer's "recent activity" view and for a light client's proofs against a recent root, but not so much that the historical tables dominate the DB.

### How it works

`smt_history_blocks` is the size of the retention window. If it's `N`, then after block H commits, the historical tables contain versions from `H - N + 1` to `H` inclusive. Older versions are pruned.

The prune runs after every block commit. It computes `keepFrom = H - N`, scans the `_by_ver` tables, and deletes every historical row whose version is strictly less than `keepFrom`. The live tree and the current root are untouched.

After the prune, the oldest available version is exactly `max(0, H - N)`. The window is exact; there's no grace period or throttling.

### Where the window is set

The window is set once per `StateAccess` by the caller. `StateAccess::setHistoryWindow(N)` stores `N` in a member, and every version check in the access layer uses that member. The default value is `UINT64_MAX`, meaning "every version is available" — the correct behaviour for tests, genesis construction, and any caller that doesn't want the window enforced.

The node sets the window on every `StateAccess` it constructs. `Node::makeStateAccess(version)` is a helper that constructs a `StateAccess` and calls `setHistoryWindow(config_.smt_history_blocks)` on it. Every call site in `Node.cpp` that needs a `StateAccess` goes through this helper, so the "every access has the configured window" invariant is structural, not a discipline that has to be remembered at each site.

The block processor similarly calls `state.setHistoryWindow(config_.smt_history_blocks)` on the `StateAccess` it constructs inside `applyCommittedBlock`. The window is applied before any historical read or write happens.

The retention window is a property of the `StateAccess`, not of the DB or the tree. Two `StateAccess` objects over the same DB can have different windows, and the tree's behaviour is identical for both — only the historical read paths differ, and those paths never affect consensus.

### Pruning is atomic with the commit

The prune runs inside the same MDBX write transaction as the block commit. The block processor opens a write transaction, applies the block's transactions, writes the block index and chain head, calls `pruneHistoryBeforeTxn(txn, keepFrom)`, and commits. If the prune fails for any reason, the entire transaction aborts, the block isn't committed, and the consensus engine's retry mechanism (see the main README's consensus section) retries the block.

This is a deliberate choice. A storage failure that prevents pruning is a real problem: if the prune failed silently, the historical tables would grow unbounded behind a warning, and an operator might not notice until the disk filled. By making the prune part of the commit, a prune failure halts the block processor and surfaces the problem. Better to stall on a fixable storage problem than to silently grow the DB forever.

### Per-network defaults

The default window is network-specific:

| Network | `smt_history_blocks` | Wall-clock equivalent (at 2s blocks) |
|---|---|---|
| Mainnet | 2,048 | ~68 minutes |
| Testnet | 512 | ~17 minutes |
| Regtest | 64 | ~2 minutes |

The values are chosen so that the historical tables stay bounded without operator tuning. On mainnet, 2,048 versions is enough for a block explorer's "recent" view and for a light client to prove a fact about a root it saw a few minutes ago. On regtest, 64 versions keeps the DB small enough that a throwaway regtest doesn't fill the disk.

Operators who want a deeper window can raise the value in `NodeConfig`. The window is not consensus-relevant, so two nodes on the same chain can have different windows and still agree on every block.

## The dry-run/apply invariant

The block processor has two paths for a block: a **dry-run** path and an **apply** path.

The dry-run path is used by the proposer to simulate a candidate block before the block's state root has been populated. It opens a write transaction, applies the block's transactions, computes the resulting root, and then *aborts* the transaction. Nothing is committed.

The apply path is used by every node that receives a committed block. It opens a write transaction, applies the block, computes the resulting root, and *commits* the transaction.

For the proposer's block to be accepted by the other nodes, the dry-run's computed root must equal the apply's computed root. That is only true if the dry-run and the apply make *the same state changes*, byte for byte. If the dry-run skips a change that the apply makes (or vice versa), the roots differ and the block is rejected.

The rule that makes this hold is: **every state change that touches the SMT happens on both paths.** Only writes to the meta table and to non-SMT index tables may be gated on `!ctx.dry_run`. The meta table's writes are non-SMT and don't contribute to the state root; the index tables are content-agnostic mirrors. Everything else — the SMT node writes, the leaf writes, the historical writes, the by-version index writes — happens unconditionally on both paths.

This invariant has been violated in the past, once, in a way that produced a hard-to-diagnose bug: a block's simulate and apply paths disagreed on the state root, so the block that a validator proposed was rejected by every other node. The fix is the rule above, and the `MatchingSimulateAndApplyProduceSameRoot`, `MatchingRootIdenticalAcrossFreshInstances`, and `NftReward_SimulateAndApplyProduceSameRoot` tests are the canaries that catch a future violation.

The tree's own operations — `update`, `remove`, `applyBatch` — write the live row and the historical rows in the same call. Neither is gated on anything. When the tree writes, it writes both; when the dry-run aborts, both are discarded. The invariant is preserved by construction at the tree level, and the block processor preserves it at the transaction level.

## What state storage actually costs

State storage has bounded and unbounded components. Understanding which is which is what lets an operator predict a node's disk footprint.

### Bounded components

**The live tree.** `smt_nodes` and `smt_leaves` hold one row per distinct subtree hash. For a chain with N live leaves, the live tree is O(N) rows. As long as the chain's live state doesn't grow without bound — which is a policy matter, not a storage-engine matter — the live tree's size is bounded by the amount of live state.

**The historical tables.** `smt_nodes_hist`, `smt_leaves_hist`, `smt_nodes_by_ver`, and `smt_leaves_by_ver` hold one row per `(hash, version)` or `(version, hash)` pair. With the retention window set to `smt_history_blocks`, the tables hold rows for at most `smt_history_blocks` versions. The total is bounded by `(writes per version) × smt_history_blocks`, and the writes per version are themselves O(state changes per block × log N).

**The entity tables.** Accounts, tokens, validators, orders, pools, positions, NFTs, and collections. Each holds one row per live object of its kind. Bounded by the size of live state.

**The index tables.** Enumerations of the entity tables. Bounded by the entity tables.

**Block and transaction history.** `blocks_by_hash`, `blocks_by_height`, `tx_index`, and `receipts` grow linearly with the chain length. A block's contribution is a few hundred bytes to a few kilobytes depending on its transaction count. This is the component that grows with the chain, and it's the reason a long-running node eventually needs more disk than a freshly-synced one.

### Unbounded components

**The live tree's stale nodes.** `smt_nodes` and `smt_leaves` are content-addressed and never delete. When the tree's shape changes — a split, a collapse, a rewrite — the old subtree hashes remain in these tables even though they are no longer reachable from the current root. The tables grow with the *total number of distinct subtrees the chain has ever produced*, not with the size of the current tree.

For a chain that grows its live state monotonically — new accounts, new tokens, new pools — this leak is small relative to the live tree itself, because the number of distinct subtrees that ever existed is close to the number currently reachable. For a chain that churns its state heavily — accounts opening and closing, pools created and drained, orders placed and filled — the leak can be significant.

The leak is currently unmitigated. A mark-and-sweep pass that deletes rows unreachable from the current root would bound it, but it's not implemented in v1. The cost is predictable: each rewrite produces at most O(log N) stale rows, and each stale row is ~100 bytes.

**Fill history.** `fill_history` holds one row per fill. It's never pruned. A chain that produces a lot of fills — an active DEX — can grow this table significantly. Like the live tree's stale nodes, it's a candidate for future bounding, and like it, the current cost is predictable and small next to the block-history tables.

### Realistic sizes

For a regtest that's been running a few hundred blocks with a modest amount of state churn:

- Live tree: a few hundred KB.
- Historical tables: a few hundred KB (bounded by the 64-version window).
- Entity tables: a few KB.
- Block and transaction history: a few MB.
- Total: under 20 MB.

For a mainnet with a million accounts, a thousand tokens, a thousand pools, and ten thousand NFTs:

- Live tree: ~50 MB (2 × N × 100 bytes for the internal nodes plus leaves).
- Historical tables: at 2,048 versions and ~100 writes per block × ~20 rows per write, ~400 MB.
- Entity tables: ~200 MB.
- Index tables: ~100 MB.
- Block and transaction history: at ~5 KB per block and a million blocks, ~5 GB.
- Total: ~6 GB.

The dominant component on mainnet is block and transaction history, not state. The historical tables are the second-largest, and their size is directly proportional to the retention window — halving the window halves the historical tables.

## What's not in this layer

State does not know about:

- **Consensus.** The state layer doesn't know that there are validators, rounds, or phases. It receives blocks from the block processor and produces state roots for the block headers. How those roots are agreed on is a consensus concern.
- **The mempool.** The mempool is a separate table that happens to live in the same MDBX environment. Its contents don't participate in the state root, and a mempool mutation doesn't touch the tree.
- **The P2P layer.** Proof serving is a state-layer operation that P2P wraps; the P2P layer itself doesn't read the tree.
- **The RPC layer.** The RPC layer reads state through `StateAccess` and exposes it over JSON-RPC. It doesn't write to state, and it doesn't see the tree's internals.
- **The wallet.** The wallet is a client of the RPC layer. It verifies proofs by calling `State::verifyProof`, which is a pure function; it doesn't open a DB.

The state layer's responsibility is exactly: hold the state, commit to it with a Merkle root, and answer questions about it. Everything else is layered on top.