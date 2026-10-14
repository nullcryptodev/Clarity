# Security

Clarity's security model: what the protocol defends against, how, and what it doesn't defend against.

This document is written for auditors, integrators, and operators. It states the threat model explicitly, describes the cryptographic primitives and their roles, walks through the security-critical code paths, and lists the known limitations.

## Table of contents

- [The threat model](#the-threat-model)
  - [What the protocol defends against](#what-the-protocol-defends-against)
  - [What the protocol doesn't defend against](#what-the-protocol-doesnt-defend-against)
  - [What the protocol assumes](#what-the-protocol-assumes)
- [Cryptographic primitives](#cryptographic-primitives)
  - [The primitive set](#the-primitive-set)
  - [Where each primitive is used](#where-each-primitive-is-used)
  - [What is not used, and why](#what-is-not-used-and-why)
- [Key management](#key-management)
  - [The four key types](#the-four-key-types)
  - [Derivation paths](#derivation-paths)
  - [Keystore format](#keystore-format)
  - [What to back up](#what-to-back-up)
- [Consensus security](#consensus-security)
  - [The safety argument](#the-safety-argument)
  - [The liveness argument](#the-liveness-argument)
  - [Equivocation and slashing](#equivocation-and-slashing)
  - [Height-scoped key verification](#height-scoped-key-verification)
  - [Emergency rotation](#emergency-rotation)
- [Network security](#network-security)
  - [Peer authentication](#peer-authentication)
  - [Session encryption and forward secrecy](#session-encryption-and-forward-secrecy)
  - [Replay and reflection resistance](#replay-and-reflection-resistance)
  - [Rate limiting and DoS mitigation](#rate-limiting-and-dos-mitigation)
- [State security](#state-security)
  - [Merkle proofs](#merkle-proofs)
  - [Light clients and the trust model](#light-clients-and-the-trust-model)
  - [Historical pruning and proof availability](#historical-pruning-and-proof-availability)
- [Wallet security](#wallet-security)
  - [Keystore encryption](#keystore-encryption)
  - [Signing isolation](#signing-isolation)
  - [The wallet's trust model](#the-wallets-trust-model)
- [Operational security](#operational-security)
  - [What an operator should protect](#what-an-operator-should-protect)
  - [The consensus key is a live key](#the-consensus-key-is-a-live-key)
  - [The reward address is a policy knob](#the-reward-address-is-a-policy-knob)
- [Known limitations](#known-limitations)
  - [No slashing for liveness failures](#no-slashing-for-liveness-failures)
  - [No RPC authentication beyond the admin token](#no-rpc-authentication-beyond-the-admin-token)
  - [No divergence detection or repair](#no-divergence-detection-or-repair)
  - [No cross-network genesis replay protection beyond chain ID](#no-cross-network-genesis-replay-protection-beyond-chain-id)
  - [No light-client P2P proofs from the wallet](#no-light-client-p2p-proofs-from-the-wallet)
  - [The consensus WAL is not encrypted](#the-consensus-wal-is-not-encrypted)
  - [The mempool is not encrypted](#the-mempool-is-not-encrypted)
  - [No hardware-wallet support](#no-hardware-wallet-support)
  - [No multi-signature accounts](#no-multi-signature-accounts)
  - [No transaction fees market mechanism](#no-transaction-fees-market-mechanism)
- [What to do if you find a vulnerability](#what-to-do-if-you-find-a-vulnerability)

## The threat model

### What the protocol defends against

**Byzantine validators.** The BFT consensus protocol tolerates up to `f = (n - 1) / 3` Byzantine validators, where `n` is the active set size. A Byzantine validator can equivocate, censor transactions, refuse to participate, or send malformed messages. The protocol's safety (no two honest validators commit different blocks) holds against this adversary. The protocol's liveness holds if `2f+1` validators are reachable and honest.

**Network adversaries.** An adversary that can eavesdrop, modify, drop, or delay messages on the network cannot: decrypt session traffic, forge a peer's identity, tamper with a block without changing its hash, tamper with a Merkle proof without detection, or inject a valid transaction without the sender's private key. The session encryption uses ephemeral X25519 for forward secrecy, and every authenticated message carries an AEAD tag that binds the message type and direction.

**Malicious peers.** A peer that sends malformed messages, floods the node with requests, or tries to connect to itself is detected and disconnected. Peers that cross the misbehavior threshold are banned. The rate-limiting policy bounds both per-peer and node-wide work.

**State corruption.** The state is committed by a Merkle tree whose root is written into every block header. Any two nodes with the same state produce the same root; a node whose state diverges from the network's produces a different root and its blocks are rejected.

**Light-client impersonation.** A server that lies about a balance or a state value produces a proof that fails verification against the client's expected root. The client doesn't need to trust the server's choice of root, because the proof is self-contained: `verifyProof(expected_root, proof)` recomputes the root from the proof and compares.

**Transaction replay.** Every transaction is signed over a chain ID, so a mainnet transaction cannot be replayed on testnet and vice versa. Within a chain, a nonce prevents replay: a transaction with a nonce lower than the sender's current nonce is rejected.

**Equivocation.** A validator that signs two conflicting votes at the same `(height, round)` produces a mathematical proof of misbehavior that any peer can verify. The proof is included in a block as a `Slash` system transaction; the validator loses 5% of its stake and its reward multiplier is permanently reduced.

**Key compromise (past sessions).** Compromise of a validator's long-term identity key does not compromise past session keys, because session keys are derived from ephemeral X25519 exchanges. An attacker who compromises an identity key can impersonate the validator in future sessions, but cannot decrypt past traffic.

### What the protocol doesn't defend against

**A supermajority of Byzantine validators.** If more than `f = (n - 1) / 3` validators are Byzantine, the protocol's safety breaks. This is a fundamental limitation of BFT consensus, not a defect of Clarity's implementation. At `n = 100`, `f = 33`; the protocol is safe up to 33 Byzantine validators and unsafe above.

**A chain stall.** If fewer than `2f+1` validators are online and honest, the chain stalls. The emergency rotation mechanism can replace offline validators with pool candidates, but only if there are pool candidates. A chain whose entire active set is offline and whose pool is empty stays halted until validators come back.

**Long-term network partitions.** A partition that lasts many hours can cause divergence in the mempool, but not in the chain: the chain either has quorum or it doesn't, and if it does, it produces blocks that every honest validator sees. A partition longer than the round timeout will trigger round advancement, and if it lasts longer than `EMERGENCY_ROTATION_ROUNDS`, emergency rotation.

**Compromise of a validator's live consensus key.** An attacker who compromises a validator's consensus key can sign conflicting votes on its behalf, which will eventually be detected and slashed, but the damage is done. There is no way to un-sign a message. The mitigation is rotation: a validator that suspects its key is compromised can call `RotateConsensusKey` to move to a fresh key. The old key remains valid for verifying past votes, which is exactly what's needed for slashing.

**Compromise of a wallet's private key.** An attacker who compromises a wallet's reward key can spend the wallet's funds, update the wallet's reward address, and unregister the wallet's validator. The protocol provides no recovery mechanism for a compromised key. The mitigation is hardware wallets (not currently supported) or offline signing (supported via `transaction_signer`).

**Malicious RPC endpoints.** A wallet that uses an RPC endpoint trusts that endpoint for the *root* it verifies proofs against. The proofs themselves are verified locally, but if the endpoint lies about the root, the wallet will verify the wrong proofs and accept the wrong balances. The mitigation is to configure a second endpoint (`connect-peer`) and require both to agree on the root. A wallet that wants to trust no endpoint must fetch headers over P2P and follow the header chain itself (see [Light clients and the trust model](#light-clients-and-the-trust-model)).

**Quantum adversaries.** Every signature scheme in Clarity is Ed25519, and every key agreement is X25519. Both are vulnerable to a sufficiently large quantum computer. There is no post-quantum fallback. This is a long-term concern, not a present one, and it affects every blockchain that uses classical signatures.

**A Byzantine proposer with a compromised prover.** A proposer that can produce a valid state root for a block whose transactions don't actually produce that root could pass simulation. The protection is that every other node runs the same simulation, so a proposer that lies produces a root that no honest node computes. The proposer's block is rejected on apply. The only way to break this is to compromise the simulation itself, which would require compromising the state transition function (a code bug) or the cryptography (a hash collision).

**Side-channel attacks on validators.** A validator's signing key is held in memory while the daemon runs. An attacker with local access to the machine can extract it via a memory dump, a cold-boot attack, or a speculative execution side channel. The mitigation is operational: run validators on isolated hardware with restricted access. There is no protocol-level defense.

### What the protocol assumes

**Honest majority of validators.** At most `f = (n - 1) / 3` validators are Byzantine. This is the standard BFT assumption and it's what every BFT protocol requires.

**Quorum liveness.** At least `2f+1` validators are reachable and honest for the chain to produce blocks. A chain whose quorum is offline stalls.

**Partial synchrony.** The network eventually delivers messages. The protocol doesn't rely on a bounded delay; it relies on the delay being finite so that timeouts eventually fire and rounds eventually advance.

**Cryptographic hardness.** Blake2b is collision-resistant and preimage-resistant. Ed25519 signatures are unforgeable. X25519 key agreement is secure against passive adversaries and provides forward secrecy against active adversaries. XChaCha20-Poly1305 is an IND-CCA2 secure AEAD. Argon2id is a memory-hard KDF. None of these assumptions is specific to Clarity; they're the standard assumptions of the primitives.

**Trusted execution environment for validators.** A validator's signing key is held in the daemon's memory and used to sign votes. The protocol assumes that the daemon is not compromised and that the key is not extracted. In practice, this means running validators on machines with restricted access and no untrusted software.

**Synchronized clocks.** The BFT protocol uses round timeouts to advance rounds. It assumes that validators' clocks are roughly synchronized — within the round timeout — so that a proposer's proposal arrives before the round times out. A validator whose clock is far off may see rounds advance too fast or too slow. There is no clock synchronization protocol; nodes are expected to use NTP or equivalent.

## Cryptographic primitives

### The primitive set

Clarity uses five cryptographic primitives:

| Primitive | Algorithm | Source |
| --- | --- | --- |
| Hash | Blake2b (256-bit output) | BLAKE2 reference |
| Signature | Ed25519 | Monocypher |
| Key exchange | X25519 | Monocypher |
| AEAD | XChaCha20-Poly1305 | Monocypher |
| KDF (keystore) | Argon2id | Argon2 reference |

The Blake2b implementation is the reference code from the BLAKE2 project, verified against the official test vectors. The Ed25519, X25519, and XChaCha20-Poly1305 implementations are from Monocypher, a small, audited, portable cryptography library. The Argon2id implementation is the Argon2 reference code.

Clarity does not implement its own cryptography. The libraries are well-known, small, and have been audited by third parties.

### Where each primitive is used

**Blake2b** — everywhere a hash is needed:

- State key derivation (`Blake2b(domain4 || payload)`).
- SMT node hashing (leaf, branch, default).
- Merkle root computation (transaction root, receipts root, validator set root, epoch fills root).
- Session challenge construction (`Blake2b(initiator_nonce || responder_nonce || identity_pubkey || ephemeral_pubkey)`).
- Session key derivation (labelled Blake2b calls over the shared secret and context).
- Address fingerprinting (`Blake2b("nfa " || LE(nft_id))` for NFT custody addresses).
- Chain ID derivation.

**Ed25519** — every signature:

- Transaction signatures.
- Block proposal signatures.
- Vote (prevote, precommit) signatures.
- Timeout vote signatures.
- Equivocation proof signatures (two votes at the same height and round).
- P2P Auth challenge signature.
- Node identity signatures.

**X25519** — the P2P session key agreement:

- One ephemeral X25519 keypair per session, generated at session start and never persisted.
- One X25519 shared secret computation per session.
- The shared secret is combined with both public keys, both identity public keys, and both network nonces to derive the two directional session keys.

**XChaCha20-Poly1305** — the P2P session encryption:

- Every message after `AuthReady` is encrypted with a per-direction key and a per-direction nonce counter.
- The AAD binds the message type and the direction.

**Argon2id** — the wallet keystore KDF:

- The keystore's encryption key is derived from the user's password with Argon2id.
- The parameters are tuned for a memory-hard KDF on commodity hardware.

### What is not used, and why

**No AES.** AES-GCM has had several catastrophic implementation bugs (both in hardware and software) and is vulnerable to timing attacks if not implemented carefully. XChaCha20-Poly1305 is constant-time in software and has no equivalent failure mode.

**No SHA-2.** SHA-2 is fine, but Blake2b is faster and has the same security level. There is no reason to use both.

**No ECDSA.** ECDSA is vulnerable to nonce-reuse attacks, has malleable signatures, and requires a random nonce that, if reused, leaks the private key. Ed25519 is deterministic, non-malleable, and has none of these problems.

**No RSA.** RSA is slow, has large keys, and is vulnerable to padding oracle attacks. There is no reason to use it in a modern system.

**No post-quantum primitives.** NIST has standardized post-quantum signature and KEM algorithms (Dilithium, Kyber), but they are large, slow, and still relatively new. Clarity doesn't use them. When a post-quantum transition is needed, it will be a hard fork.

**No homomorphic encryption, ZK proofs, or commit-and-reveal schemes.** These are powerful but complex, and Clarity doesn't need them.

## Key management

### The four key types

Every Clarity participant holds some subset of four key types:

**Wallet key.** An Ed25519 public key that controls an account. Derived from a BIP-39 mnemonic at `m/44'/9000'/account'/0'/index'`. Controls the account's balance, token balances, staked funds, and validator identity (if the account is also a validator's owner).

**Validator reward address.** A wallet key used as a validator's reward address. When a validator registers, the registering wallet's address becomes the validator's `reward_address` and `owner`. Block rewards are paid to this address, and the address is the effective authority over the validator's parameters.

**Validator consensus key.** A 32-byte Ed25519 public key that signs proposals, prevotes, precommits, and timeout votes. It is the validator's identity for BFT purposes. It's held as a raw hex secret in the daemon (via `--consensus-key` or a `--consensus-key-file` when implemented). It can be rotated via `RotateConsensusKey`.

**Node identity key.** An Ed25519 public key that authenticates the node in P2P connections. It's distinct from the consensus key: a non-validator node has a node identity key but no consensus key, and a validator node can use either the same key for both or distinct keys.

Additionally, an **ephemeral X25519 key** is generated per P2P session and used only for the session key agreement. It's never persisted, never derived from a mnemonic, and never reused.

### Derivation paths

All BIP-39 mnemonics use the SLIP-10 derivation scheme, which for Ed25519 requires hardened-only derivation. The two chains in use are:

- **Reward addresses**: `m/44'/9000'/account'/0'/index'`
  - The `0'` at position 4 is the "receive" branch, matching the convention used by most HD wallets.
  - `account'` distinguishes different accounts under one mnemonic.
  - `index'` distinguishes different addresses within one account.

- **Consensus keys**: `m/44'/9000'/account'/2'/index'`
  - The `2'` at position 4 is a distinct branch reserved for consensus keys.
  - The same mnemonic produces both a reward address and a consensus key, so one backup covers both.

The `coin_type` is `9000`, which is not registered in the SLIP-44 registry (as of this writing). This is a deliberate choice to avoid collision with other chains' derivation paths.

The all-hardened derivation is required by SLIP-10 for Ed25519. A non-hardened path would produce a key with a known relationship to the parent, which for Ed25519 is not a security property you want.

### Keystore format

A keystore is a JSON file with the following structure:

```json
{
  "version": 1,
  "label": "user-supplied-name",
  "fingerprint": "0x...",
  "kdf": {
    "algorithm": "argon2id",
    "params": { ... },
    "salt": "0x..."
  },
  "cipher": {
    "algorithm": "chacha20-poly1305",
    "nonce": "0x...",
    "ciphertext": "0x..."
  },
  "mac": "0x..."
}
```

The `fingerprint` is a stable per-mnemonic identifier derived from the seed. It's used to detect a keystore swap: if the file's declared fingerprint doesn't match the one derived on unlock, the file was replaced or corrupted.

The `mac` covers the ciphertext and the AAD (the header fields). Any tampering with the ciphertext, MAC, nonce, salt, or AAD causes unlock to fail.

The keystore format is versioned. Adding fields is a minor version bump; changing the layout is a major version bump with a migration path.

### What to back up

The **BIP-39 mnemonic** is the only thing that needs to be backed up. Everything else is derived from it.

- **Wallet key**: derived from the mnemonic at the account's path. Losing the mnemonic loses the wallet.
- **Validator reward address**: same mnemonic, different path. Losing the mnemonic loses the reward address.
- **Validator consensus key**: same mnemonic, different path. Losing the mnemonic loses the ability to sign for the validator if the daemon's key is also lost.

A validator that has already registered and is running on a live daemon holds its consensus key in the daemon's memory. Losing the mnemonic doesn't immediately break the validator (the daemon keeps signing), but a restart without the mnemonic would leave the validator unable to sign, which effectively disables it. Back up the mnemonic.

The **node identity key** is generated automatically and stored at `<data_dir>/node_key`. It's not derived from a mnemonic. Losing it changes the node's P2P identity but doesn't lose funds or validator status. It's fine to let a node generate a new one on restart; the identity is only meaningful for the duration of a session.

## Consensus security

### The safety argument

**Claim**: two honest validators never commit different blocks at the same height.

The proof reduces to three lemmas:

1. **A validator casts at most one prevote and one precommit per round.** The engine's step transitions enforce this: a validator in `Prevote` has already cast its prevote, and it never transitions back to `Propose` within a round.

2. **A precommit quorum on a block X implies that every honest validator that later precommits has seen a polka for X or has X as its lock or valid value.** This follows directly from the precommit rules: a validator precommits X only if it saw a prevote quorum (a polka) for X this round, or if X is its lock.

3. **An honest validator's lock is only superseded by a polka in a strictly higher round.** The lock is set at precommit time and replaced only when a new polka (from a round strictly greater than the lock round) is observed.

Combining the lemmas: suppose A commits X at round R and B commits Y at round S, with X ≠ Y and R ≤ S.

If R = S, the two precommit quorums intersect in an honest validator, which would have precommitted both X and Y in the same round, contradicting Lemma 1.

If R < S, then the precommit quorum for X implies every honest validator that saw it locked on X (or had X as valid value). For B to precommit Y at round S, it must have seen a polka for Y in a round greater than R. But a polka for Y in a round greater than R requires `2f+1` prevotes for Y in that round, and by Lemma 3, no honest validator with a lock on X can prevote Y in a round greater than R unless it saw a polka for Y in a round greater than R — which is circular. The base case is that no such polka exists at round R or below. The induction holds.

The full proof is the standard Tendermint safety proof. The pieces of the code that implement it are:

- `enterPrevote`, `enterPrecommit`, `enterCommit`: step transition rules.
- `selectPrevoteHash`: the prevote selection rule.
- `enterPrecommit`: lock and valid-value updates.
- `checkPrevoteQuorum`, `checkPrecommitQuorum`: polka detection.
- `verifyVoteSignature`: binds each vote to the signer's authoritative key at the vote's height.
- `insertVote`: records votes and detects equivocation.

### The liveness argument

**Claim**: if `2f+1` validators are online and honest, the chain produces blocks.

The argument is: within each round, if the proposer is honest and its proposal arrives at all honest validators before their timeout fires, every honest validator prevotes the proposal, a polka forms, every honest validator precommits the block, and the block commits. If the proposer is offline or its proposal doesn't arrive, the round times out, the round number advances, and a new proposer takes over. Eventually a round has a live proposer whose proposal arrives, and the round commits.

The bound on how many rounds can elapse is: the number of consecutive Byzantine or offline proposers in a row. With `n` validators, at most `f` are Byzantine, so at most `f` rounds can fail consecutively due to a Byzantine proposer. After at most `f+1` rounds, an honest proposer takes over and the round commits (assuming the network delivers in time).

The `EMERGENCY_ROTATION_ROUNDS` threshold provides a fallback for the case where the committed active set is unable to produce blocks — say, because a majority of it is offline. When 30 consecutive rounds time out, a validator proposes an emergency block with a timeout certificate. The emergency set replaces offline members with pool candidates. This is a liveness mechanism, not a safety mechanism; an emergency block still requires quorum on the emergency set.

### Equivocation and slashing

The only slashing offense in Clarity is equivocation: a validator signing two conflicting votes at the same `(height, round)`. This is a mathematical fact — two valid signatures over different block hashes (or one block hash and a nil) from the same key — and it's not subject to interpretation.

**Evidence collection.** When a validator sees two conflicting votes from the same signer at the same `(height, round)`, it records an `EquivocationEvidence` entry. The evidence is recorded only if both signatures verify against the signer's effective consensus key at the vote's height. A forged conflict is dropped rather than stored.

**Evidence inclusion.** A proposer that has pending equivocation evidence includes a `Slash` system transaction for each verified proof. The proposer checks each proof with `verifyEquivocationProof` before including it. Only verified proofs are included; unverifiable evidence is skipped.

**Evidence application.** `executeSystemSlash` runs for each `Slash` transaction in the block:

1. Looks up the validator by id. If unregistered, no-op.
2. If the validator is a seed, no-op (seeds are slashing-exempt).
3. Reduces the validator's stake by 5% (`SLASH_AMOUNT_BPS = 500`).
4. Applies the infraction penalty: the validator's `reward_multiplier` is reduced by 2000 bps (down to a floor of 2000 bps, i.e. 20%).
5. Adds the slashed amount to the pot.

**Evidence erasure.** When a block containing a Slash transaction commits, every node scans the block's transactions, decodes each Slash, and erases matching evidence from its own pending list. Every node does this, not just the proposer. Reading the block as the source of truth is what keeps all nodes in sync.

**Why automatic.** Slashing is not subject to a vote. A proof of equivocation is a mathematical fact; a Byzantine majority cannot forge a signature. If the majority could vote on whether to slash, it could vote to slash an honest validator. Automatic application means the safety argument of BFT is economically enforced.

### Height-scoped key verification

A vote or equivocation proof at height H verifies against the key that was authoritative at H, not against the validator's current key. This is what makes consensus-key rotation compatible with the slashing machinery.

The key history is a list of `(key, valid_from_height, valid_until_height)` entries, ordered by `valid_from_height`, with half-open intervals. The last entry has `valid_until_height == 0` (current). The ranges are gapless and non-overlapping: every height in a validator's life has exactly one authoritative key, and no height verifies against two.

The tight rule preserves the property: **you can only be slashed for votes you were authorized to cast**. A looser rule — "signature verifies against any key the validator has ever held" — would mean a validator whose old key was compromised could be slashed for votes that key never signed. The tight rule also means a validator that rotates does not escape a pending equivocation proof against its old key.

### Emergency rotation

Emergency rotation triggers when a validator has observed `EMERGENCY_ROTATION_ROUNDS = 30` consecutive round timeouts at the current height. The threshold is a liveness fallback: if the committed active set can't form quorum for 30 rounds, the set is presumed to have lost members.

An emergency block carries a **timeout certificate**: `f+1` signed timeout votes from the committed set at rounds `>= EMERGENCY_ROTATION_ROUNDS`. The certificate is what proves to a verifier that at least `f+1` validators observed the stall. Since at most `f` validators are Byzantine, `f+1` signatures imply at least one honest validator observed the stall.

The certificate is included in the block header and committed to via the `timeout_certificate_hash` field. A relaying peer cannot strip or swap the certificate without changing the block hash and invalidating every signature.

The emergency active set is derived from the committed set and the validator registry using the same predicate as offline removal:

```
emergency_set =
    (committed_set - validators_offline_at_current_height)
    + pool_promotions
```

A validator is "offline" if its `last_seen_height` is more than 20 blocks behind the current height. Seeds are **not** protected in emergency rotation — a failed seed is exactly what emergency rotation is designed to replace.

The emergency set is deterministic: every honest node with the same inputs computes the same set. This is what makes an emergency block verifiable by nodes that didn't propose it.

## Network security

### Peer authentication

Every peer must complete the `Auth` exchange before reaching the `Established` state. The exchange is a signed challenge-response that binds both peers' identity keys and ephemeral keys to the session.

**The challenge**:

```
Blake2b(
    initiator_nonce  8 bytes (LE)
  || responder_nonce  8 bytes (LE)
  || identityPubkey   32 bytes
  || ephemeralPubkey  32 bytes
)
```

Including both nonces binds the signature to the specific session — a captured `Auth` cannot be replayed against a different connection. Including both public keys binds the signature to the claimed identity and to the ephemeral key — a MITM that substitutes a different ephemeral key produces a different challenge and invalidates the signature.

**The identity key** is the sender's long-term Ed25519 public key. After verification, the manager looks up the validator whose consensus key matches the identity key. If found, the peer's `validator_id` is set; if not, the peer is authenticated but claims `validator_id = 0`.

**Failure handling**: an invalid signature closes the peer immediately and reports misbehavior. A missing or malformed `Auth` is the same. A key derivation failure closes the peer without a ban — it's a configuration or protocol error, not an attack. An `AuthReady` mismatch closes the peer without a ban — a session-key disagreement is not evidence of misbehavior.

### Session encryption and forward secrecy

Session keys are derived from an ephemeral X25519 exchange:

```
sharedSecret = X25519(our_ephemeral_secret, their_ephemeral_pubkey)
keyA, keyB    = KDF(sharedSecret, both ephemeral pubs, both identity pubs, both nonces)
```

The ephemeral secret is generated fresh per session and wiped immediately after key derivation. It's never persisted, never logged, never leaves the `Peer` object.

The forward secrecy property: an attacker who compromises a validator's long-term identity key does not thereby compromise past session keys. The identity key is used only for signing the Auth challenge; the session key is derived from the ephemeral X25519 exchange. An attacker who records a session's encrypted traffic today and compromises the identity key tomorrow still cannot decrypt the traffic, because the ephemeral secrets are gone.

**Directional keys.** The KDF produces two keys, not one. The lower-nonce side uses key A for sending and key B for receiving; the higher-nonce side uses them the other way. This removes the class of bug where the two directions accidentally share a nonce space.

**Nonces.** Every message uses XChaCha20-Poly1305 with a 24-byte nonce constructed from an 8-byte counter: `nonce[0..8) = counter (LE)`, `nonce[8..24) = 0`. The counter starts at 0 and increments per message per direction. It never wraps; the code checks before incrementing and closes the connection if it would overflow.

**AAD.** Every message carries an AAD that binds the message type and the direction: `AAD = message_type (2 bytes LE) || direction_tag (1 byte)`. The direction tag is 0 for the lower-nonce side and 1 for the higher-nonce side. This makes reflection (a message sent by A cannot be replayed back to A), type confusion (a `Prevote` cannot be re-framed as a `Precommit`), and cross-direction attacks impossible.

### Replay and reflection resistance

**Replay resistance.** Every message after `AuthReady` uses a fresh nonce (the counter). A message from session A cannot be replayed in session B, because the session keys are different and the AEAD tag would fail.

**Reflection resistance.** The AAD binds the direction, so a message sent by A under direction tag 0 cannot be reflected back to A under the same tag. Even if the two directions shared a key (they don't), the direction tag would fail to match.

**Cross-message-type resistance.** The AAD binds the message type, so a message framed as a `Prevote` cannot be re-framed as a `Precommit` without invalidating the AEAD tag.

**Cross-session resistance.** The session key is derived from the ephemeral exchange plus both nonces. Two sessions with the same peers but different nonces have different session keys. An attacker cannot transplant a message from one session to another.

### Rate limiting and DoS mitigation

**Per-peer token bucket.** Every peer has a token bucket that charges messages by type. The cost reflects the asymmetry of work: a control message costs 1, a `Tx` costs 5, a `GetHeaders` or `GetBlocks` costs 20, a `GetProof` costs 50. A peer that floods expensive-to-serve messages is cut off and disconnected.

**Consensus token bucket.** A separate, stricter bucket for consensus messages. Bounds the proposal/vote throughput from one validator independently of the general bucket.

**Aggregate bucket.** A node-wide budget shared by all peers. Bounds the sum of all peers' work. Charged with a compressed cost table (a `GetProof` costs 10, not 50) so that a single legitimate proof request doesn't consume a large fraction of the budget. A peer behind a shared NAT can trip the aggregate budget through no fault of its own, so the aggregate trip closes the connection **without** reporting misbehavior or banning.

**Message size caps.** A single message is capped at `MAX_MESSAGE_SIZE = 16 MiB`. A `GetHeaders` can request at most 2000 headers; a `GetBlocks` at most 128 blocks. A message that claims a larger payload is rejected before the payload is read.

**Peer count caps.** A node accepts at most `maxInbound` inbound connections and maintains at most `targetOutbound` outbound connections. A peer that tries to open more is rejected.

**Ban list.** A peer that crosses the misbehavior threshold is banned for `banDurationSec`. Banned IPs are rejected at accept time and skipped during outbound dialing.

## State security

### Merkle proofs

A Merkle proof for a key is a list of sibling hashes from the leaf up to the root, plus a terminal descriptor. Verification recomputes the root from the proof and compares to the expected root. The verification function `verifyProof(expected_root, proof)` performs no DB access and no signature checks.

**Soundness.** A proof is valid if and only if the recomputed root matches the expected root. An attacker who wants to forge a proof for a key must produce a sequence of sibling hashes that reconstructs the expected root from the leaf. This requires finding a hash collision (Blake2b is collision-resistant) or brute-forcing the sibling hashes (2^256 work). Neither is feasible.

**Completeness.** Every key in the tree has a valid proof against every root that includes it. Proof generation walks the tree from the root and captures the siblings. The proof's value and siblings come from a single walk from a single root, so they're always consistent.

**Non-inclusion.** A proof for a key not in the tree demonstrates that the walk terminates at a default subtree, a different leaf, or a divergent branch. The terminal descriptor carries the specific case. A verifier can distinguish an inclusion from a non-inclusion by inspecting the descriptor.

### Light clients and the trust model

A light client that wants to verify a fact about the state (a balance, an ownership, a pool reserve) does so in two steps:

1. Obtain a state root it trusts.
2. Obtain a Merkle proof for the fact and verify it against that root.

The Merkle proof is verified locally. The light client doesn't need to trust the server that produced the proof; if the server lies about the value, the proof fails verification. The `verifyProof` function is the same one the full node uses; there is no light-client-specific implementation.

The **state root** is the trust anchor. How a light client obtains it determines the trust model:

- **Trust an RPC endpoint.** The client asks the endpoint for the current root and verifies proofs against it. The client trusts the endpoint's choice of root. If the endpoint lies about the root, the client accepts proofs against the wrong root and reports wrong balances. This is the current wallet's model.

- **Two-endpoint agreement.** The client asks two endpoints for the current root and requires them to agree before accepting either. This is stronger than a single endpoint but still trusts that at least one endpoint is honest. This is the wallet's `connect-peer` model.

- **Follow the header chain.** The client fetches block headers over P2P, verifies each header's `parent_hash` against its predecessor, and takes the current root from the latest header. The client needs a trusted checkpoint at the start (a genesis hash or a recent block hash), but once it has one, it trusts nothing else. This is a full light client. Not currently implemented.

The spectrum goes from "trust one endpoint" to "trust nothing but a hash." The current wallet stops at the second step; the third is the next milestone for a full light-client mode.

### Historical pruning and proof availability

Historical proofs are available for versions within the retention window (`smt_history_blocks`, per-network default: 2048 on mainnet). A proof against a version older than the window returns `VersionUnavailable`.

The window is a policy choice, not a security property. Two nodes with different windows still agree on consensus; only the historical queries they can answer differ. A node that prunes aggressively can still serve proofs against the current root and any version inside its window.

The pruning is atomic with the block commit: the historical prune runs inside the block-commit transaction. A failed prune aborts the commit; the consensus retry mechanism then retries the block. This makes the window exact: after block H commits, the oldest retained version is exactly `H - smt_history_blocks`.

## Wallet security

### Keystore encryption

A keystore is an encrypted JSON file. The encryption key is derived from the user's password via Argon2id with parameters tuned for a memory-hard KDF. The ciphertext is ChaCha20-Poly1305. The MAC covers the ciphertext and the header (via AAD).

**Password strength.** Argon2id makes brute-force attacks expensive, but it doesn't make a weak password safe. A user who chooses "password123" is vulnerable to a dictionary attack, no matter how strong the KDF is. The wallet should encourage strong passwords; the keystore format enforces a minimum length.

**Tamper detection.** Any modification to the ciphertext, MAC, nonce, salt, or AAD causes unlock to fail. The MAC covers all of the header fields, so a keystore that has been edited in any way is rejected.

**Fingerprint.** A stable per-mnemonic identifier derived from the seed. It's used to detect a keystore swap: if the file's declared fingerprint doesn't match the one derived on unlock, the file was replaced or corrupted.

**No memory protection.** The password and the derived keys are held in memory while the keystore is unlocked. An attacker with local access to the machine can extract them via a memory dump. The mitigation is to run the wallet on a machine with restricted access.

### Signing isolation

A `LocalSigner` wraps an unlocked keystore and registers derived keys by public key. Signing requires the keystore to be unlocked; a derived key that hasn't been registered can't be signed with (the signer refuses rather than deriving on the fly).

**Offline signing.** The `transaction_signer` binary is an offline wallet transaction signer. It takes a serialized transaction, signs it with a keystore, and outputs the signature. This lets a user sign transactions on an air-gapped machine and broadcast them from a networked one. The private key never touches the networked machine.

**No hardware wallet support.** There is no hardware-wallet protocol. Adding one would require defining a signing protocol, a communication channel, and a validation path. The `transaction_signer` binary is the current best practice for isolating signing.

**Signing failures are silent.** A signing failure is not reported as a network event; it's a local error. A transaction that can't be signed is not broadcast. A validator whose consensus key is missing or invalid simply doesn't sign votes; the network sees it as offline.

### The wallet's trust model

The `clarity-wallet` CLI connects to a node's RPC endpoint. What it trusts depends on how it's used:

- **`balance <address>`** (no `--verify`): trusts the RPC endpoint. The endpoint could lie about the balance.
- **`balance <address> --verify`**: verifies the balance against a Merkle proof. The endpoint's response is verified locally with `State::verifyProof`. If the endpoint lies about the value, the proof fails.
- **`balance <address> --verify` with `connect-peer`**: two endpoints must agree on the state root before the wallet trusts either. This is stronger than a single endpoint but still trusts that at least one endpoint is honest.

**The wallet does not follow the header chain.** The state root it verifies against comes from the RPC endpoint, not from the chain. A fully trustless light client would fetch headers over P2P, follow the header chain, and obtain the current root independently. This is the next milestone.

**Signed transactions are broadcast via the RPC endpoint.** The wallet signs locally, then submits via `clrty_sendRawTransaction`. The endpoint could refuse to relay, delay the transaction, or drop it. It cannot forge a signature or alter the transaction without invalidating the signature.

## Operational security

### What an operator should protect

A validator operator should protect:

1. **The mnemonic.** The BIP-39 words are the only thing that needs to be backed up. Everything else is derived from them. Store the mnemonic in a secure, offline location.

2. **The consensus secret key.** Held by the daemon as `--consensus-key <hex>` (dev-only) or a `--consensus-key-file` when implemented. This is the key that signs votes. An attacker who extracts it can equivocate on the validator's behalf.

3. **The wallet keystore.** Encrypted with the operator's password. Should be stored on an encrypted filesystem, with a strong password.

4. **The daemon's binary and config.** A compromised binary could exfiltrate the consensus key. Verify the binary's hash before running it on a validator machine.

5. **The machine itself.** A validator that runs on a general-purpose machine exposes the consensus key to any software on that machine. Run validators on dedicated, hardened machines with restricted network access and no untrusted software.

### The consensus key is a live key

The consensus key is used for every vote the validator casts. It's held in the daemon's memory while the daemon runs. It's a live key: compromise means an attacker can sign on the validator's behalf, and the only way to stop them is to rotate the key (via `RotateConsensusKey`) or shut down the validator.

**Rotation is immediate.** The moment a `RotateConsensusKey` transaction commits, the old key is invalid for new signatures and the new key is authoritative. There is no grace period. A validator that rotates and then has a signing problem cannot fall back to the old key.

**Rotation is rejected for pending-unbond validators.** A validator that has started unregistering should not extend its signing window. The check is `validator.pending_unbond_height != 0`.

### The reward address is a policy knob

The reward address receives the validator's block rewards. It's a user-facing Ed25519 public key, normally backed by a mnemonic keystore. It's freely changeable via `UpdateRewardAddress`, with no effect on consensus participation.

**Update is one-way.** After `UpdateRewardAddress`, the new address becomes the validator's `owner` and can control all further parameter changes (rotation, reward address update, unregistration). The old address loses control. This is deliberate: it lets a validator hand off control to a new key while keeping the same validator identity.

**No two-step handoff.** There is no confirmation step from the new address. The old address can unilaterally transfer ownership. The mitigation is operational: don't use a reward address you don't control.

## Known limitations

### No slashing for liveness failures

A validator that is offline loses active-set membership through the offline-removal path, but its stake is not reduced. The only slashing offense is equivocation — a provable fact. Downtime, missed votes, and repeated timeouts are penalized only through loss of rotation priority and reward multiplier decay.

This is a design choice. Liveness failures are often environmental, and slashing for them would punish a validator for a datacenter outage rather than malice. The trade-off is that a validator with nothing to lose by being offline faces no economic penalty.

### No RPC authentication beyond the admin token

Read methods are unauthenticated. If the RPC endpoint is exposed to the public internet, anyone can query balances, blocks, and state roots. That's usually fine for a public node; it becomes a problem if the RPC endpoint is also used as a control plane.

The metrics endpoint is bound to loopback by default and has no authentication at all. The design assumes that a scrape endpoint on a private interface is not a secret.

**What an operator should do:** if the RPC endpoint is public, expose it behind a reverse proxy with rate limiting and authentication. If it's for local use, bind it to loopback and use the admin token for write methods.

### No divergence detection or repair

With the atomic commit discipline (state writes, block index writes, and head update in one MDBX transaction), divergence shouldn't be possible. If it happened — from a bug, or from a partially-written restart — the node has no detection or recovery path.

**What an operator should do:** if a node's state root diverges from the network's, the only recovery is to resync from scratch. Back up the data directory before upgrades; if a node's state is corrupted, restore from a known-good backup and resync.

### No cross-network genesis replay protection beyond chain ID

A transaction is signed over a chain ID, so a mainnet transaction cannot be replayed on testnet and vice versa. But two networks that share a chain ID would have compatible signatures. The design assumes the three networks use distinct chain IDs, and no runtime check enforces this beyond the genesis constant.

**What an operator should do:** never configure a node with a chain ID that's not from the pinned network constants. A private chain that wants to be replay-protected must use a unique chain ID.

### No light-client P2P proofs from the wallet

The wallet's `balance --verify` requests a proof over the `clrty_getProof` RPC method and verifies it locally. The proof itself is verified with the same `State::verifyProof` function a light client would use, so a server that lies about a balance produces a failing proof. But the *root* comes from the RPC endpoint, not from the chain.

A client that wants to trust no RPC endpoint at all would need to fetch headers over P2P, follow the header chain, and obtain the current root independently. That's the `GetHeaders`/`Headers` P2P pair plus header-chain verification in the wallet, and it's the next milestone.

**What an operator should do:** for high-value transactions, use two RPC endpoints and require them to agree on the root. For critical operations, run a full node and connect to it directly.

### The consensus WAL is not encrypted

The write-ahead log holds the votes a validator has signed and the locks it holds. It's stored in the MDBX database as plaintext. An attacker with read access to the validator's data directory can read the WAL and learn the validator's voting history.

The WAL does not contain private keys — the votes are signed, but the signing key is not in the WAL. Reading the WAL reveals *what* the validator voted for, not *how* it signed. This is not a direct compromise, but it's information an attacker might use.

**What an operator should do:** encrypt the validator's data directory at rest.

### The mempool is not encrypted

The mempool holds pending transactions. Transactions are signed and their signatures are verified on receipt, but the transactions themselves are stored in plaintext in the MDBX database. An attacker with read access to the data directory can read every pending transaction.

**What an operator should do:** encrypt the data directory at rest.

### No hardware-wallet support

There is no hardware-wallet protocol. A user who wants to isolate signing must use the `transaction_signer` binary on an air-gapped machine.

**What an operator should do:** for high-value keys, use `transaction_signer` on a machine that never touches the network. Transfer the signed transaction via USB or QR code.

### No multi-signature accounts

Every account has a single Ed25519 key. There is no mechanism for M-of-N multisig, no threshold signatures, no account abstraction.

**What an operator should do:** for accounts that need shared control, use a smart-contract layer (not available today) or split funds across multiple accounts.

### No transaction fees market mechanism

Transaction fees are fixed by the sender; the mempool accepts any fee above the minimum rate. There is no fee auction, no EIP-1559-style base fee, no dynamic fee adjustment. A transaction with a low fee may sit in the mempool indefinitely if the block is full.

**What an operator should do:** for time-sensitive transactions, pay a fee that's above the current median. The `getMempoolStats` RPC method reports the current fee distribution.

## What to do if you find a vulnerability

If you believe you've found a security vulnerability in Clarity, please report it privately rather than publicly. A disclosure that's exploited before it's fixed can cost users funds.

The project's preferred disclosure path is via a private channel — the maintainers' contact information is in the repository's `SECURITY.md` file (if it exists) or in the `README.md`. Do not open a public issue for a security bug.

Include in your report:

- **A description of the vulnerability.**
- **A minimal reproduction** (a test, a script, or a sequence of RPC calls) that demonstrates the issue.
- **The impact**: what an attacker can do, what an honest user loses, what the chain's behavior is under attack.
- **Any suggestions for a fix**, if you have them.

The maintainers will acknowledge your report, investigate the issue, and coordinate a fix and a disclosure timeline with you. Credit will be given in the release notes unless you request otherwise.

Thank you for helping keep Clarity secure.