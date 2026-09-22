# Crypto — Testing Notes

The lowest layer of the codebase. Depends only on Monocypher and the
standard library. Contains hashes, signatures, AEAD, and the
fixed-size byte-array wrappers used throughout the code.

Every primitive here is consensus-critical: block hashes, transaction
hashes, state roots, signatures, and address derivation all go
through this module. A bug here would produce silent, unrecoverable
divergence between nodes.

### Known-answer tests

- **Blake2b** (`Blake2bTests.cpp`): empty input, `"abc"`, longer
  message. All against reference values. The primary hash for block
  and transaction commitments.
- **Keccak-256 and SHA-3-256** (`KeccakTests.cpp`): empty and `"abc"`
  for both. The tests pin the distinction between Keccak padding
  (`0x01`) and SHA-3 padding (`0x06`). Same permutation, different
  output.
- **SHA-512** (`Sha512Tests.cpp`): empty, `"abc"`, longer message
  against RFC 6234 vectors.

### Ed25519 (`Ed25519Tests.cpp`)

Three layers of testing:

1. **Raw Monocypher.** Bypasses the wrapper to distinguish wrapper
   bugs from library bugs. If the raw test fails, Monocypher or its
   linkage is wrong; if it passes and the wrapper test fails, the
   wrapper is wrong.
2. **RFC 8032 vectors via the wrapper.** Test 1 (empty message),
   Test 2 (one byte), Test 3 (two bytes). Verifies key derivation,
   signing, and verification against the exact RFC vectors.
3. **Round-trip and negative tests.** Generate, sign, verify;
   reject tampered signature, wrong message, wrong key.
   `DeterministicFromSeed` verifies deterministic key derivation.

### ChaCha20-Poly1305 (`ChaChaTests.cpp`)

- Encrypt/decrypt round-trip.
- Tampered ciphertext rejected.
- Tampered MAC rejected.
- Different nonces produce different ciphertexts.

## The boundary this module has

Crypto is a leaf dependency. Every other module depends on it, and
it depends on nothing else in the codebase. When Crypto changes, the
change is felt everywhere; when Crypto is correct, it can be trusted
in isolation.

The three known-answer tests for Blake2b are the most important in
the entire codebase. If they fail, every block hash, transaction
hash, state root, merkle root, and receipt hash is wrong, and the
failure would manifest as consensus failure rather than as a hash
test failure. When modifying `Blake2b.cpp` or the Monocypher linkage,
always run these three first.