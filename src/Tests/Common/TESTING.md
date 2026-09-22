# Common Testing Notes

The Common module contains pure utility functions with no dependencies
on other Clarity modules.

### Base58 and Base64 (`BaseTests.cpp`)

- Base58 round-trips for empty strings, ASCII, binary data, and every
  byte value 0–255.
- Base58 rejects characters outside its alphabet (`0`, `O`, `I`, `l`).
- **Base58 in this module is NOT Bitcoin-compatible.** It uses a
  CryptoNote-style block encoding and produces different output than
  standard Bitcoin Base58 for the same input. Do not use this for
  interop with external tools.
- Base64 covers all RFC 4648 test vectors, both directions. Round-trips
  all bytes 0–127. Ignores `' '`, `'\n'`, `'\t'` on decode.
  Standard-compliant and interoperable.

### CRC32 (`CRC32Tests.cpp`)

- IEEE 802.3 polynomial (same as zlib). Verified against four standard
  vectors including `"123456789"` → `0xCBF43926`.
- Deterministic; different inputs produce different checksums.

### JSON accessors (`JsonTests.cpp`)

- Typed getters with fallback: `getBoolOrDefault`, `getIntOrDefault`,
  `getStringOrDefault`, `getVectorOrDefault<T>`.
- Each tested for: present with correct value, missing with no
  default, missing with a default, wrong type (for bool).

### String tools (`StringToolsTests.cpp`)

- Hex encoding/decoding round-trip, uppercase input, odd length
  rejection, invalid character rejection.
- `podToHex` writes memory order — on little-endian the output of
  `podToHex(0xDEADBEEF)` is `"efbeadde"`. This is intentional but
  surprising; do not use for human-readable display.
- `extract` (stateful delimiter splitting) covers multi-item,
  no-delimiter, and offset-iteration cases.
- `ipAddressToString` and `parseIpAddressAndPort` cover IPv4 in
  network byte order.
- `timeIntervalToString` covers seconds through days, including a
  mixed case.

### Varint (`VarintTests.cpp`)

Thorough. Round-trips all integer widths (`uint8_t` through
`uint64_t`) at their power-of-2 boundaries. Verifies encoding sizes,
empty/incomplete input, overflow for narrow types, and both
buffer- and vector-based APIs.

## Constraints

- Base58 is not Bitcoin-compatible. If Clarity needs to interoperate
  with external Base58 tooling, replace with a big-integer-based
  encoder and re-add known vectors.
- `podToHex` byte order is memory-endian-dependent. Prefer `toHex`
  for portable output.
