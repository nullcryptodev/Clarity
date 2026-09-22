# Serialization Testing Notes

Serialization provides three serializers used across the codebase:

- **BinarySerializer** — the primary on-disk and wire format.
- **KVBinarySerializer** — a variant with a signature prefix and version
  byte, used for structured state entries and metadata.
- **JsonSerializer** — diagnostics, RPC responses, and debug output.

The test suite runs a shared set of test types (`TestTypes.h`) through
each serializer and verifies round-trip.

### Binary format (`BinarySerializerTests.cpp`)

The largest test file. Round-trips every primitive type (`uint8_t`
through `uint64_t`, `int8_t` through `int64_t`, `bool`, `std::string`),
structs of every primitive (`SimpleType`), nested structs
(`NestedType`), binary blobs and fixed-size crypto types
(`BinaryType`), enums (`EnumType`), vectors, maps, and varints at
boundaries.

Special cases:
- String with embedded null byte (`StringWithSpecialChars`).
- Varint at `0x7F`, `0x80`, `0xFF`, `0x1000`, and
  `0xFFFFFFFFFFFFFFFF`.
- Large negative integers.
- 1000-element vector, 10000-character string.

### JSON format (`JsonSerializerTests.cpp`)

Primitives, one struct (`SimpleType`), pretty-print output, and
malformed-input rejection. **Complex types (`NestedType`,
`BinaryType`, `EnumType`) are not tested through JSON.**

### Key-value binary format (`KVBinarySerializerTests.cpp`)

Signature and version validation on construction. Whether the file
contains broader round-trip coverage is not visible in the excerpt
reviewed.

### Shared test types (`TestTypes.h`)

Four types used across all serializer tests, each with a
`serialize(ISerializer&)` method and an `operator==` for round-trip
comparison. The comment in `BinaryType::operator==` notes that
`Crypto::Hash` and `Crypto::Signature` provide `operator==` via their
`ByteArray` base class, so manual `memcmp` is not needed.

## The boundaries this module has

Serialization is called from every other module. Its inputs are
arbitrary bytes from the network (P2P messages), arbitrary bytes from
disk (chain state), and values from every in-memory struct in the
codebase. That makes it a place where a bug has wide reach: a subtle
byte-order mistake in the length prefix would corrupt every message
that uses it.

The tests exercise round-trip correctness (write then read gives the
same value) but not defensive correctness (read of malformed input
fails safely). When adding tests here, prefer ones that feed malformed
or adversarial input to the deserializer over ones that verify another
primitive type round-trips.