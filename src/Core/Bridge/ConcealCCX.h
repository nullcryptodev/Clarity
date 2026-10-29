// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "Common/Base.h"
#include "Common/Varint.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"
#include "Crypto/Keccak.h"
#include "Core/BridgeTypes.h"
#include "Core/TokenTypes.h"

extern "C"
{
#include "Crypto/crypto-ops.h"
}

namespace Core
{
  //  =========================================================================
  //  ConcealCCX Bridge
  //
  //  The CCX adapter. Everything the chain-agnostic bridge core needs to
  //  know about CCX, and nothing else. This is the *only* file in the
  //  bridge that knows CCX exists; the generic core (BridgeTypes,
  //  StateAccess, TransactionExecutor) reads the registration and the
  //  signer set out of state and does not know which chain they describe.
  //
  //  Three responsibilities:
  //
  //    1. Constants: the CCX chain id (as the bridge sees it), the
  //       decimal scale, the confirmation depth, the wrapped-token
  //       metadata, and the destination blob bounds.
  //
  //    2. Destination codec: CCX addresses are 64 bytes (a spend
  //       public key and a view public key, each 32 bytes). The codec
  //       converts between the typed pair and the opaque blob the
  //       bridge stores, and between the blob and the base58 string
  //       a CCX wallet RPC expects.
  //
  //    3. Fingerprint: the wrapped-CCX token's fingerprint is a
  //       commitment to (chain id, asset id). It pins the token to
  //       CCX; a token without this fingerprint is rejected by the
  //       executor on every mint and burn.
  //
  //  Everything here is header-inline because it is small, pure, and
  //  the definitions are needed by the CCX watcher (file 12) and by
  //  any test that exercises the CCX bridge. There is no .cpp.
  //
  //  If a second bridge is added (say, a Monero bridge), it gets its
  //  own header — `MoneroBridge.h`, with its own chain id, its own
  //  decimals, its own destination codec, its own fingerprint — and
  //  the generic core doesn't need to know it exists. This is the
  //  whole point of the chain-adapter layer.
  //  =========================================================================

  namespace CcxBridge
  {
    //  ---------------------------------------------------------------------
    //  Identity
    //  ---------------------------------------------------------------------

    //  The CCX chain id, as the bridge sees it. This is a bridge-internal
    //  identifier, not the chain's own id (CCX's mainnet chain id is
    //  whatever CCX uses internally; the bridge only cares that this
    //  number is unique among registered chains and stable).
    //
    //  'CCX1' in ASCII, big-endian:
    //    C  = 0x43
    //    C  = 0x43
    //    X  = 0x58
    //    1  = 0x31
    //  packed as a 64-bit integer so it's memorable in hex and
    //  distinct from any other chain id a future adapter might use.
    inline constexpr uint64_t CCX_CHAIN_ID = 0x43435831ULL;

    //  The asset id of CCX's own native token, within CCX's own
    //  namespace. CCX has one native asset; the id 1 is used here
    //  to distinguish it from a future bridged asset that isn't the
    //  native coin. (Asset id 0 is reserved for "unknown / not
    //  applicable" throughout the bridge.)
    inline constexpr uint64_t CCX_NATIVE_ASSET_ID = 1ULL;

    //  ---------------------------------------------------------------------
    //  Decimals and conversion
    //  ---------------------------------------------------------------------

    //  CCX's atomic unit has 6 decimals (`COIN = 1,000,000` in the
    //  CCX crypto config). Clarity's atomic unit has 5
    //  (`ATOMIC_UNITS_PER_COIN = 100,000`).
    //
    //  The wrapped-CCX token on Clarity has 6 decimals, matching
    //  CCX's own. This means a CCX amount and the wCCX amount are
    //  the same atomic number: a deposit of `A` CCX atomic units
    //  mints `A` wCCX atomic units. There is no scaling factor and
    //  no rounding. The value is preserved exactly.
    //
    //  (An earlier design used 5 clarity decimals and divided by
    //  ten, which produced a display bug — a 1.0 CCX deposit
    //  showed as 10 wCCX. Matching the source decimals is the fix.)
    inline constexpr uint8_t CCX_SOURCE_DECIMALS = 6;
    inline constexpr uint8_t CCX_CLARITY_DECIMALS = 6;

    //  ---------------------------------------------------------------------
    //  Confirmation depth
    //  ---------------------------------------------------------------------

    //  Number of CCX blocks a deposit must be buried under before the
    //  watcher will build a BridgeMint. CCX uses PoW with a 120-second
    //  target block time (from DIFFICULTY_TARGET in the CCX config);
    //  20 blocks is roughly 40 minutes of confirmation, which is
    //  conservative for a PoW chain of CCX's size.
    //
    //  This value is stored in the chain registration and read by
    //  the watcher; it is *informational* to the executor (the
    //  executor doesn't verify the depth; the federation's signature
    //  attests that the watcher observed the depth, and the watcher's
    //  policy is enforced off-chain). The registration field is
    //  duplicated here so the watcher doesn't have to hardcode it.
    inline constexpr uint16_t CCX_CONFIRMATION_DEPTH = 20;

    //  ---------------------------------------------------------------------
    //  Destination codec
    //  ---------------------------------------------------------------------

    //  A CCX address is the pair (spend_public_key, view_public_key),
    //  each a 32-byte Ed25519 public key (in Cryptonote's ed25519
    //  variant, but the byte size is 32). The bridge stores the pair
    //  as a 64-byte blob in a BridgeWithdrawal's destination_blob.
    //
    //  The blob's layout is exactly the pair in order:
    //    [0..32)   spend_public_key
    //    [32..64)  view_public_key
    //
    //  This is what a MultisignatureInput's `keys[0]` and the
    //  AccountPublicAddress require. The order matches Cryptonote's
    //  AccountPublicAddress (spend, then view), which is what the
    //  watcher needs to reconstruct on the CCX side.

    inline constexpr size_t CCX_DESTINATION_BYTES = 64;
    inline constexpr size_t CCX_DESTINATION_MIN_BYTES = 64;
    inline constexpr size_t CCX_DESTINATION_MAX_BYTES = 64;

    //  Encode a (spend, view) pair as the 64-byte blob.
    //
    //  Returns an empty vector on a null key — the bridge refuses
    //  to encode a destination with a null pubkey (the resulting
    //  blob would be a valid length but encode an address no one
    //  can spend from, which would be a loss-of-funds bug).
    inline std::vector<uint8_t> encodeDestination(
        const Crypto::PublicKey &spend,
        const Crypto::PublicKey &view)
    {
      if (spend.isNull() || view.isNull())
        return {};

      std::vector<uint8_t> out(CCX_DESTINATION_BYTES);
      std::memcpy(out.data(), spend.data.data(), 32);
      std::memcpy(out.data() + 32, view.data.data(), 32);
      return out;
    }

    //  Decode the 64-byte blob into a (spend, view) pair.
    //
    //  Returns false on any malformation: wrong length, null
    //  key. The null check is the same loss-of-funds guard as on
    //  the encode side — a destination with a null key is not a
    //  valid CCX address and must not be released to.
    inline bool decodeDestination(const std::vector<uint8_t> &blob,
                                  Crypto::PublicKey &spend_out,
                                  Crypto::PublicKey &view_out)
    {
      if (blob.size() != CCX_DESTINATION_BYTES)
        return false;

      std::memcpy(spend_out.data.data(), blob.data(), 32);
      std::memcpy(view_out.data.data(), blob.data() + 32, 32);

      if (spend_out.isNull() || view_out.isNull())
        return false;

      return true;
    }

    //  ---------------------------------------------------------------------
    //  Subaddress derivation
    //  ---------------------------------------------------------------------
    //
    //  The bridge owns the CCX custody wallet end-to-end. To let each
    //  Clarity user deposit to a distinct CCX address, the bridge
    //  derives a fresh subaddress per registration index from the
    //  custody wallet's (spend_pub, view_priv) pair. The derivation
    //  is bridge-owned — it does NOT match conceal-wallet-rpc's
    //  internal Monero-compatible subaddress construction, and is
    //  not meant to. The custody wallet is exclusively bridge-owned,
    //  so its own subaddress set is never queried; a derived
    //  subaddress is only ever seen by CCX as "an address someone
    //  sent to," which is exactly what it is.
    //
    //  Construction:
    //
    //    domain        = "clrty-sa" || LE64(source_chain_id) || LE64(index)
    //    m             = sc_reduce32(cnFastHash(domain))
    //    sub_spend_pub = spend_pub + m*G
    //    sub_view_pub  = view_priv * sub_spend_pub
    //
    //  The domain tag "clrty-sa" (8 bytes, unlike the 4-byte tags in
    //  Keys.h, because this isn't an SMT key and there's no
    //  collision space to share) distinguishes the bridge's
    //  subaddress space from any other use of the custody wallet's
    //  keys. The chain id is included so a subaddress derived on
    //  one CCX deployment (mainnet, testnet) never collides with a
    //  subaddress derived on another — the two have different
    //  chain ids from the bridge's perspective.
    //
    //  The `index` is the value stored in BridgeDepositRecord.index,
    //  assigned by the executor. Every caller (the deposit scanner,
    //  the RPC, the wallet) derives the same subaddress for the same
    //  (chain, index) pair because the inputs are identical and the
    //  construction is deterministic.
    //
    //  Returns false if:
    //    - spend_pub is not a valid curve point (ge_frombytes_vartime
    //      fails),
    //    - view_priv is not a valid scalar (sc_check fails),
    //    - or the resulting spend or view key is null (would indicate
    //      a hostile input rather than a computation failure — the
    //      check is defensive).
    //
    //  The null-key check is the same loss-of-funds guard
    //  encodeDestination applies: a subaddress with a null half is
    //  not spendable, and must not be handed out as a deposit
    //  destination.

    inline bool deriveSubaddress(
        const Crypto::PublicKey &spend_pub,
        const Crypto::SecretKey &view_priv,
        uint64_t source_chain_id,
        uint64_t index,
        Crypto::PublicKey &sub_spend_out,
        Crypto::PublicKey &sub_view_out)
    {
      if (spend_pub.isNull() || view_priv.isNull())
        return false;

      //  ---- Domain ----
      //
      //  "clrty-sa" is 8 bytes; source_chain_id and index are 8
      //  bytes each LE; total 24 bytes.
      unsigned char domain[8 + 8 + 8];
      std::memcpy(domain, "clrty-sa", 8);
      for (int i = 0; i < 8; ++i)
        domain[8 + i] = uint8_t(source_chain_id >> (i * 8));
      for (int i = 0; i < 8; ++i)
        domain[16 + i] = uint8_t(index >> (i * 8));

      //  ---- m = sc_reduce32(cnFastHash(domain)) ----
      //
      //  sc_reduce32 takes a 32-byte hash and reduces it modulo ℓ.
      //  The intermediate hash buffer is zeroed after use.
      unsigned char m[32];
      Crypto::cnFastHash(domain, sizeof(domain), m);
      sc_reduce32(m);

      //  ---- sub_spend_pub = spend_pub + m*G ----

      ge_p3 spend_p3;
      if (ge_frombytes_vartime(
              &spend_p3,
              reinterpret_cast<const unsigned char *>(
                  spend_pub.data.data())) != 0)
      {
        Crypto::secureZero(m, sizeof(m));
        return false;
      }

      ge_p3 mG;
      ge_cached cached;
      ge_p1p1 p1p1;
      ge_p2 spend_p2;

      ge_scalarmult_base(&mG, m);
      ge_p3_to_cached(&cached, &mG);
      ge_add(&p1p1, &spend_p3, &cached);
      ge_p1p1_to_p2(&spend_p2, &p1p1);

      unsigned char spend_buf[32];
      ge_tobytes(spend_buf, &spend_p2);
      std::memcpy(sub_spend_out.data.data(), spend_buf, 32);

      //  ---- sub_view_pub = view_priv * sub_spend_pub ----

      if (sc_check(reinterpret_cast<const unsigned char *>(
              view_priv.data.data())) != 0)
      {
        Crypto::secureZero(m, sizeof(m));
        Crypto::secureZero(spend_buf, sizeof(spend_buf));
        return false;
      }

      //  sub_spend_out is now a valid point (the result of an
      //  addition of two valid points), so this ge_frombytes_vartime
      //  cannot fail — but we check anyway for symmetry with the
      //  spend input above, and because a future change to ge_add
      //  semantics would be caught here rather than downstream.
      ge_p3 sub_spend_p3;
      if (ge_frombytes_vartime(&sub_spend_p3, spend_buf) != 0)
      {
        Crypto::secureZero(m, sizeof(m));
        Crypto::secureZero(spend_buf, sizeof(spend_buf));
        return false;
      }

      ge_p2 view_p2;
      ge_scalarmult(
          &view_p2,
          reinterpret_cast<const unsigned char *>(view_priv.data.data()),
          &sub_spend_p3);

      unsigned char view_buf[32];
      ge_tobytes(view_buf, &view_p2);
      std::memcpy(sub_view_out.data.data(), view_buf, 32);

      Crypto::secureZero(m, sizeof(m));
      Crypto::secureZero(spend_buf, sizeof(spend_buf));
      Crypto::secureZero(view_buf, sizeof(view_buf));

      //  ---- Null-key guard ----

      if (sub_spend_out.isNull() || sub_view_out.isNull())
        return false;

      return true;
    }

    //  Convenience: derive the subaddress and encode it as the
    //  64-byte (spend || view) destination blob. Same checks as the
    //  typed overload; an empty return means the derivation failed
    //  (invalid spend_pub, invalid view_priv, or a null resulting
    //  key).
    inline std::vector<uint8_t> deriveSubaddressBlob(
        const Crypto::PublicKey &spend_pub,
        const Crypto::SecretKey &view_priv,
        uint64_t source_chain_id,
        uint64_t index)
    {
      Crypto::PublicKey sub_spend, sub_view;
      if (!deriveSubaddress(spend_pub, view_priv,
                            source_chain_id, index,
                            sub_spend, sub_view))
        return {};
      return encodeDestination(sub_spend, sub_view);
    }

    //  Encode a (spend ‖ view) blob as a CCX base58 address.
    //
    //  The layout matches CryptoNote's canonical address encoding:
    //
    //    [varint network_prefix]
    //    [spend key, 32 bytes]
    //    [view key, 32 bytes]
    //    [checksum, 4 bytes]
    //
    //  where the checksum is the first 4 bytes of
    //  cn_fast_hash(prefix_bytes || spend || view) — Keccak-256
    //  with 0x01 padding, matching Crypto::keccak256. The whole
    //  payload is then base58-encoded with the CryptoNote base58
    //  alphabet, which is what Common::encodeBase58 implements.
    //
    //  The `network_prefix` is a deployment property, not a
    //  chain-identity property: CCX mainnet and CCX testnet share a
    //  chain id (from the bridge's perspective) but use different
    //  prefix bytes. The caller supplies it, typically from config
    //  (see CcxAdapter::set_network_prefix).
    //
    //  Returns an empty string if:
    //    - blob is not exactly 64 bytes,
    //    - either 32-byte half is all-zero (no valid CCX address has
    //      a null spend or view key),
    //    - checksum computation fails (would indicate a library bug).
    //
    //  Round-trip guarantee: for any valid (spend, view) pair on the
    //  network whose prefix is `network_prefix`,
    //
    //    CcxAdapter::parse_deposit_address(
    //        encodeDestinationAsBase58(
    //            encodeDestination(spend, view),
    //            network_prefix)) == encodeDestination(spend, view)
    //
    //  as long as `parse_deposit_address` is called on the same
    //  network. The checksum validation on the parse side guarantees
    //  the round-trip in the presence of a corrupted prefix byte.
    inline std::string encodeDestinationAsBase58(
        const std::vector<uint8_t> &blob,
        uint64_t network_prefix)
    {
      if (blob.size() != CCX_DESTINATION_BYTES)
        return {};

      //  Refuse null keys: a blob with a null half would produce a
      //  syntactically valid base58 string, but the wallet RPC on
      //  the other side would either reject it or (worse) accept it
      //  and later fail to spend from it. The encodeDestination
      //  helper refuses nulls too; this is the belt-and-braces check
      //  on the raw blob, for callers that construct blobs directly.
      Crypto::PublicKey spend_pk, view_pk;
      std::memcpy(spend_pk.data.data(), blob.data(), 32);
      std::memcpy(view_pk.data.data(), blob.data() + 32, 32);
      if (spend_pk.isNull() || view_pk.isNull())
        return {};

      //  Build the payload:
      //    [varint prefix] [spend] [view] [checksum]

      std::vector<uint8_t> payload;
      payload.reserve(1 + 64 + 4);

      Common::write_varint_to_vector<uint64_t>(network_prefix, payload);

      payload.insert(payload.end(), blob.begin(), blob.begin() + 32);
      payload.insert(payload.end(), blob.begin() + 32, blob.begin() + 64);

      //  CryptoNote's address checksum is the first 4 bytes of
      //  cn_fast_hash(payload). In this codebase, cn_fast_hash is
      //  Crypto::keccak256 (Keccak-256 with 0x01 padding, not
      //  FIPS-202 SHA3-256). Using Blake2b here produced a
      //  syntactically valid base58 string that walletd rejected
      //  as an invalid address — see handover §7.8.
      Crypto::Hash checksum;
      Crypto::keccak256(payload.data(), payload.size(),
                        checksum.data.data());

      payload.push_back(checksum.data[0]);
      payload.push_back(checksum.data[1]);
      payload.push_back(checksum.data[2]);
      payload.push_back(checksum.data[3]);

      //  Base58-encode the whole payload. Common::encodeBase58
      //  takes a string_view; the payload is bytes, so we cast
      //  through a string_view over the same memory.
      return Common::encodeBase58(
          std::string_view(reinterpret_cast<const char *>(payload.data()),
                           payload.size()));
    }

    //  ---------------------------------------------------------------------
    //  Wrapped-token fingerprint
    //  ---------------------------------------------------------------------

    //  The wrapped-CCX token's fingerprint. A TokenInfo with
    //  `backing = Backed` and this fingerprint is recognized by the
    //  executor as the wrapped-CCX token; a token with any other
    //  fingerprint (or none) is rejected on every mint and burn.
    //
    //  The fingerprint is:
    //
    //    Blake2b("ccw" || LE64(chain_id) || LE64(asset_id))
    //
    //  The domain tag "ccw" (3 bytes, unlike the 4-byte tags
    //  elsewhere) is here because the fingerprint's construction is
    //  not part of the state-key namespace — it's a data fingerprint,
    //  not an SMT key — and a 3-byte tag is enough to be distinct
    //  from any other hash the bridge computes. (The 4-byte
    //  convention is for `hashDomain` calls that become SMT keys;
    //  this fingerprint never becomes a key, it becomes the
    //  TokenInfo's `fingerprint` field.)
    //
    //  The inclusion of both the chain id and the asset id means
    //  the fingerprint commits to "this is CCX's native asset,
    //  bridged" — not just "this is CCX" and not just "this is
    //  asset 1". A future bridged asset from CCX would have a
    //  different asset id and therefore a different fingerprint.

    inline Crypto::Hash wrappedTokenFingerprint()
    {
      uint8_t buf[3 + 8 + 8];
      std::memcpy(buf, "ccw", 3);

      uint8_t *p = buf + 3;
      for (int i = 0; i < 8; ++i)
        p[i] = uint8_t(CCX_CHAIN_ID >> (i * 8));
      p += 8;
      for (int i = 0; i < 8; ++i)
        p[i] = uint8_t(CCX_NATIVE_ASSET_ID >> (i * 8));

      Crypto::Hash h;
      Crypto::blake2b(buf, sizeof(buf), h.data.data(), h.data.size());
      return h;
    }

    //  ---------------------------------------------------------------------
    //  Wrapped-token metadata
    //  ---------------------------------------------------------------------

    //  The name, symbol, and decimals that the genesis (or a future
    //  registration) writes into the wrapped-CCX TokenInfo. The
    //  executor does not check these (it checks the fingerprint,
    //  which is stricter); they exist so the genesis writer and the
    //  RPC display don't hardcode string literals.
    //
    //  The symbol is "wCCX" rather than "CCX" to distinguish the
    //  wrapped asset from the source asset in any display. The
    //  wrapped token has 6 decimals, matching CCX's own; a user
    //  holding 1.000000 wCCX is owed 1.000000 CCX on release. The
    //  amount is preserved exactly, with no scaling factor.
    inline constexpr std::string_view CCX_WRAPPED_NAME = "Wrapped CCX";
    inline constexpr std::string_view CCX_WRAPPED_SYMBOL = "wCCX";
    inline constexpr uint8_t CCX_WRAPPED_DECIMALS = CCX_CLARITY_DECIMALS;

    //  ---------------------------------------------------------------------
    //  Sanity assertions
    //  ---------------------------------------------------------------------
    //
    //  These fire at compile time if a constant is ever changed to a
    //  value that breaks a downstream assumption. They are cheap and
    //  they make the "which number changed?" question answerable
    //  from the compiler output.

    static_assert(CCX_SOURCE_DECIMALS == CCX_CLARITY_DECIMALS,
                  "CCX and Clarity decimals must match under the "
                  "value-preserving design: a CCX amount and its wCCX "
                  "amount are the same atomic number. If a future chain "
                  "needs scaling, that is a different adapter with a "
                  "different conversion direction and its own static "
                  "asserts.");
    static_assert(CCX_DESTINATION_MIN_BYTES == CCX_DESTINATION_BYTES &&
                      CCX_DESTINATION_MAX_BYTES == CCX_DESTINATION_BYTES,
                  "CCX destinations are a fixed 64 bytes (spend || view). "
                  "A future variant that allowed multiple address formats "
                  "would need to widen these bounds and the codec.");
    static_assert(CCX_DESTINATION_BYTES == 64,
                  "CCX address = 32-byte spend key + 32-byte view key.");
    static_assert(CCX_CONFIRMATION_DEPTH >= 6,
                  "Fewer than 6 CCX confirmations is not a plausible "
                  "reorg-safety depth on a PoW chain of CCX's size. If "
                  "you're lowering this, you're lowering the bridge's "
                  "reorg safety, and the assert is here to make you say "
                  "so explicitly.");

  } // namespace CcxBridge

} // namespace Core