// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "Crypto/Types.h"

namespace Crypto
{
  //  =========================================================================
  //  Bitcoin transaction wire format and BIP143 signing hash
  //
  //  Serialization, txid computation, and the segwit v0 signing
  //  hash. No signing (that is BitcoinEcdsa), no script
  //  interpretation (the bridge only ever spends P2WPKH), no
  //  consensus rules beyond what a single-input P2WPKH spend needs.
  //
  //  BIP143 is the ONLY signing hash implemented. Legacy
  //  (pre-segwit) sighash is not implemented and not needed: every
  //  custody output is P2WPKH by construction (BIP84), and the
  //  change output is P2WPKH to the same source address. A
  //  legacy-signing path would be dead code, and dead signing code
  //  is a footgun.
  //
  //  BIP143 test vector (from the BIP itself) is exercised in
  //  src/Tests/Crypto/BitcoinTransaction.cpp. Do not modify the
  //  sighash construction without re-running it.
  // =========================================================================

  //  One transaction input. For P2WPKH spends script_sig is empty
  //  (the signature lives in the witness stack); witness has
  //  exactly two items: [sig_der || sighash_byte], [compressed_pubkey].
  //
  //  prev_txid is stored in WIRE order (little-endian of the
  //  display txid): if the display txid is "ab...ef", the wire
  //  bytes are ef ... ab. Callers convert at the boundary; this
  //  struct does not.
  struct BitcoinTxIn
  {
    std::array<uint8_t, 32> prev_txid{};
    uint32_t prev_vout{0};
    std::vector<uint8_t> script_sig; // empty for P2WPKH
    uint32_t sequence{0xFFFFFFFF};
    std::vector<std::vector<uint8_t>> witness; // empty for legacy
  };

  struct BitcoinTxOut
  {
    uint64_t value_sat{0};
    std::vector<uint8_t> script_pubkey;
  };

  struct BitcoinTransaction
  {
    uint32_t version{2};
    std::vector<BitcoinTxIn> inputs;
    std::vector<BitcoinTxOut> outputs;
    uint32_t locktime{0};

    //  Wire form, WITH the segwit marker/flag and witness stacks.
    //  This is what gets broadcast. Uses BIP144 serialization:
    //    version || 0x00 0x01 || inputs || outputs ||
    //    witness-stack-per-input || locktime
    //
    //  A transaction with no witness stacks serializes
    //  identically under serialize() and serializeNoWitness()
    //  (no marker/flag is emitted). Callers must not assume
    //  serialize() is always longer than serializeNoWitness().
    //
    //  An empty inputs or outputs vector produces a malformed
    //  transaction; the caller is responsible for building a
    //  valid shape. This function does not validate.
    std::vector<uint8_t> serialize() const;

    //  Wire form WITHOUT segwit marker/flag or witness stacks.
    //  This is the legacy serialization, which is what the txid
    //  commits to (BIP141: txid = double-SHA256(serializeNoWitness())).
    std::vector<uint8_t> serializeNoWitness() const;

    //  txid = double-SHA256(serializeNoWitness()), returned in
    //  WIRE order (i.e. the little-endian byte sequence you'd
    //  store in BitcoinTxIn::prev_txid when spending this output).
    //  The display txid is the reverse of these bytes.
    std::array<uint8_t, 32> txid() const;

    //  True if any input has a non-empty witness stack. Used to
    //  decide whether serialize() emits the marker/flag at all.
    bool hasWitness() const;
  };

  //  BIP143 sighash for witness v0 (P2WPKH, P2WSH).
  //
  //  Inputs:
  //    tx                the transaction being signed (its inputs'
  //                      script_sig and witness are NOT committed
  //                      to by the sighash; only the outpoints,
  //                      sequence numbers, outputs, and the
  //                      current input's outpoint/script/amount/
  //                      sequence are)
  //    input_index       which input is being signed (0-based)
  //    script_code       the scriptPubKey of the output being
  //                      spent. For P2WPKH, that's the 22-byte
  //                      0x0014<20-byte-hash>. BIP143 calls this
  //                      "scriptCode"; for P2WPKH it's the same
  //                      as the scriptPubKey.
  //    prev_output_value the value (in satoshis) of the output
  //                      being spent — required by BIP143 and
  //                      committed to in the sighash
  //    hash_type         must be 0x01 (SIGHASH_ALL). Every other
  //                      value returns a null Hash. The bridge
  //                      only ever signs SIGHASH_ALL, and the
  //                      SIGHASH_SINGLE / NONE / ANYONECANPAY
  //                      branches of BIP143 each have edge-case
  //                      quirks that would be dead-but-untested
  //                      code here. Restricting to SIGHASH_ALL
  //                      makes "only ALL is supported" a property
  //                      of the implementation rather than a
  //                      comment.
  //
  //  Returns the 32-byte signing hash, ready for ECDSA signing.
  //  On out-of-range input_index or non-SIGHASH_ALL hash_type,
  //  returns a null Hash.
  Crypto::Hash sighashBip143(
      const BitcoinTransaction &tx,
      size_t input_index,
      const std::vector<uint8_t> &script_code,
      uint64_t prev_output_value,
      uint32_t hash_type);

  //  Serialization primitives. Exposed for testing (the BIP143
  //  test vector builds its preimage by hand in some references)
  //  and for other Bitcoin wire uses that aren't a full
  //  transaction.
  void appendU16LE(std::vector<uint8_t> &out, uint16_t v);
  void appendU32LE(std::vector<uint8_t> &out, uint32_t v);
  void appendU64LE(std::vector<uint8_t> &out, uint64_t v);
  void appendVarInt(std::vector<uint8_t> &out, uint64_t v);

} // namespace Crypto