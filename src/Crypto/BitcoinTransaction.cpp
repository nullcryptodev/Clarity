// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BitcoinTransaction.h"

#include "Crypto/Sha256.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    //  Bitcoin's CompactSize. Used for script lengths, witness
    //  item counts, and input/output counts.
    //
    //    < 0xfd        : 1 byte, the value itself
    //    0xfd + u16LE  : up to 0xffff
    //    0xfe + u32LE  : up to 0xffffffff
    //    0xff + u64LE  : up to 2^64-1
    void writeVarInt(std::vector<uint8_t> &out, uint64_t v)
    {
      if (v < 0xfd)
      {
        out.push_back(static_cast<uint8_t>(v));
      }
      else if (v <= 0xffff)
      {
        out.push_back(0xfd);
        appendU16LE(out, static_cast<uint16_t>(v));
      }
      else if (v <= 0xffffffffULL)
      {
        out.push_back(0xfe);
        appendU32LE(out, static_cast<uint32_t>(v));
      }
      else
      {
        out.push_back(0xff);
        appendU64LE(out, v);
      }
    }

    //  Double-SHA256. Bitcoin's standard hash for txids, sighash,
    //  and merkle nodes. Note: Crypto::sha256 is the free function
    //  (lowercase); Crypto::Sha256 is the streaming class.
    Crypto::Hash doubleSha256(const uint8_t *data, size_t len)
    {
      uint8_t first[32];
      Crypto::sha256(data, len, first);
      Crypto::Hash out;
      Crypto::sha256(first, 32, out.data.data());
      return out;
    }

    Crypto::Hash doubleSha256(const std::vector<uint8_t> &v)
    {
      return doubleSha256(v.data(), v.size());
    }

    //  Serialize a single input's outpoint, script_sig, and
    //  sequence (the legacy wire body of an input). Witness is
    //  written separately by serialize().
    void writeInputLegacy(std::vector<uint8_t> &out, const BitcoinTxIn &in)
    {
      out.insert(out.end(), in.prev_txid.begin(), in.prev_txid.end());
      appendU32LE(out, in.prev_vout);
      writeVarInt(out, in.script_sig.size());
      out.insert(out.end(), in.script_sig.begin(), in.script_sig.end());
      appendU32LE(out, in.sequence);
    }

    void writeOutput(std::vector<uint8_t> &out, const BitcoinTxOut &o)
    {
      appendU64LE(out, o.value_sat);
      writeVarInt(out, o.script_pubkey.size());
      out.insert(out.end(), o.script_pubkey.begin(), o.script_pubkey.end());
    }
  } // anonymous namespace

  //  ---- Serialization primitives ----

  void appendU16LE(std::vector<uint8_t> &out, uint16_t v)
  {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
  }

  void appendU32LE(std::vector<uint8_t> &out, uint32_t v)
  {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 24));
  }

  void appendU64LE(std::vector<uint8_t> &out, uint64_t v)
  {
    for (int i = 0; i < 8; ++i)
      out.push_back(static_cast<uint8_t>(v >> (i * 8)));
  }

  void appendVarInt(std::vector<uint8_t> &out, uint64_t v)
  {
    writeVarInt(out, v);
  }

  //  ---- BitcoinTransaction ----

  bool BitcoinTransaction::hasWitness() const
  {
    for (const auto &in : inputs)
      if (!in.witness.empty())
        return true;
    return false;
  }

  std::vector<uint8_t> BitcoinTransaction::serializeNoWitness() const
  {
    std::vector<uint8_t> out;
    appendU32LE(out, version);
    writeVarInt(out, inputs.size());
    for (const auto &in : inputs)
      writeInputLegacy(out, in);
    writeVarInt(out, outputs.size());
    for (const auto &o : outputs)
      writeOutput(out, o);
    appendU32LE(out, locktime);
    return out;
  }

  std::vector<uint8_t> BitcoinTransaction::serialize() const
  {
    if (!hasWitness())
      return serializeNoWitness();

    std::vector<uint8_t> out;
    appendU32LE(out, version);

    //  BIP144: marker 0x00, flag 0x01. Emitted only when at least
    //  one input has a witness stack.
    out.push_back(0x00);
    out.push_back(0x01);

    writeVarInt(out, inputs.size());
    for (const auto &in : inputs)
      writeInputLegacy(out, in);
    writeVarInt(out, outputs.size());
    for (const auto &o : outputs)
      writeOutput(out, o);

    //  Witness stack per input. An input with an empty stack
    //  still gets a 0x00 count, per BIP144. The bridge only ever
    //  builds single-input transactions, so this is "one input,
    //  two witness items" in practice, but the loop is generic.
    for (const auto &in : inputs)
    {
      writeVarInt(out, in.witness.size());
      for (const auto &item : in.witness)
      {
        writeVarInt(out, item.size());
        out.insert(out.end(), item.begin(), item.end());
      }
    }

    appendU32LE(out, locktime);
    return out;
  }

  std::array<uint8_t, 32> BitcoinTransaction::txid() const
  {
    const auto bytes = serializeNoWitness();
    const Crypto::Hash h = doubleSha256(bytes);
    std::array<uint8_t, 32> out{};
    std::memcpy(out.data(), h.data.data(), 32);
    return out;
  }

  //  ---- BIP143 sighash (SIGHASH_ALL only) ----

  Crypto::Hash sighashBip143(
      const BitcoinTransaction &tx,
      size_t input_index,
      const std::vector<uint8_t> &script_code,
      uint64_t prev_output_value,
      uint32_t hash_type)
  {
    if (hash_type != 0x01) // SIGHASH_ALL is the only supported type
    {
      Crypto::Hash zero;
      return zero;
    }
    if (input_index >= tx.inputs.size())
    {
      Crypto::Hash zero;
      return zero;
    }

    //  hashPrevouts = double-SHA256(all outpoints).
    Crypto::Hash hash_prevouts;
    {
      std::vector<uint8_t> buf;
      buf.reserve(tx.inputs.size() * 36);
      for (const auto &in : tx.inputs)
      {
        buf.insert(buf.end(), in.prev_txid.begin(), in.prev_txid.end());
        appendU32LE(buf, in.prev_vout);
      }
      hash_prevouts = doubleSha256(buf);
    }

    //  hashSequence = double-SHA256(all input sequences).
    Crypto::Hash hash_sequence;
    {
      std::vector<uint8_t> buf;
      buf.reserve(tx.inputs.size() * 4);
      for (const auto &in : tx.inputs)
        appendU32LE(buf, in.sequence);
      hash_sequence = doubleSha256(buf);
    }

    //  hashOutputs = double-SHA256(all outputs).
    Crypto::Hash hash_outputs;
    {
      std::vector<uint8_t> buf;
      for (const auto &o : tx.outputs)
        writeOutput(buf, o);
      hash_outputs = doubleSha256(buf);
    }

    const auto &in = tx.inputs[input_index];

    //  BIP143 preimage (SIGHASH_ALL):
    //    nVersion        (4 LE)
    //    hashPrevouts    (32)
    //    hashSequence    (32)
    //    outpoint        (32 prev_txid || 4 prev_vout LE)  [this input]
    //    scriptCode      (varint len || bytes)
    //    amount          (8 LE)
    //    nSequence       (4 LE)  [this input]
    //    hashOutputs     (32)
    //    nLockTime       (4 LE)
    //    sighash type    (4 LE)
    std::vector<uint8_t> buf;
    buf.reserve(4 + 32 + 32 + 36 + 1 + script_code.size() +
                8 + 4 + 32 + 4 + 4);

    appendU32LE(buf, tx.version);
    buf.insert(buf.end(), hash_prevouts.data.begin(), hash_prevouts.data.end());
    buf.insert(buf.end(), hash_sequence.data.begin(), hash_sequence.data.end());
    buf.insert(buf.end(), in.prev_txid.begin(), in.prev_txid.end());
    appendU32LE(buf, in.prev_vout);
    writeVarInt(buf, script_code.size());
    buf.insert(buf.end(), script_code.begin(), script_code.end());
    appendU64LE(buf, prev_output_value);
    appendU32LE(buf, in.sequence);
    buf.insert(buf.end(), hash_outputs.data.begin(), hash_outputs.data.end());
    appendU32LE(buf, tx.locktime);
    appendU32LE(buf, hash_type);

    return doubleSha256(buf);
  }

} // namespace Crypto