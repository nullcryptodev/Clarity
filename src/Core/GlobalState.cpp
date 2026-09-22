// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "GlobalState.h"
#include "State/StateAccess.h"

namespace Core
{

  //  Encoders

  std::vector<uint8_t> encodeGlobalU64(uint64_t v)
  {
    std::vector<uint8_t> out(8);
    for (int i = 0; i < 8; ++i)
      out[i] = uint8_t(v >> (i * 8));
    return out;
  }

  bool decodeGlobalU64(const uint8_t *data, size_t len, uint64_t &out)
  {
    if (len != 8)
      return false;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v |= uint64_t(data[i]) << (i * 8);
    out = v;
    return true;
  }

  //  Reader

  namespace
  {
    uint64_t readGlobalU64(const State::StateAccess &access, std::string_view name)
    {
      std::vector<uint8_t> value;
      if (!access.getGlobal(std::string(name), value))
        return 0;
      uint64_t v = 0;
      decodeGlobalU64(value.data(), value.size(), v);
      return v;
    }
  } // anonymous namespace

  uint64_t GlobalStateReader::totalStaked() const
  {
    return readGlobalU64(access_, GLOBAL_TOTAL_STAKED);
  }

  uint64_t GlobalStateReader::pot() const
  {
    return readGlobalU64(access_, GLOBAL_POT);
  }

  uint64_t GlobalStateReader::epochNumber() const
  {
    return readGlobalU64(access_, GLOBAL_EPOCH_NUMBER);
  }

  uint64_t GlobalStateReader::totalSupply() const
  {
    return readGlobalU64(access_, GLOBAL_TOTAL_SUPPLY);
  }

  uint64_t GlobalStateReader::stakerCount() const
  {
    return readGlobalU64(access_, GLOBAL_STAKER_COUNT);
  }

  uint32_t GlobalStateReader::nextTokenId() const
  {
    return static_cast<uint32_t>(readGlobalU64(access_, GLOBAL_NEXT_TOKEN_ID));
  }

  uint64_t GlobalStateReader::nextOrderId() const
  {
    return readGlobalU64(access_, GLOBAL_NEXT_ORDER_ID);
  }

  uint64_t GlobalStateReader::nextValidatorId() const
  {
    return readGlobalU64(access_, GLOBAL_NEXT_VALIDATOR_ID);
  }

  uint32_t GlobalStateReader::activeSetSize() const
  {
    return static_cast<uint32_t>(readGlobalU64(access_, GLOBAL_ACTIVE_SET_SIZE));
  }

  uint64_t GlobalStateReader::lastRotationHeight() const
  {
    return readGlobalU64(access_, GLOBAL_LAST_ROTATION_H);
  }

  uint16_t GlobalStateReader::apyActivityBps() const
  {
    return static_cast<uint16_t>(readGlobalU64(access_, GLOBAL_APY_ACTIVITY_BPS));
  }

  uint16_t GlobalStateReader::apyPotBps() const
  {
    return static_cast<uint16_t>(readGlobalU64(access_, GLOBAL_APY_POT_BPS));
  }

  //  Writer

  namespace
  {
    void writeGlobalU64(State::StateAccess &access, std::string_view name, uint64_t v)
    {
      access.putGlobal(std::string(name), encodeGlobalU64(v));
    }
  } // anonymous namespace

  void GlobalStateWriter::setTotalStaked(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_TOTAL_STAKED, v);
  }

  void GlobalStateWriter::setPot(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_POT, v);
  }

  void GlobalStateWriter::setEpochNumber(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_EPOCH_NUMBER, v);
  }

  void GlobalStateWriter::setTotalSupply(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_TOTAL_SUPPLY, v);
  }

  void GlobalStateWriter::setStakerCount(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_STAKER_COUNT, v);
  }

  void GlobalStateWriter::setNextTokenId(uint32_t v)
  {
    writeGlobalU64(access_, GLOBAL_NEXT_TOKEN_ID, v);
  }

  void GlobalStateWriter::setNextOrderId(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_NEXT_ORDER_ID, v);
  }

  void GlobalStateWriter::setNextValidatorId(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_NEXT_VALIDATOR_ID, v);
  }

  void GlobalStateWriter::setActiveSetSize(uint32_t v)
  {
    writeGlobalU64(access_, GLOBAL_ACTIVE_SET_SIZE, v);
  }

  void GlobalStateWriter::setLastRotationHeight(uint64_t v)
  {
    writeGlobalU64(access_, GLOBAL_LAST_ROTATION_H, v);
  }

  void GlobalStateWriter::setApyActivityBps(uint16_t v)
  {
    writeGlobalU64(access_, GLOBAL_APY_ACTIVITY_BPS, v);
  }

  void GlobalStateWriter::setApyPotBps(uint16_t v)
  {
    writeGlobalU64(access_, GLOBAL_APY_POT_BPS, v);
  }

} // namespace Core