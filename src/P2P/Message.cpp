// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Message.h"

#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>
#include <stdexcept>

namespace P2P
{
  std::vector<uint8_t> encodeMessage(const Message &msg,
                                     uint32_t magic,
                                     uint32_t maxSize)
  {
    if (msg.payload.size() > maxSize)
    {
      throw std::length_error("P2P: payload exceeds maximum message size");
    }

    std::vector<uint8_t> out;
    out.reserve(MESSAGE_HEADER_SIZE + msg.payload.size());

    Common::putU32(out, magic);                                     // [0..3]
    Common::putU16(out, static_cast<uint16_t>(msg.type));           // [4..5]
    Common::putU32(out, static_cast<uint32_t>(msg.payload.size())); // [6..9]

    if (!msg.payload.empty())
    {
      out.insert(out.end(), msg.payload.begin(), msg.payload.end());
    }

    return out;
  }

  void MessageDecoder::feed(const uint8_t *data, size_t len)
  {
    if (len == 0)
      return;
    buffer_.insert(buffer_.end(), data, data + len);
  }

  DecodeResult MessageDecoder::next()
  {
    if (buffer_.size() < MESSAGE_HEADER_SIZE)
    {
      return {DecodeStatus::NeedMoreData, std::nullopt};
    }

    const uint8_t *p = buffer_.data();
    uint32_t magic = Common::readU32(p + 0);
    uint16_t type =  Common::readU16(p + 4);
    uint32_t size =  Common::readU32(p + 6);

    if (magic != magic_)
    {
      return {DecodeStatus::Corrupted, std::nullopt};
    }
    if (size > maxSize_)
    {
      return {DecodeStatus::Corrupted, std::nullopt};
    }
    if (buffer_.size() < MESSAGE_HEADER_SIZE + size)
    {
      return {DecodeStatus::NeedMoreData, std::nullopt};
    }

    Message msg;
    msg.type = static_cast<MessageType>(type);
    msg.payload.assign(p + MESSAGE_HEADER_SIZE, p + MESSAGE_HEADER_SIZE + size);

    buffer_.erase(buffer_.begin(),
                  buffer_.begin() + MESSAGE_HEADER_SIZE + size);

    return {DecodeStatus::Ok, std::move(msg)};
  }

  void MessageDecoder::reset() noexcept
  {
    buffer_.clear();
  }

} // namespace P2P