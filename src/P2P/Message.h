// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "MessageTypes.h"

namespace P2P
{
  // A complete P2P message. The payload is opaque bytes here; specific
  // message types are parsed by dedicated codecs (VersionMessage etc).
  struct Message
  {
    MessageType type{};
    std::vector<uint8_t> payload;

    Message() = default;

    Message(MessageType t, std::vector<uint8_t> p = {})
        : type(t), payload(std::move(p)) {}

    static Message ping() { return Message(MessageType::Ping); }
    static Message pong() { return Message(MessageType::Pong); }
    static Message verack() { return Message(MessageType::Verack); }
    static Message getPeers() { return Message(MessageType::GetPeers); }
    static Message disconnect() { return Message(MessageType::Disconnect); }
  };

  // ---- Wire framing ----
  //
  //   [4] magic         LE
  //   [2] type          LE
  //   [4] payload_size  LE
  //   [N] payload

  inline constexpr size_t MESSAGE_HEADER_SIZE = 10;

  std::vector<uint8_t> encodeMessage(const Message &msg,
                                     uint32_t magic,
                                     uint32_t maxSize = MAX_MESSAGE_SIZE);

  // ---- Incremental decoder ----

  enum class DecodeStatus
  {
    Ok,
    NeedMoreData,
    Corrupted,
  };

  struct DecodeResult
  {
    DecodeStatus status;
    std::optional<Message> message;
  };

  class MessageDecoder
  {
  public:
    MessageDecoder(uint32_t magic, uint32_t maxSize) noexcept
        : magic_(magic), maxSize_(maxSize) {}

    void feed(const uint8_t *data, size_t len);
    DecodeResult next();
    size_t bufferedBytes() const noexcept { return buffer_.size(); }
    void reset() noexcept;

  private:
    uint32_t magic_;
    uint32_t maxSize_;
    std::vector<uint8_t> buffer_;
  };

} // namespace P2P