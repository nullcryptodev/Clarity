// Json/JsonSerializer.h
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <istream>
#include <type_traits>

#include "ISerializer.h"
#include "Common/Json.h"

namespace Serialization
{

  /**
   * @brief JSON serializer using nlohmann::json
   *
   * Implements JSON serialization with support for:
   * - Object and array nesting
   * - All primitive types
   * - Binary data (Base64 encoded)
   */
  class JsonSerializer : public ISerializer
  {
  public:
    // Constructors (Input mode)

    explicit JsonSerializer(std::istream &stream);
    explicit JsonSerializer(const Common::Json &json);
    explicit JsonSerializer(const std::string &jsonString);

    // Constructor (Output mode)

    JsonSerializer();

    // ISerializer Interface

    InternalMode mode() const override { return m_internalMode; }

    bool beginObject(std::string_view name) override;
    void endObject() override;
    bool beginArray(size_t &size, std::string_view name) override;
    void endArray() override;

    bool operator()(uint8_t &value, std::string_view name) override;
    bool operator()(int16_t &value, std::string_view name) override;
    bool operator()(uint16_t &value, std::string_view name) override;
    bool operator()(int32_t &value, std::string_view name) override;
    bool operator()(uint32_t &value, std::string_view name) override;
    bool operator()(int64_t &value, std::string_view name) override;
    bool operator()(uint64_t &value, std::string_view name) override;
    bool operator()(float &value, std::string_view name) override;
    bool operator()(double &value, std::string_view name) override;
    bool operator()(bool &value, std::string_view name) override;
    bool operator()(std::string &value, std::string_view name) override;

    bool binary(void *value, size_t size, std::string_view name) override;
    bool binary(std::string &value, std::string_view name) override;

    // Output-only methods

    const Common::Json &value() const { return m_root; }
    std::string toString() const;
    std::string toStringPretty(int indent = 4) const;
    void writeToStream(std::ostream &os) const;
    void writeToFile(const std::string &filename) const;

    friend std::ostream &operator<<(std::ostream &os, const JsonSerializer &serializer);

  private:
    // Internal state

    InternalMode m_internalMode;
    Common::Json m_root;
    std::vector<Common::Json *> m_stack;
    std::vector<size_t> m_indices;

    // Helper methods

    void initInput();
    void initOutput();
    Common::Json &current();
    const Common::Json &current() const;
    Common::Json *getValue(std::string_view name);
    void insertOrPush(std::string_view name, const Common::Json &value);
    void incrementArrayIndex();

    template <typename T>
    bool readNumber(std::string_view name, T &value);
    template <typename T>
    void writeNumber(std::string_view name, const T &value);

    // Helpers for input mode

    bool isInput() const { return m_internalMode == InternalMode::Input; }
    bool isOutput() const { return m_internalMode == InternalMode::Output; }
  };

} // namespace Serialization