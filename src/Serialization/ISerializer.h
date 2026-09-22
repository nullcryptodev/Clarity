#pragma once

#include <string>
#include <string_view>
#include <cstdint>
#include <type_traits>
#include <concepts>

namespace Serialization
{
  /**
   * @brief Core serialization interface
   *
   * Defines the contract for all serializers. Supports both input (deserialization)
   * and output (serialization) modes.
   */
  class ISerializer
  {
  public:
    enum class InternalMode
    {
      Input, ///< Deserialization mode
      Output ///< Serialization mode
    };

    virtual ~ISerializer() = default;

    /// @return Current mode (Input or Output)
    virtual InternalMode mode() const = 0;

    // ========================================================================
    // Object & Array Operations
    // ========================================================================

    /// Begin an object scope
    virtual bool beginObject(std::string_view name) = 0;

    /// End the current object scope
    virtual void endObject() = 0;

    /// Begin an array scope, returns the size (Input) or sets size (Output)
    virtual bool beginArray(size_t &size, std::string_view name) = 0;

    /// End the current array scope
    virtual void endArray() = 0;

    // ========================================================================
    // Primitive Serialization
    // ========================================================================

    virtual bool operator()(uint8_t &value, std::string_view name) = 0;
    virtual bool operator()(int16_t &value, std::string_view name) = 0;
    virtual bool operator()(uint16_t &value, std::string_view name) = 0;
    virtual bool operator()(int32_t &value, std::string_view name) = 0;
    virtual bool operator()(uint32_t &value, std::string_view name) = 0;
    virtual bool operator()(int64_t &value, std::string_view name) = 0;
    virtual bool operator()(uint64_t &value, std::string_view name) = 0;
    virtual bool operator()(float &value, std::string_view name) = 0;
    virtual bool operator()(double &value, std::string_view name) = 0;
    virtual bool operator()(bool &value, std::string_view name) = 0;
    virtual bool operator()(std::string &value, std::string_view name) = 0;

    /// Binary blob serialization
    virtual bool binary(void *value, size_t size, std::string_view name) = 0;
    virtual bool binary(std::string &value, std::string_view name) = 0;

    // ========================================================================
    // Template Interface
    // ========================================================================

    template <typename T>
    bool operator()(T &value, std::string_view name)
    {
      return serialize(value, name, *this);
    }

  protected:
    /// Helper for Input mode type checking
    bool isInput() const { return mode() == InternalMode::Input; }
    bool isOutput() const { return mode() == InternalMode::Output; }
  };
} // namespace