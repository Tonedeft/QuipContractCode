#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <nlohmann/json.hpp>

namespace quip {

class RLP {
public:
    // Encode a single item
    static std::vector<uint8_t> encode(const std::string& item);
    static std::vector<uint8_t> encode(const std::vector<uint8_t>& item);
    static std::vector<uint8_t> encode(const nlohmann::json& item);

    // Encode a list of items
    static std::vector<uint8_t> encodeList(const std::vector<std::vector<uint8_t>>& items);

    // Decode a single item
    static std::vector<uint8_t> decode(const std::vector<uint8_t>& input, size_t& pos);
    static std::vector<std::vector<uint8_t>> decodeList(const std::vector<uint8_t>& input);

    // Helper functions
    static std::vector<uint8_t> hexToBytes(const std::string& hex);
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static uint64_t bytesToUint64(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> uint64ToBytes(uint64_t value);

private:
    // RLP encoding helpers
    static std::vector<uint8_t> encodeLength(size_t length, uint8_t offset);
    static size_t decodeLength(const std::vector<uint8_t>& input, size_t& pos);
    static bool isList(const std::vector<uint8_t>& input, size_t pos);
}; 