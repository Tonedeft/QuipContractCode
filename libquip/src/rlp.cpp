#include "rlp.hpp"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iomanip>

namespace quip {

std::vector<uint8_t> RLP::hexToBytes(const std::string& hex) {
    std::string hexStr = hex;
    if (hexStr.substr(0, 2) == "0x") {
        hexStr = hexStr.substr(2);
    }
    
    std::vector<uint8_t> bytes;
    boost::algorithm::unhex(hexStr.begin(), hexStr.end(), std::back_inserter(bytes));
    return bytes;
}

std::string RLP::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    boost::algorithm::hex(bytes.begin(), bytes.end(), std::back_inserter(hex));
    return "0x" + hex;
}

uint64_t RLP::bytesToUint64(const std::vector<uint8_t>& bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

std::vector<uint8_t> RLP::uint64ToBytes(uint64_t value) {
    std::vector<uint8_t> bytes;
    while (value > 0) {
        bytes.insert(bytes.begin(), value & 0xFF);
        value >>= 8;
    }
    if (bytes.empty()) {
        bytes.push_back(0);
    }
    return bytes;
}

std::vector<uint8_t> RLP::encodeLength(size_t length, uint8_t offset) {
    std::vector<uint8_t> encoded;
    if (length < 56) {
        encoded.push_back(offset + length);
    } else {
        std::vector<uint8_t> lengthBytes = uint64ToBytes(length);
        encoded.push_back(offset + 55 + lengthBytes.size());
        encoded.insert(encoded.end(), lengthBytes.begin(), lengthBytes.end());
    }
    return encoded;
}

size_t RLP::decodeLength(const std::vector<uint8_t>& input, size_t& pos) {
    if (pos >= input.size()) {
        throw std::runtime_error("Invalid RLP: end of input");
    }
    
    uint8_t firstByte = input[pos++];
    if (firstByte <= 0x7f) {
        return 1;
    } else if (firstByte <= 0xb7) {
        return firstByte - 0x80;
    } else if (firstByte <= 0xbf) {
        size_t lengthLength = firstByte - 0xb7;
        if (pos + lengthLength > input.size()) {
            throw std::runtime_error("Invalid RLP: end of input");
        }
        std::vector<uint8_t> lengthBytes(input.begin() + pos, input.begin() + pos + lengthLength);
        pos += lengthLength;
        return bytesToUint64(lengthBytes);
    } else if (firstByte <= 0xf7) {
        return firstByte - 0xc0;
    } else {
        size_t lengthLength = firstByte - 0xf7;
        if (pos + lengthLength > input.size()) {
            throw std::runtime_error("Invalid RLP: end of input");
        }
        std::vector<uint8_t> lengthBytes(input.begin() + pos, input.begin() + pos + lengthLength);
        pos += lengthLength;
        return bytesToUint64(lengthBytes);
    }
}

bool RLP::isList(const std::vector<uint8_t>& input, size_t pos) {
    if (pos >= input.size()) {
        return false;
    }
    return input[pos] >= 0xc0;
}

std::vector<uint8_t> RLP::encode(const std::string& item) {
    std::string str = item;
    if (str.substr(0, 2) == "0x") {
        str = str.substr(2);
    }
    std::vector<uint8_t> bytes = hexToBytes(str);
    return encode(bytes);
}

std::vector<uint8_t> RLP::encode(const std::vector<uint8_t>& item) {
    if (item.size() == 1 && item[0] <= 0x7f) {
        return item;
    }
    
    std::vector<uint8_t> encoded = encodeLength(item.size(), 0x80);
    encoded.insert(encoded.end(), item.begin(), item.end());
    return encoded;
}

std::vector<uint8_t> RLP::encode(const nlohmann::json& item) {
    if (item.is_string()) {
        return encode(item.get<std::string>());
    } else if (item.is_number()) {
        return encode(uint64ToBytes(item.get<uint64_t>()));
    }
    throw std::runtime_error("Unsupported JSON type for RLP encoding");
}

std::vector<uint8_t> RLP::encodeList(const std::vector<std::vector<uint8_t>>& items) {
    std::vector<uint8_t> encoded;
    for (const auto& item : items) {
        std::vector<uint8_t> itemEncoded = encode(item);
        encoded.insert(encoded.end(), itemEncoded.begin(), itemEncoded.end());
    }
    
    std::vector<uint8_t> result = encodeLength(encoded.size(), 0xc0);
    result.insert(result.end(), encoded.begin(), encoded.end());
    return result;
}

std::vector<uint8_t> RLP::decode(const std::vector<uint8_t>& input, size_t& pos) {
    if (pos >= input.size()) {
        throw std::runtime_error("Invalid RLP: end of input");
    }
    
    uint8_t firstByte = input[pos];
    if (firstByte <= 0x7f) {
        pos++;
        return {firstByte};
    } else if (firstByte <= 0xb7) {
        size_t length = firstByte - 0x80;
        pos++;
        if (pos + length > input.size()) {
            throw std::runtime_error("Invalid RLP: end of input");
        }
        std::vector<uint8_t> result(input.begin() + pos, input.begin() + pos + length);
        pos += length;
        return result;
    } else if (firstByte <= 0xbf) {
        size_t lengthLength = firstByte - 0xb7;
        pos++;
        if (pos + lengthLength > input.size()) {
            throw std::runtime_error("Invalid RLP: end of input");
        }
        std::vector<uint8_t> lengthBytes(input.begin() + pos, input.begin() + pos + lengthLength);
        size_t length = bytesToUint64(lengthBytes);
        pos += lengthLength;
        if (pos + length > input.size()) {
            throw std::runtime_error("Invalid RLP: end of input");
        }
        std::vector<uint8_t> result(input.begin() + pos, input.begin() + pos + length);
        pos += length;
        return result;
    } else {
        throw std::runtime_error("Invalid RLP: unexpected list");
    }
}

std::vector<std::vector<uint8_t>> RLP::decodeList(const std::vector<uint8_t>& input) {
    size_t pos = 0;
    if (!isList(input, pos)) {
        throw std::runtime_error("Invalid RLP: not a list");
    }
    
    size_t length = decodeLength(input, pos);
    if (pos + length > input.size()) {
        throw std::runtime_error("Invalid RLP: end of input");
    }
    
    std::vector<std::vector<uint8_t>> items;
    while (pos < input.size()) {
        items.push_back(decode(input, pos));
    }
    return items;
}

} // namespace quip 