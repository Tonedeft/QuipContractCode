#include "wots_plus.hpp"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <boost/algorithm/hex.hpp>
#include <array>
#include <vector>

namespace quip {

std::pair<WinternitzAddress, std::array<uint8_t, HASH_LEN>> WOTSPlus::generateKeyPair(
    const std::array<uint8_t, HASH_LEN>& privateSeed) {
    
    // Generate private key
    auto privateKey = prf(privateSeed, 0);
    
    // Generate public seed
    auto publicSeed = prf(privateKey, 0);
    
    // Generate randomization elements
    auto randomizationElements = generateRandomizationElements(publicSeed);
    
    // Generate public key segments
    std::vector<std::array<uint8_t, HASH_LEN>> publicKeySegments;
    for (size_t i = 0; i < 67; ++i) { // NumSignatureChunks
        auto secretKeySegment = prf(privateKey, i + 1);
        auto publicKeySegment = chain(secretKeySegment, randomizationElements, 0, 15); // ChainLen - 1
        publicKeySegments.push_back(publicKeySegment);
    }
    
    // Hash all public key segments
    std::array<uint8_t, HASH_LEN> publicKeyHash;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    for (const auto& segment : publicKeySegments) {
        SHA256_Update(&sha256, segment.data(), segment.size());
    }
    SHA256_Final(publicKeyHash.data(), &sha256);
    
    WinternitzAddress address{publicSeed, publicKeyHash};
    return {address, privateKey};
}

WinternitzElements WOTSPlus::sign(
    const std::array<uint8_t, HASH_LEN>& privateKey,
    const std::array<uint8_t, HASH_LEN>& messageHash) {
    
    // Generate public seed and randomization elements
    auto publicSeed = prf(privateKey, 0);
    auto randomizationElements = generateRandomizationElements(publicSeed);
    
    // Compute chain indexes
    auto chainIndexes = computeMessageHashChainIndexes(messageHash);
    
    // Generate signature
    WinternitzElements signature;
    for (size_t i = 0; i < chainIndexes.size(); ++i) {
        auto secretKeySegment = prf(privateKey, i + 1);
        signature.elements[i] = chain(secretKeySegment, randomizationElements, 0, chainIndexes[i]);
    }
    
    return signature;
}

bool WOTSPlus::verify(
    const WinternitzAddress& address,
    const std::array<uint8_t, HASH_LEN>& messageHash,
    const WinternitzElements& signature) {
    
    // Generate randomization elements
    auto randomizationElements = generateRandomizationElements(address.publicSeed);
    
    // Compute chain indexes
    auto chainIndexes = computeMessageHashChainIndexes(messageHash);
    
    // Recompute public key segments
    std::vector<std::array<uint8_t, HASH_LEN>> publicKeySegments;
    for (size_t i = 0; i < chainIndexes.size(); ++i) {
        auto steps = 15 - chainIndexes[i]; // ChainLen - 1 - chainIndexes[i]
        publicKeySegments.push_back(chain(signature.elements[i], randomizationElements, chainIndexes[i], steps));
    }
    
    // Hash all public key segments
    std::array<uint8_t, HASH_LEN> computedHash;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    for (const auto& segment : publicKeySegments) {
        SHA256_Update(&sha256, segment.data(), segment.size());
    }
    SHA256_Final(computedHash.data(), &sha256);
    
    return computedHash == address.publicKeyHash;
}

std::array<uint8_t, HASH_LEN> WOTSPlus::prf(
    const std::array<uint8_t, HASH_LEN>& key,
    uint32_t index) {
    
    std::array<uint8_t, HASH_LEN> output;
    std::array<uint8_t, sizeof(uint32_t)> indexBytes;
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        indexBytes[i] = (index >> (8 * i)) & 0xFF;
    }
    
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), nullptr);
    HMAC_Update(ctx, indexBytes.data(), indexBytes.size());
    unsigned int len;
    HMAC_Final(ctx, output.data(), &len);
    HMAC_CTX_free(ctx);
    
    return output;
}

std::array<uint8_t, HASH_LEN> WOTSPlus::chain(
    const std::array<uint8_t, HASH_LEN>& start,
    const WinternitzElements& randomizationElements,
    uint8_t startIndex,
    uint8_t steps) {
    
    std::array<uint8_t, HASH_LEN> current = start;
    for (uint8_t i = startIndex; i < startIndex + steps; ++i) {
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, current.data(), current.size());
        SHA256_Update(&sha256, randomizationElements.elements[i].data(), randomizationElements.elements[i].size());
        SHA256_Final(current.data(), &sha256);
    }
    return current;
}

WinternitzElements WOTSPlus::generateRandomizationElements(
    const std::array<uint8_t, HASH_LEN>& publicSeed) {
    
    WinternitzElements elements;
    for (size_t i = 0; i < 67; ++i) { // NumSignatureChunks
        elements.elements[i] = prf(publicSeed, i);
    }
    return elements;
}

std::vector<uint8_t> WOTSPlus::computeMessageHashChainIndexes(
    const std::array<uint8_t, HASH_LEN>& messageHash) {
    
    std::vector<uint8_t> indexes;
    for (size_t i = 0; i < 64; ++i) { // NumMessageChunks
        uint8_t byte = messageHash[i / 2];
        if (i % 2 == 0) {
            indexes.push_back(byte >> 4);
        } else {
            indexes.push_back(byte & 0x0F);
        }
    }
    
    // Add checksum
    uint16_t checksum = 0;
    for (auto idx : indexes) {
        checksum += 15 - idx; // ChainLen - 1 - idx
    }
    
    for (size_t i = 0; i < 3; ++i) { // NumChecksumChunks
        indexes.push_back(checksum & 0x0F);
        checksum >>= 4;
    }
    
    return indexes;
}

} // namespace quip 