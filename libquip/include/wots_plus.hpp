#pragma once

#include <array>
#include <vector>
#include <string>

namespace quip {

// Constants from the smart contract
constexpr size_t HASH_LEN = 32;
constexpr size_t SIGNATURE_SIZE = 67; // NumSignatureChunks * HashLen
constexpr size_t PUBLIC_KEY_SIZE = 64; // HashLen * 2

struct WinternitzAddress {
    std::array<uint8_t, HASH_LEN> publicSeed;
    std::array<uint8_t, HASH_LEN> publicKeyHash;
};

struct WinternitzElements {
    std::array<std::array<uint8_t, HASH_LEN>, 67> elements; // NumSignatureChunks elements
};

class WOTSPlus {
public:
    // Generate a new WOTS+ key pair
    static std::pair<WinternitzAddress, std::array<uint8_t, HASH_LEN>> generateKeyPair(
        const std::array<uint8_t, HASH_LEN>& privateSeed
    );

    // Sign a message with a WOTS+ private key
    static WinternitzElements sign(
        const std::array<uint8_t, HASH_LEN>& privateKey,
        const std::array<uint8_t, HASH_LEN>& messageHash
    );

    // Verify a WOTS+ signature
    static bool verify(
        const WinternitzAddress& address,
        const std::array<uint8_t, HASH_LEN>& messageHash,
        const WinternitzElements& signature
    );

private:
    // Helper functions
    static std::array<uint8_t, HASH_LEN> prf(
        const std::array<uint8_t, HASH_LEN>& key,
        uint32_t index
    );

    static std::array<uint8_t, HASH_LEN> chain(
        const std::array<uint8_t, HASH_LEN>& start,
        const WinternitzElements& randomizationElements,
        uint8_t startIndex,
        uint8_t steps
    );

    static WinternitzElements generateRandomizationElements(
        const std::array<uint8_t, HASH_LEN>& publicSeed
    );

    static std::vector<uint8_t> computeMessageHashChainIndexes(
        const std::array<uint8_t, HASH_LEN>& messageHash
    );
};

} // namespace quip 