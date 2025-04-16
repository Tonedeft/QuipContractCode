#pragma once

#include <string>
#include <vector>
#include <memory>
#include <array>
#include <cstdint>

namespace quip {

// Forward declarations
class EthereumClient;
class WOTSPlus;

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

class QuipWallet {
public:
    // Constructor
    QuipWallet(const std::string& ethereumNodeUrl, const std::string& factoryAddress);
    
    // Create a new QuipWallet contract
    std::string depositToWinternitz(
        const std::string& vaultId,
        const std::string& toAddress,
        const WinternitzAddress& pqTo,
        const std::string& privateKey,
        uint64_t value
    );

    // Transfer funds using WOTS+ signature
    void transferWithWinternitz(
        const std::string& walletAddress,
        const WinternitzAddress& nextPqOwner,
        const WinternitzElements& pqSig,
        const std::string& toAddress,
        uint64_t value,
        const std::string& privateKey
    );

private:
    std::unique_ptr<EthereumClient> ethClient_;
    std::unique_ptr<WOTSPlus> wotsPlus_;
    std::string factoryAddress_;
};

} // namespace quip 