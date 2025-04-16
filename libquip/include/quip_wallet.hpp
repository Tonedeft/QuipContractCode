#pragma once

#include <string>
#include <vector>
#include <memory>
#include <array>
#include <cstdint>
#include "ethereum_client.hpp"
#include "wots_plus.hpp"

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
    /**
     * @brief Construct a new QuipWallet object
     * @param ethClient The Ethereum client to use for blockchain interactions
     * @param factoryAddress The address of the QuipFactory contract
     */
    QuipWallet(std::unique_ptr<EthereumClient> ethClient, const std::string& factoryAddress);
    
    /**
     * @brief Deposit funds to a Winternitz address
     * @param vaultId The vault ID
     * @param toAddress The address to receive the funds
     * @param pqTo The Winternitz address to receive the funds
     * @param privateKey The private key to sign the transaction
     * @param value The amount of ETH to deposit (in wei)
     * @return The transaction hash
     */
    std::string depositToWinternitz(
        const std::string& vaultId,
        const std::string& toAddress,
        const WinternitzAddress& pqTo,
        const std::string& privateKey,
        uint64_t value
    );

    /**
     * @brief Transfer funds using a Winternitz signature
     * @param walletAddress The address of the QuipWallet contract
     * @param nextPqOwner The new Winternitz address that will own the wallet
     * @param pqSig The Winternitz signature authorizing the transfer
     * @param toAddress The address to receive the funds
     * @param value The amount of ETH to transfer (in wei)
     * @param privateKey The private key to sign the transaction
     */
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