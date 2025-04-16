#include "../include/quip_wallet.hpp"
#include "mock_ethereum_client.hpp"
#include <gtest/gtest.h>
#include <boost/algorithm/hex.hpp>
#include <iostream>

using namespace quip;

class QuipWalletTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a mock Ethereum client for Sepolia
        mockClient_ = std::make_unique<MockEthereumClient>("https://sepolia.infura.io/v3/YOUR-PROJECT-ID", Chain::Sepolia);
        
        // Create a QuipWallet instance with the mock client
        wallet_ = std::make_unique<QuipWallet>("https://sepolia.infura.io/v3/YOUR-PROJECT-ID", "0x1234567890123456789012345678901234567890");
    }

    std::unique_ptr<MockEthereumClient> mockClient_;
    std::unique_ptr<QuipWallet> wallet_;
};

TEST_F(QuipWalletTest, DepositToWinternitz) {
    // Test data
    std::string vaultId = "0x1234567890123456789012345678901234567890123456789012345678901234";
    std::string toAddress = "0xabcdef1234567890123456789012345678901234";
    std::string privateKey = "0x1234567890123456789012345678901234567890123456789012345678901234";
    uint64_t value = 1000000000000000000; // 1 ETH in wei

    // Create a WOTS+ address
    std::array<uint8_t, HASH_LEN> privateSeed = {0};
    auto [address, _] = WOTSPlus::generateKeyPair(privateSeed);

    // Call the function
    std::string result = wallet_->depositToWinternitz(
        vaultId,
        toAddress,
        address,
        privateKey,
        value
    );

    // Verify the RPC call
    EXPECT_EQ(mockClient_->getLastMethod(), "eth_sendRawTransaction");
    
    auto params = mockClient_->getLastParams();
    auto tx = params["params"][0];
    
    // Verify transaction parameters
    EXPECT_EQ(tx["to"], "0x1234567890123456789012345678901234567890"); // Factory address
    EXPECT_EQ(tx["value"], "0xde0b6b3a7640000"); // 1 ETH in hex
    EXPECT_EQ(tx["chainId"], "0xaa36a7"); // Sepolia chain ID
    
    // Verify the data field contains the correct function selector
    std::string data = tx["data"].get<std::string>();
    EXPECT_TRUE(data.substr(0, 10) == "0x7f1b1e1f"); // Function selector
    
    // Verify the data contains the vaultId
    EXPECT_TRUE(data.find(vaultId.substr(2)) != std::string::npos);
    
    // Verify the data contains the toAddress
    EXPECT_TRUE(data.find(toAddress.substr(2)) != std::string::npos);
    
    // Verify the data contains the public seed
    std::string publicSeedHex;
    boost::algorithm::hex(address.publicSeed.begin(), address.publicSeed.end(), std::back_inserter(publicSeedHex));
    EXPECT_TRUE(data.find(publicSeedHex) != std::string::npos);
    
    // Verify the data contains the public key hash
    std::string publicKeyHashHex;
    boost::algorithm::hex(address.publicKeyHash.begin(), address.publicKeyHash.end(), std::back_inserter(publicKeyHashHex));
    EXPECT_TRUE(data.find(publicKeyHashHex) != std::string::npos);
}

TEST_F(QuipWalletTest, TransferWithWinternitz) {
    // Test data
    std::string walletAddress = "0xabcdef1234567890123456789012345678901234";
    std::string toAddress = "0x5678901234567890123456789012345678901234";
    std::string privateKey = "0x1234567890123456789012345678901234567890123456789012345678901234";
    uint64_t value = 500000000000000000; // 0.5 ETH in wei

    // Create WOTS+ addresses for current and next owner
    std::array<uint8_t, HASH_LEN> privateSeed = {0};
    auto [currentAddress, currentPrivateKey] = WOTSPlus::generateKeyPair(privateSeed);
    auto [nextAddress, _] = WOTSPlus::generateKeyPair(privateSeed);

    // Create a message to sign
    std::array<uint8_t, HASH_LEN> messageHash = {0};
    for (size_t i = 0; i < HASH_LEN; ++i) {
        messageHash[i] = static_cast<uint8_t>(i);
    }

    // Generate the signature
    auto signature = WOTSPlus::sign(currentPrivateKey, messageHash);

    // Call the transfer function
    wallet_->transferWithWinternitz(
        walletAddress,
        nextAddress,
        signature,
        toAddress,
        value,
        privateKey
    );

    // Verify the RPC call
    EXPECT_EQ(mockClient_->getLastMethod(), "eth_sendRawTransaction");
    
    auto params = mockClient_->getLastParams();
    auto tx = params["params"][0];
    
    // Verify transaction parameters
    EXPECT_EQ(tx["to"], walletAddress);
    EXPECT_EQ(tx["value"], "0x0"); // No ETH value as it's a contract call
    EXPECT_EQ(tx["chainId"], "0xaa36a7"); // Sepolia chain ID
    
    // Verify the data field contains the correct function selector
    std::string data = tx["data"].get<std::string>();
    EXPECT_TRUE(data.substr(0, 10) == "0x12345678"); // Function selector for transferWithWinternitz
    
    // Verify the data contains the next owner's public seed
    std::string nextPublicSeedHex;
    boost::algorithm::hex(nextAddress.publicSeed.begin(), nextAddress.publicSeed.end(), std::back_inserter(nextPublicSeedHex));
    EXPECT_TRUE(data.find(nextPublicSeedHex) != std::string::npos);
    
    // Verify the data contains the next owner's public key hash
    std::string nextPublicKeyHashHex;
    boost::algorithm::hex(nextAddress.publicKeyHash.begin(), nextAddress.publicKeyHash.end(), std::back_inserter(nextPublicKeyHashHex));
    EXPECT_TRUE(data.find(nextPublicKeyHashHex) != std::string::npos);
    
    // Verify the data contains the signature elements
    for (const auto& element : signature.elements) {
        std::string elementHex;
        boost::algorithm::hex(element.begin(), element.end(), std::back_inserter(elementHex));
        EXPECT_TRUE(data.find(elementHex) != std::string::npos);
    }
    
    // Verify the data contains the toAddress
    EXPECT_TRUE(data.find(toAddress.substr(2)) != std::string::npos);
    
    // Verify the data contains the value
    std::string valueHex = boost::algorithm::hex(std::to_string(value));
    EXPECT_TRUE(data.find(valueHex) != std::string::npos);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 