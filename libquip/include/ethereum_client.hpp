#pragma once

#include <string>
#include <vector>
#include <memory>
#include <nlohmann/json.hpp>

namespace quip {

enum class Chain {
    Mainnet,
    Sepolia
};

class EthereumClient {
public:
    EthereumClient(const std::string& nodeUrl, Chain chain = Chain::Mainnet);
    virtual ~EthereumClient() = default;
    
    // Send a transaction to the Ethereum network
    std::string sendTransaction(
        const std::string& to,
        const std::string& data,
        const std::string& privateKey,
        uint64_t value = 0
    );

    // Call a contract function (read-only)
    std::string callContract(
        const std::string& contractAddress,
        const std::string& data
    );

    // Get the nonce for an address
    uint64_t getNonce(const std::string& address);

    // Get the current gas price
    std::string getGasPrice();

    // Get the chain ID as a hex string
    std::string getChainId() const;

protected:
    // Make rpcCall virtual so it can be mocked in tests
    virtual nlohmann::json rpcCall(const std::string& method, const nlohmann::json& params);

private:
    std::string nodeUrl_;
    Chain chain_;
    
    // Helper functions
    std::string signTransaction(
        const std::string& to,
        const std::string& data,
        const std::string& privateKey,
        uint64_t value,
        uint64_t nonce,
        const std::string& gasPrice
    );
    std::string serializeTransaction(const nlohmann::json& tx);
};

} // namespace quip 