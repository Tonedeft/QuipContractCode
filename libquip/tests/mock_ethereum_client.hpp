#pragma once

#include "../include/ethereum_client.hpp"
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>

namespace quip {

class MockEthereumClient : public EthereumClient {
public:
    MockEthereumClient(const std::string& nodeUrl) : EthereumClient(nodeUrl) {
        // Set up default responses
        defaultResponses_["eth_getTransactionCount"] = R"({
            "jsonrpc": "2.0",
            "result": "0x1",
            "id": 1
        })"_json;

        defaultResponses_["eth_gasPrice"] = R"({
            "jsonrpc": "2.0",
            "result": "0x4a817c800",
            "id": 1
        })"_json;

        defaultResponses_["eth_sendRawTransaction"] = R"({
            "jsonrpc": "2.0",
            "result": "0x1234567890abcdef",
            "id": 1
        })"_json;
    }

    // Override rpcCall to log the request and return mock response
    nlohmann::json rpcCall(const std::string& method, const nlohmann::json& params) override {
        std::cout << "Mock RPC Call:" << std::endl;
        std::cout << "Method: " << method << std::endl;
        std::cout << "Params: " << params.dump(2) << std::endl;
        
        // Store the last call for verification
        lastMethod_ = method;
        lastParams_ = params;
        
        return defaultResponses_[method];
    }

    // Getter methods for verification
    std::string getLastMethod() const { return lastMethod_; }
    nlohmann::json getLastParams() const { return lastParams_; }

private:
    std::string lastMethod_;
    nlohmann::json lastParams_;
    std::map<std::string, nlohmann::json> defaultResponses_;
};

} // namespace quip 