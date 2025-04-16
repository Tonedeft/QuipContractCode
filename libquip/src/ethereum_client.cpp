#include "ethereum_client.hpp"
#include "rlp.hpp"
#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <sstream>
#include <iomanip>

namespace quip {

EthereumClient::EthereumClient(const std::string& nodeUrl, Chain chain)
    : nodeUrl_(nodeUrl), chain_(chain) {
    curl_global_init(CURL_GLOBAL_ALL);
}

std::string EthereumClient::getChainId() const {
    switch (chain_) {
        case Chain::Mainnet:
            return "0x1";
        case Chain::Sepolia:
            return "0xaa36a7";
        default:
            throw std::runtime_error("Unsupported chain");
    }
}

std::string EthereumClient::sendTransaction(
    const std::string& to,
    const std::string& data,
    const std::string& privateKey,
    uint64_t value) {
    
    // Get nonce and gas price
    auto nonce = getNonce(privateKey);
    auto gasPrice = getGasPrice();
    
    // Sign the transaction
    auto signedTx = signTransaction(to, data, privateKey, value, nonce, gasPrice);
    
    // Send the transaction
    nlohmann::json params = {
        {"jsonrpc", "2.0"},
        {"method", "eth_sendRawTransaction"},
        {"params", {signedTx}},
        {"id", 1}
    };
    
    auto response = rpcCall("eth_sendRawTransaction", params);
    return response["result"].get<std::string>();
}

std::string EthereumClient::callContract(
    const std::string& contractAddress,
    const std::string& data) {
    
    nlohmann::json params = {
        {"jsonrpc", "2.0"},
        {"method", "eth_call"},
        {"params", {
            {
                {"to", contractAddress},
                {"data", data}
            },
            "latest"
        }},
        {"id", 1}
    };
    
    auto response = rpcCall("eth_call", params);
    return response["result"].get<std::string>();
}

uint64_t EthereumClient::getNonce(const std::string& address) {
    nlohmann::json params = {
        {"jsonrpc", "2.0"},
        {"method", "eth_getTransactionCount"},
        {"params", {address, "latest"}},
        {"id", 1}
    };
    
    auto response = rpcCall("eth_getTransactionCount", params);
    return std::stoull(response["result"].get<std::string>().substr(2), nullptr, 16);
}

std::string EthereumClient::getGasPrice() {
    nlohmann::json params = {
        {"jsonrpc", "2.0"},
        {"method", "eth_gasPrice"},
        {"params", {}},
        {"id", 1}
    };
    
    auto response = rpcCall("eth_gasPrice", params);
    return response["result"].get<std::string>();
}

nlohmann::json EthereumClient::rpcCall(const std::string& method, const nlohmann::json& params) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize CURL");
    }
    
    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, nodeUrl_.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    
    std::string postData = params.dump();
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, [](void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }
    
    return nlohmann::json::parse(response);
}

std::string EthereumClient::signTransaction(
    const std::string& to,
    const std::string& data,
    const std::string& privateKey,
    uint64_t value,
    uint64_t nonce,
    const std::string& gasPrice) {
    
    // Create the transaction data
    nlohmann::json tx = {
        {"nonce", "0x" + boost::algorithm::hex(std::to_string(nonce))},
        {"gasPrice", gasPrice},
        {"gasLimit", "0x" + boost::algorithm::hex(std::to_string(21000))}, // Standard gas limit
        {"to", to},
        {"value", "0x" + boost::algorithm::hex(std::to_string(value))},
        {"data", data},
        {"chainId", getChainId()}
    };
    
    // Serialize the transaction
    std::string rlpData = serializeTransaction(tx);
    
    // Hash the transaction
    std::array<uint8_t, HASH_LEN> hash;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, rlpData.data(), rlpData.size());
    SHA256_Final(hash.data(), &sha256);
    
    // Sign the hash
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* priv = BN_new();
    BN_hex2bn(&priv, privateKey.substr(2).c_str());
    EC_KEY_set_private_key(key, priv);
    
    ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), hash.size(), key);
    
    // Encode the signature
    const BIGNUM* r;
    const BIGNUM* s;
    ECDSA_SIG_get0(sig, &r, &s);
    
    std::stringstream ss;
    ss << "0x" << std::hex << std::setfill('0') << std::setw(64) << BN_bn2hex(r)
       << std::setw(64) << BN_bn2hex(s);
    
    // Clean up
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    BN_free(priv);
    
    return ss.str();
}

std::string EthereumClient::serializeTransaction(const nlohmann::json& tx) {
    // Convert transaction fields to bytes
    std::vector<std::vector<uint8_t>> items;
    
    // Nonce
    items.push_back(RLP::hexToBytes(tx["nonce"].get<std::string>()));
    
    // Gas Price
    items.push_back(RLP::hexToBytes(tx["gasPrice"].get<std::string>()));
    
    // Gas Limit
    items.push_back(RLP::hexToBytes(tx["gasLimit"].get<std::string>()));
    
    // To Address
    items.push_back(RLP::hexToBytes(tx["to"].get<std::string>()));
    
    // Value
    items.push_back(RLP::hexToBytes(tx["value"].get<std::string>()));
    
    // Data
    items.push_back(RLP::hexToBytes(tx["data"].get<std::string>()));
    
    // Chain ID
    items.push_back(RLP::hexToBytes(tx["chainId"].get<std::string>()));
    
    // RLP encode the list
    std::vector<uint8_t> encoded = RLP::encodeList(items);
    
    // Convert to hex string
    return RLP::bytesToHex(encoded);
}

nlohmann::json EthereumClient::deserializeTransaction(const std::string& hexTx) {
    // Convert hex to bytes
    std::vector<uint8_t> bytes = RLP::hexToBytes(hexTx);
    
    // Decode the RLP list
    std::vector<std::vector<uint8_t>> items = RLP::decodeList(bytes);
    
    if (items.size() != 7) {
        throw std::runtime_error("Invalid transaction: wrong number of fields");
    }
    
    // Create JSON object
    nlohmann::json tx;
    
    // Nonce
    tx["nonce"] = RLP::bytesToHex(items[0]);
    
    // Gas Price
    tx["gasPrice"] = RLP::bytesToHex(items[1]);
    
    // Gas Limit
    tx["gasLimit"] = RLP::bytesToHex(items[2]);
    
    // To Address
    tx["to"] = RLP::bytesToHex(items[3]);
    
    // Value
    tx["value"] = RLP::bytesToHex(items[4]);
    
    // Data
    tx["data"] = RLP::bytesToHex(items[5]);
    
    // Chain ID
    tx["chainId"] = RLP::bytesToHex(items[6]);
    
    return tx;
}

} // namespace quip 