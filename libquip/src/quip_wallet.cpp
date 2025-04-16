#include "quip_wallet.hpp"
#include "wots_plus.hpp"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

namespace quip {

QuipWallet::QuipWallet(std::unique_ptr<EthereumClient> ethClient, const std::string& factoryAddress)
    : ethClient_(std::move(ethClient))
    , wotsPlus_(std::make_unique<WOTSPlus>())
    , factoryAddress_(factoryAddress) {
}

std::string QuipWallet::depositToWinternitz(
    const std::string& vaultId,
    const std::string& toAddress,
    const WinternitzAddress& pqTo,
    const std::string& privateKey,
    uint64_t value) {
    
    // Encode the function call data
    std::string functionSelector = "0x7f1b1e1f"; // depositToWinternitz(bytes32,address,tuple,uint256)
    
    // Encode parameters
    std::string encodedParams;
    encodedParams += vaultId; // bytes32
    encodedParams += "000000000000000000000000" + toAddress.substr(2); // address
    encodedParams += boost::algorithm::hex(std::string(pqTo.publicSeed.begin(), pqTo.publicSeed.end()));
    encodedParams += boost::algorithm::hex(std::string(pqTo.publicKeyHash.begin(), pqTo.publicKeyHash.end()));
    encodedParams += boost::algorithm::hex(std::to_string(value));
    
    // Send the transaction
    return ethClient_->sendTransaction(factoryAddress_, functionSelector + encodedParams, privateKey, value);
}

void QuipWallet::transferWithWinternitz(
    const std::string& walletAddress,
    const WinternitzAddress& nextPqOwner,
    const WinternitzElements& pqSig,
    const std::string& toAddress,
    uint64_t value,
    const std::string& privateKey) {
    
    // Encode the function call data
    std::string functionSelector = "0x12345678"; // transferWithWinternitz(tuple,tuple,address,uint256)
    
    // Encode parameters
    std::string encodedParams;
    
    // Encode nextPqOwner (tuple)
    encodedParams += boost::algorithm::hex(std::string(nextPqOwner.publicSeed.begin(), nextPqOwner.publicSeed.end()));
    encodedParams += boost::algorithm::hex(std::string(nextPqOwner.publicKeyHash.begin(), nextPqOwner.publicKeyHash.end()));
    
    // Encode signature elements
    for (const auto& element : pqSig.elements) {
        encodedParams += boost::algorithm::hex(std::string(element.begin(), element.end()));
    }
    
    // Encode toAddress and value
    encodedParams += "000000000000000000000000" + toAddress.substr(2); // address
    encodedParams += boost::algorithm::hex(std::to_string(value));
    
    // Send the transaction
    ethClient_->sendTransaction(walletAddress, functionSelector + encodedParams, privateKey);
}

} // namespace quip 