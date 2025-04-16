cmake_minimum_required(VERSION 3.15)
project(libquip VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem)
find_package(nlohmann_json REQUIRED)
find_package(CURL REQUIRED)

# Add web3 library (you'll need to install this)
find_package(web3 REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add source files
add_library(quip
    src/quip_wallet.cpp
    src/ethereum_client.cpp
    src/wots_plus.cpp
)

# Include directories
target_include_directories(quip
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${Boost_INCLUDE_DIRS}
        ${nlohmann_json_INCLUDE_DIRS}
)

# Link dependencies
target_link_libraries(quip
    PUBLIC
        Boost::system
        nlohmann_json::nlohmann_json
    PRIVATE
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Install rules
install(TARGETS quip
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
)

# Add tests
enable_testing()
add_subdirectory(tests) 