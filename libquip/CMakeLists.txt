cmake_minimum_required(VERSION 3.15)
project(libquip VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem)

# Add web3 library (you'll need to install this)
find_package(web3 REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add source files
add_library(quip SHARED
    src/quip_wallet.cpp
    src/wots_plus.cpp
    src/ethereum_client.cpp
)

# Link libraries
target_link_libraries(quip
    PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Boost::filesystem
    web3::web3
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