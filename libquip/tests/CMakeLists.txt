find_package(GTest REQUIRED)

# Add the test executable
add_executable(test_quip_wallet
    test_quip_wallet.cpp
    mock_ethereum_client.cpp
)

# Include directories
target_include_directories(test_quip_wallet
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${Boost_INCLUDE_DIRS}
        ${GTEST_INCLUDE_DIRS}
        ${nlohmann_json_INCLUDE_DIRS}
)

# Link dependencies
target_link_libraries(test_quip_wallet
    PRIVATE
        quip
        GTest::GTest
        GTest::Main
        Boost::system
        nlohmann_json::nlohmann_json
)

# Add the test
add_test(NAME test_quip_wallet COMMAND test_quip_wallet) 