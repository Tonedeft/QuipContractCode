find_package(GTest REQUIRED)

# Add the test executable
add_executable(test_quip_wallet
    test_quip_wallet.cpp
)

# Link with the main library and GTest
target_link_libraries(test_quip_wallet
    PRIVATE
    quip
    GTest::GTest
    GTest::Main
)

# Add the test to CTest
add_test(NAME test_quip_wallet COMMAND test_quip_wallet) 