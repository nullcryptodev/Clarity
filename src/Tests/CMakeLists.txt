cmake_minimum_required(VERSION 3.12)

set(TEST_TARGET "clarity_tests")

# Build each test folder as its own OBJECT library. This gives CMake
# a per-folder build graph instead of a single 125-source target, so
# a change to one test file recompiles one .o and relinks the
# executable — it doesn't touch the rest of the suite.
add_subdirectory(Common)
add_subdirectory(Consensus)
add_subdirectory(Core)
add_subdirectory(Crypto)
add_subdirectory(Node)
add_subdirectory(P2P)
add_subdirectory(RPC)
add_subdirectory(Serialization)
add_subdirectory(State)
add_subdirectory(Wallet)

# Top-level test files: main, shared utils, the transaction builder.
add_executable(${TEST_TARGET}
  main.cpp
  TransactionBuilder.cpp
  Utils.cpp
)

target_include_directories(${TEST_TARGET}
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(${TEST_TARGET}
  SYSTEM PRIVATE
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_link_libraries(${TEST_TARGET}
  PRIVATE
    TestsCommon
    TestsConsensus
    TestsCore
    TestsCrypto
    TestsNode
    TestsP2P
    TestsRpc
    TestsSerialization
    TestsState
    TestsWallet
    CoreLibs
    gtest
    gtest_main
    monocypher
    ${MDBX_LIBRARY_TARGET}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    libminiupnpc-static
    ${CMAKE_THREAD_LIBS_INIT}
)

target_compile_features(${TEST_TARGET} PRIVATE cxx_std_17)
target_compile_options(${TEST_TARGET} PRIVATE -g -O0)

add_test(NAME ${TEST_TARGET} COMMAND ${TEST_TARGET})