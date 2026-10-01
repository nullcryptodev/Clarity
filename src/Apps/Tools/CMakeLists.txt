# Tools are standalone binaries that link against the CoreLibs bundle.

# ./genesis_hash
add_executable(genesis_hash GenesisHash.cpp)
target_link_libraries(genesis_hash PRIVATE CoreLibs)
target_include_directories(genesis_hash PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(genesis_hash PRIVATE cxx_std_17)

# ./address
add_executable(address Address.cpp)
target_link_libraries(address PRIVATE CoreLibs)
target_include_directories(address PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(address PRIVATE cxx_std_17)

# ./transaction_signer
add_executable(transaction_signer TransactionSigner.cpp)
target_link_libraries(transaction_signer PRIVATE CoreLibs)
target_include_directories(transaction_signer PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(transaction_signer PRIVATE cxx_std_17)