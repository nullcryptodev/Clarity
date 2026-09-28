# Tools are standalone binaries that link against the CoreLibs bundle.

# ./GenesisHash
add_executable(GenesisHash GenesisHash.cpp)
target_link_libraries(GenesisHash PRIVATE CoreLibs)
target_include_directories(GenesisHash PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(GenesisHash PRIVATE cxx_std_17)

# ./Address
add_executable(Address Address.cpp)
target_link_libraries(Address PRIVATE CoreLibs)
target_include_directories(Address PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_compile_features(Address PRIVATE cxx_std_17)