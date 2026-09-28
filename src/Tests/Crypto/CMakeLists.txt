cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_CRYPTO_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_CRYPTO_SOURCES)
  message(FATAL_ERROR "No test sources found for Crypto in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_CRYPTO_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsCrypto OBJECT ${TESTS_CRYPTO_SOURCES})

set_property(TARGET TestsCrypto PROPERTY OUTPUT_NAME "TestsCrypto")

target_link_libraries(TestsCrypto
  PUBLIC
    CoreLibs
    gtest
    monocypher
    ${MDBX_LIBRARY_TARGET}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    libminiupnpc-static
    ${CMAKE_THREAD_LIBS_INIT}
)

target_include_directories(TestsCrypto
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsCrypto
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsCrypto PRIVATE -g -O0)

set_property(TARGET TestsCrypto PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsCrypto PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\Crypto" FILES ${TESTS_CRYPTO_SOURCES})
source_group("Tests\\Crypto\\Headers" FILES ${TESTS_CRYPTO_HEADERS})