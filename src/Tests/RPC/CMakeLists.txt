cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_RPC_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_RPC_SOURCES)
  message(FATAL_ERROR "No test sources found for RPC in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_RPC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsRpc OBJECT ${TESTS_RPC_SOURCES})

set_property(TARGET TestsRpc PROPERTY OUTPUT_NAME "TestsRpc")

target_link_libraries(TestsRpc
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

target_include_directories(TestsRpc
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsRpc
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsRpc PRIVATE -g -O0)

set_property(TARGET TestsRpc PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsRpc PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\Rpc" FILES ${TESTS_RPC_SOURCES})
source_group("Tests\\Rpc\\Headers" FILES ${TESTS_RPC_HEADERS})