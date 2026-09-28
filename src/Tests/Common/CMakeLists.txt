cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_COMMON_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_COMMON_SOURCES)
  message(FATAL_ERROR "No test sources found for Common in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_COMMON_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsCommon OBJECT ${TESTS_COMMON_SOURCES})

set_property(TARGET TestsCommon PROPERTY OUTPUT_NAME "TestsCommon")

target_link_libraries(TestsCommon
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

target_include_directories(TestsCommon
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsCommon
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsCommon PRIVATE -g -O0)

set_property(TARGET TestsCommon PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsCommon PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\Common" FILES ${TESTS_COMMON_SOURCES})
source_group("Tests\\Common\\Headers" FILES ${TESTS_COMMON_HEADERS})