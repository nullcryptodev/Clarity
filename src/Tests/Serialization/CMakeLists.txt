cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_SERIALIZATION_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_SERIALIZATION_SOURCES)
  message(FATAL_ERROR "No test sources found for Serialization in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_SERIALIZATION_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsSerialization OBJECT ${TESTS_SERIALIZATION_SOURCES})

set_property(TARGET TestsSerialization PROPERTY OUTPUT_NAME "TestsSerialization")

target_link_libraries(TestsSerialization
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

target_include_directories(TestsSerialization
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsSerialization
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsSerialization PRIVATE -g -O0)

set_property(TARGET TestsSerialization PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsSerialization PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\Serialization" FILES ${TESTS_SERIALIZATION_SOURCES})
source_group("Tests\\Serialization\\Headers" FILES ${TESTS_SERIALIZATION_HEADERS})