cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_NODE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_NODE_SOURCES)
  message(FATAL_ERROR "No test sources found for Node in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_NODE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsNode OBJECT ${TESTS_NODE_SOURCES})

set_property(TARGET TestsNode PROPERTY OUTPUT_NAME "TestsNode")

target_link_libraries(TestsNode
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

target_include_directories(TestsNode
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsNode
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsNode PRIVATE -g -O0)

set_property(TARGET TestsNode PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsNode PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\Node" FILES ${TESTS_NODE_SOURCES})
source_group("Tests\\Node\\Headers" FILES ${TESTS_NODE_HEADERS})