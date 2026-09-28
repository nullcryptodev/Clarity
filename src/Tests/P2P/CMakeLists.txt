cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_P2P_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_P2P_SOURCES)
  message(FATAL_ERROR "No test sources found for P2P in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_P2P_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsP2P OBJECT ${TESTS_P2P_SOURCES})

set_property(TARGET TestsP2P PROPERTY OUTPUT_NAME "TestsP2P")

target_link_libraries(TestsP2P
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

target_include_directories(TestsP2P
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsP2P
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsP2P PRIVATE -g -O0)

set_property(TARGET TestsP2P PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsP2P PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\P2P" FILES ${TESTS_P2P_SOURCES})
source_group("Tests\\P2P\\Headers" FILES ${TESTS_P2P_HEADERS})