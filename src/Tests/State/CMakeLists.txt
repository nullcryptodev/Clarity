cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_STATE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_STATE_SOURCES)
  message(FATAL_ERROR "No test sources found for State in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_STATE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsState OBJECT ${TESTS_STATE_SOURCES})

set_property(TARGET TestsState PROPERTY OUTPUT_NAME "TestsState")

target_link_libraries(TestsState
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

target_include_directories(TestsState
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsState
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsState PRIVATE -g -O0)

set_property(TARGET TestsState PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsState PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\State" FILES ${TESTS_STATE_SOURCES})
source_group("Tests\\State\\Headers" FILES ${TESTS_STATE_HEADERS})