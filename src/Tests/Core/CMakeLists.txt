cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE TESTS_CORE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TESTS_CORE_SOURCES)
  message(FATAL_ERROR "No test sources found for Core in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE TESTS_CORE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_library(TestsCore OBJECT ${TESTS_CORE_SOURCES})

set_property(TARGET TestsCore PROPERTY OUTPUT_NAME "TestsCore")

target_link_libraries(TestsCore
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

target_include_directories(TestsCore
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(TestsCore
  SYSTEM PUBLIC
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_compile_options(TestsCore PRIVATE -g -O0)

set_property(TARGET TestsCore PROPERTY CXX_STANDARD 17)
set_property(TARGET TestsCore PROPERTY CXX_STANDARD_REQUIRED ON)

source_group("Tests\\Core" FILES ${TESTS_CORE_SOURCES})
source_group("Tests\\Core\\Headers" FILES ${TESTS_CORE_HEADERS})