# All tests for the Clarity codebase, built as a single binary.

set(TEST_TARGET "clarity_tests")

file(GLOB_RECURSE TEST_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT TEST_SOURCES)
  message(FATAL_ERROR "No test sources in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

add_executable(${TEST_TARGET} ${TEST_SOURCES})

# Our own headers — normal include path, warnings apply.
target_include_directories(${TEST_TARGET}
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

# System headers — warnings suppressed.
#
# gtest's headers use bare #if GTEST_OS_WINDOWS etc., where the macro
# is undefined on non-Windows and evaluates to 0. That's correct C
# preprocessor semantics, but -Wundef flags every such use. Marking
# the directory as SYSTEM is the fix that suppresses the warning
# without also suppressing -Wundef in our own code.
target_include_directories(${TEST_TARGET}
  SYSTEM PRIVATE
    ${CMAKE_SOURCE_DIR}/external/gtest/include
)

target_link_libraries(${TEST_TARGET}
  PRIVATE
    CoreLibs
    gtest
    gtest_main
    monocypher
    ${MDBX_LIBRARY_TARGET}
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    libminiupnpc-static
    ${CMAKE_THREAD_LIBS_INIT}
)

target_compile_features(${TEST_TARGET} PRIVATE cxx_std_17)

add_test(NAME ${TEST_TARGET} COMMAND ${TEST_TARGET})