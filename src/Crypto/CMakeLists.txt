cmake_minimum_required(VERSION 3.10)

# Collect files
#
# We glob both .cpp and .c sources. The .c source is the vendored
# Argon2 reference implementation (argon2_ref.c). The root
# project() enables the C language; without C enabled, CMake cannot
# find a C compiler for the .c file and configuration fails.
file(GLOB_RECURSE CRYPTO_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/*.c
)

# Remove Tests directory from the sources
list(FILTER CRYPTO_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT CRYPTO_SOURCES)
  message(FATAL_ERROR "No source files found for Crypto in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE CRYPTO_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER CRYPTO_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Crypto as an OBJECT library
add_library(Crypto OBJECT ${CRYPTO_SOURCES})

# Argon2 reference implementation.
#
# It is C, third-party, and we do not want our global warning
# settings to reject it. The -w flag suppresses warnings for this
# translation unit only.
#
# We also declare LANGUAGE C explicitly, even though CMake infers
# it from the .c extension, so a future rename to .cpp cannot
# silently break the extern "C" linkage expected by Argon2id.cpp.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/argon2_ref.c)
  set_source_files_properties(
    ${CMAKE_CURRENT_SOURCE_DIR}/argon2_ref.c
    PROPERTIES
      LANGUAGE C
      COMPILE_OPTIONS "-w"
  )
endif()

# Set output name
set_property(TARGET Crypto PROPERTY OUTPUT_NAME "crypto")

# Include directories
target_include_directories(Crypto
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(Crypto PUBLIC monocypher)

# Compile definitions
target_compile_definitions(Crypto
  PUBLIC
    -DCRYPTO_STATIC_LIB
)

# C++17 standard
set_property(TARGET Crypto PROPERTY CXX_STANDARD 17)
set_property(TARGET Crypto PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Crypto PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Crypto" FILES ${CRYPTO_SOURCES})
source_group("Crypto\\Headers" FILES ${CRYPTO_HEADERS})

# Create an alias
add_library(Crypto::Crypto ALIAS Crypto)

# EXPORT the source files for parent scope
set(Crypto_FILES ${CRYPTO_SOURCES} ${CRYPTO_HEADERS} PARENT_SCOPE)

message(STATUS "Crypto: Found ${CRYPTO_SOURCES} source files")