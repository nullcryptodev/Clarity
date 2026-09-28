cmake_minimum_required(VERSION 3.12)

# Collect files
file(GLOB_RECURSE WALLET_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER WALLET_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT WALLET_SOURCES)
  message(FATAL_ERROR "No source files found for Wallet in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE WALLET_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER WALLET_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Wallet as an OBJECT library
add_library(Wallet OBJECT ${WALLET_SOURCES})

# Set output name
set_property(TARGET Wallet PROPERTY OUTPUT_NAME "wallet")

# Include directories
target_include_directories(Wallet
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Compile definitions
target_compile_definitions(Wallet
  PUBLIC
    -DWALLET_STATIC_LIB
)

# C++17 standard
set_property(TARGET Wallet PROPERTY CXX_STANDARD 17)
set_property(TARGET Wallet PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Wallet PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Wallet" FILES ${WALLET_SOURCES})
source_group("Wallet\\Headers" FILES ${WALLET_HEADERS})

# Create an alias
add_library(Wallet::Wallet ALIAS Wallet)

# EXPORT the source files for parent scope
set(Wallet_FILES ${WALLET_SOURCES} ${WALLET_HEADERS} PARENT_SCOPE)

message(STATUS "Wallet: Found ${WALLET_SOURCES} source files")