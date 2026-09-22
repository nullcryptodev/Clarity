cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE P2P_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER P2P_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT P2P_SOURCES)
  message(FATAL_ERROR "No source files found for P2P in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE P2P_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER P2P_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define P2P as an OBJECT library
add_library(P2P OBJECT ${P2P_SOURCES})

# Set output name
set_property(TARGET P2P PROPERTY OUTPUT_NAME "p2p")

# Include directories
target_include_directories(P2P
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(P2P PUBLIC
    Boost::boost
    Boost::system
    Crypto
)

# Compile definitions
target_compile_definitions(P2P
  PUBLIC
    -DP2P_STATIC_LIB
)

# C++17 standard
set_property(TARGET P2P PROPERTY CXX_STANDARD 17)
set_property(TARGET P2P PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(P2P PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("P2P" FILES ${P2P_SOURCES})
source_group("P2P\\Headers" FILES ${P2P_HEADERS})

# Create an alias
add_library(P2P::P2P ALIAS P2P)

# EXPORT the source files for parent scope
set(P2P_FILES ${P2P_SOURCES} ${P2P_HEADERS} PARENT_SCOPE)

message(STATUS "P2P: Found ${P2P_SOURCES} source files")