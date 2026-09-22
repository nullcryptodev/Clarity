cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE CONSENSUS_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER CONSENSUS_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT CONSENSUS_SOURCES)
  message(FATAL_ERROR "No source files found for Consensus in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE CONSENSUS_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER CONSENSUS_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Consensus as an OBJECT library
add_library(Consensus OBJECT ${CONSENSUS_SOURCES})

# Set output name
set_property(TARGET Consensus PROPERTY OUTPUT_NAME "Consensus")

# Include directories
target_include_directories(Consensus
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Compile definitions
target_compile_definitions(Consensus
  PUBLIC
    -DCONSENSUS_STATIC_LIB
)

# C++17 standard
set_property(TARGET Consensus PROPERTY CXX_STANDARD 17)
set_property(TARGET Consensus PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Consensus PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Consensus" FILES ${CONSENSUS_SOURCES})
source_group("Consensus\\Headers" FILES ${CONSENSUS_HEADERS})

# Create an alias
add_library(Consensus::Consensus ALIAS Consensus)

# EXPORT the source files for parent scope
set(Consensus_FILES ${CONSENSUS_SOURCES} ${CONSENSUS_HEADERS} PARENT_SCOPE)

message(STATUS "Consensus: Found ${CONSENSUS_SOURCES} source files")