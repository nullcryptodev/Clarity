cmake_minimum_required(VERSION 3.12)

# Collect files
file(GLOB_RECURSE RPC_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER RPC_SOURCES EXCLUDE REGEX ".*/Tests/.*")

if(NOT RPC_SOURCES)
  message(FATAL_ERROR "No source files found for RPC in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE RPC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

list(FILTER RPC_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define RPC as an OBJECT library to match the other modules
add_library(RPC OBJECT ${RPC_SOURCES})

set_property(TARGET RPC PROPERTY OUTPUT_NAME "rpc")

target_include_directories(RPC
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# RPC reads chain state and submits transactions through Core/State;
# everything else (Crypto, Serialization, Common, Logging) it gets
# transitively. P2P and Consensus are NOT linked — RPC goes through
# Node for anything peer- or consensus-related.
target_link_libraries(RPC PUBLIC monocypher)

target_compile_definitions(RPC
  PUBLIC
    -DRPC_STATIC_LIB
)

set_property(TARGET RPC PROPERTY CXX_STANDARD 17)
set_property(TARGET RPC PROPERTY CXX_STANDARD_REQUIRED ON)

if (MSVC)
  target_compile_definitions(RPC PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

source_group("RPC" FILES ${RPC_SOURCES})
source_group("RPC\\Headers" FILES ${RPC_HEADERS})

add_library(RPC::RPC ALIAS RPC)

set(RPC_FILES ${RPC_SOURCES} ${RPC_HEADERS} PARENT_SCOPE)

message(STATUS "RPC: Found ${RPC_SOURCES} source files")