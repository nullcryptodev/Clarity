cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE NODE_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER NODE_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT NODE_SOURCES)
  message(FATAL_ERROR "No source files found for Node in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE NODE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER NODE_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Node as an OBJECT library
add_library(Node OBJECT ${NODE_SOURCES})

# Set output name
set_property(TARGET Node PROPERTY OUTPUT_NAME "node")

# Include directories
target_include_directories(Node
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(Node PUBLIC monocypher)

# Compile definitions
target_compile_definitions(Node
  PUBLIC
    -DNODE_STATIC_LIB
)

# C++17 standard
set_property(TARGET Node PROPERTY CXX_STANDARD 17)
set_property(TARGET Node PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Node PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Node" FILES ${NODE_SOURCES})
source_group("Node\\Headers" FILES ${NODE_HEADERS})

# Create an alias
add_library(Node::Node ALIAS Node)

# EXPORT the source files for parent scope
set(Node_FILES ${NODE_SOURCES} ${NODE_HEADERS} PARENT_SCOPE)

message(STATUS "Node: Found ${NODE_SOURCES} source files")