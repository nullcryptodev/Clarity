cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE STATE_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER STATE_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT STATE_SOURCES)
  message(FATAL_ERROR "No source files found for State in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE STATE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER STATE_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define State as an OBJECT library
add_library(State OBJECT ${STATE_SOURCES})

# Set output name
set_property(TARGET State PROPERTY OUTPUT_NAME "state")

# Include directories
target_include_directories(State
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(State PUBLIC monocypher)

# Compile definitions
target_compile_definitions(State
  PUBLIC
    -DSTATE_STATIC_LIB
)

# C++17 standard
set_property(TARGET State PROPERTY CXX_STANDARD 17)
set_property(TARGET State PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(State PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("State" FILES ${STATE_SOURCES})
source_group("State\\Headers" FILES ${STATE_HEADERS})

# Create an alias
add_library(State::State ALIAS State)

# EXPORT the source files for parent scope
set(State_FILES ${STATE_SOURCES} ${STATE_HEADERS} PARENT_SCOPE)

message(STATUS "State: Found ${STATE_SOURCES} source files")