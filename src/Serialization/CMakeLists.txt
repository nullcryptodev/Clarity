cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE SERIALIZATION_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER SERIALIZATION_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT SERIALIZATION_SOURCES)
  message(FATAL_ERROR "No source files found for Serialization in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE SERIALIZATION_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER SERIALIZATION_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Serialization as an OBJECT library
add_library(Serialization OBJECT ${SERIALIZATION_SOURCES})

# Set output name
set_property(TARGET Serialization PROPERTY OUTPUT_NAME "serialization")

# Include directories
target_include_directories(Serialization
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Compile definitions
target_compile_definitions(Serialization
  PUBLIC
    -DSERIALIZATION_STATIC_LIB
)

# C++17 standard
set_property(TARGET Serialization PROPERTY CXX_STANDARD 17)
set_property(TARGET Serialization PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Serialization PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Serialization" FILES ${SERIALIZATION_SOURCES})
source_group("Serialization\\Headers" FILES ${SERIALIZATION_HEADERS})

# Create an alias
add_library(Serialization::Serialization ALIAS Serialization)

# EXPORT the source files for parent scope
set(Serialization_FILES ${SERIALIZATION_SOURCES} ${SERIALIZATION_HEADERS} PARENT_SCOPE)

message(STATUS "Serialization: Found ${SERIALIZATION_SOURCES} source files")