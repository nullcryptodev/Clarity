cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE LOGGING_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER LOGGING_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT LOGGING_SOURCES)
  message(FATAL_ERROR "No source files found for Logging in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE LOGGING_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER LOGGING_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Logging as an OBJECT library
add_library(Logging OBJECT ${LOGGING_SOURCES})

# Set output name
set_property(TARGET Logging PROPERTY OUTPUT_NAME "logging")

# Include directories
target_include_directories(Logging
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Compile definitions
target_compile_definitions(Logging
  PUBLIC
    -DLOGGING_STATIC_LIB
)

# C++17 standard
set_property(TARGET Logging PROPERTY CXX_STANDARD 17)
set_property(TARGET Logging PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Logging PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Logging" FILES ${LOGGING_SOURCES})
source_group("Logging\\Headers" FILES ${LOGGING_HEADERS})

# Create an alias
add_library(Logging::Logging ALIAS Logging)

# EXPORT the source files for parent scope
set(Logging_FILES ${LOGGING_SOURCES} ${LOGGING_HEADERS} PARENT_SCOPE)

message(STATUS "Logging: Found ${LOGGING_SOURCES} source files")