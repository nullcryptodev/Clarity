cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE CORE_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER CORE_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT CORE_SOURCES)
  message(FATAL_ERROR "No source files found for Core in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE CORE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER CORE_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Core as an OBJECT library
add_library(Core OBJECT ${CORE_SOURCES})

# Set output name
set_property(TARGET Core PROPERTY OUTPUT_NAME "core")

# Include directories
target_include_directories(Core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(Core PUBLIC monocypher)

# Compile definitions
target_compile_definitions(Core
  PUBLIC
    -DCORE_STATIC_LIB
)

# C++17 standard
set_property(TARGET Core PROPERTY CXX_STANDARD 17)
set_property(TARGET Core PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Core PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Core" FILES ${CORE_SOURCES})
source_group("Core\\Headers" FILES ${CORE_HEADERS})

# Create an alias
add_library(Core::Core ALIAS Core)

# EXPORT the source files for parent scope
set(Core_FILES ${CORE_SOURCES} ${CORE_HEADERS} PARENT_SCOPE)

message(STATUS "Core: Found ${CORE_SOURCES} source files")