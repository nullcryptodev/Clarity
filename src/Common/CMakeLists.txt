cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE COMMON_SOURCES 
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER COMMON_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT COMMON_SOURCES)
  message(FATAL_ERROR "No source files found for Common in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE COMMON_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER COMMON_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define Common as an OBJECT library
add_library(Common OBJECT ${COMMON_SOURCES})

# Set output name
set_property(TARGET Common PROPERTY OUTPUT_NAME "Common")

target_link_libraries(Common
  PUBLIC
    Crypto
)

# Include directories
target_include_directories(Common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Compile definitions
target_compile_definitions(Common
  PUBLIC
    -DCOMMON_STATIC_LIB
)

# C++17 standard
set_property(TARGET Common PROPERTY CXX_STANDARD 17)
set_property(TARGET Common PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(Common PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Source groups for IDE organization
source_group("Common" FILES ${COMMON_SOURCES})
source_group("Common\\Headers" FILES ${COMMON_HEADERS})

# Create an alias
add_library(Common::Common ALIAS Common)

# EXPORT the source files for parent scope
set(Common_FILES ${COMMON_SOURCES} ${COMMON_HEADERS} PARENT_SCOPE)

message(STATUS "Common: Found ${COMMON_SOURCES} source files")