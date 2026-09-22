cmake_minimum_required(VERSION 3.10)

# Collect files
file(GLOB_RECURSE DAEMON_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Remove Tests directory from the sources
list(FILTER DAEMON_SOURCES EXCLUDE REGEX ".*/Tests/.*")

# Check if we found any sources
if(NOT DAEMON_SOURCES)
  message(FATAL_ERROR "No source files found for Daemon in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# Collect headers for source grouping
file(GLOB_RECURSE DAEMON_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

# Remove Tests headers
list(FILTER DAEMON_HEADERS EXCLUDE REGEX ".*/Tests/.*")

# Define the daemon as an executable
add_executable(clarityd ${DAEMON_SOURCES})

# Set output name
set_property(TARGET clarityd PROPERTY OUTPUT_NAME "clarityd")

# Include directories
target_include_directories(clarityd
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

# Link against CoreLibs (which contains all our static libraries as objects)
target_link_libraries(clarityd
  PRIVATE
    CoreLibs
)

# Compile definitions
target_compile_definitions(clarityd
  PRIVATE
    -DDAEMON_STATIC_LIB
)

# C++17 standard
set_property(TARGET clarityd PROPERTY CXX_STANDARD 17)
set_property(TARGET clarityd PROPERTY CXX_STANDARD_REQUIRED ON)

# Platform-specific settings
if (MSVC)
  target_compile_definitions(clarityd PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX)
  # Enable pthreads on Linux/macOS
  find_package(Threads REQUIRED)
  target_link_libraries(clarityd PRIVATE Threads::Threads)
endif()

# Source groups for IDE organization
source_group("Daemon" FILES ${DAEMON_SOURCES})
source_group("Daemon\\Headers" FILES ${DAEMON_HEADERS})

# Install rule (optional — installs to /usr/local/bin by default)
install(TARGETS clarityd
  RUNTIME DESTINATION bin
)

message(STATUS "Daemon: Found ${DAEMON_SOURCES} source files")