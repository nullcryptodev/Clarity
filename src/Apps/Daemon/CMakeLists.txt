cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE DAEMON_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT DAEMON_SOURCES)
  message(FATAL_ERROR "No source files found for Daemon in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE DAEMON_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_executable(clarityd ${DAEMON_SOURCES})

set_property(TARGET clarityd PROPERTY OUTPUT_NAME "clarityd")

target_include_directories(clarityd
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(clarityd
  PRIVATE
    CoreLibs
)

target_compile_definitions(clarityd
  PRIVATE
    -DDAEMON_STATIC_LIB
)

set_property(TARGET clarityd PROPERTY CXX_STANDARD 17)
set_property(TARGET clarityd PROPERTY CXX_STANDARD_REQUIRED ON)

if (MSVC)
  target_compile_definitions(clarityd PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX)
  find_package(Threads REQUIRED)
  target_link_libraries(clarityd PRIVATE Threads::Threads)
endif()

source_group("Daemon" FILES ${DAEMON_SOURCES})
source_group("Daemon\\Headers" FILES ${DAEMON_HEADERS})

install(TARGETS clarityd
  RUNTIME DESTINATION bin
)

message(STATUS "Daemon: Found ${DAEMON_SOURCES} source files")