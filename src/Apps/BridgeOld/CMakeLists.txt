cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE BRIDGE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT BRIDGE_SOURCES)
  message(FATAL_ERROR "No source files found for Bridge in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE BRIDGE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_executable(clarity_bridge ${BRIDGE_SOURCES})

set_property(TARGET clarity_bridge PROPERTY OUTPUT_NAME "clarity_bridge")

target_include_directories(clarity_bridge
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/Apps/Common
)

target_link_libraries(clarity_bridge
  PRIVATE
    CoreLibs
)

set_property(TARGET clarity_bridge PROPERTY CXX_STANDARD 17)
set_property(TARGET clarity_bridge PROPERTY CXX_STANDARD_REQUIRED ON)

if (MSVC)
  target_compile_definitions(clarity_bridge PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX)
  find_package(Threads REQUIRED)
  target_link_libraries(clarity_bridge PRIVATE Threads::Threads)
endif()

source_group("Bridge" FILES ${BRIDGE_SOURCES})
source_group("Bridge\\Headers" FILES ${BRIDGE_HEADERS})

install(TARGETS clarity_bridge
  RUNTIME DESTINATION bin
)

message(STATUS "Bridge: Found ${BRIDGE_SOURCES} source files")