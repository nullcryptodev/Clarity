cmake_minimum_required(VERSION 3.12)

file(GLOB_RECURSE WALLET_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

if(NOT WALLET_SOURCES)
  message(FATAL_ERROR "No source files found for Wallet in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

file(GLOB_RECURSE WALLET_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/*.h
)

add_executable(clarity_wallet ${WALLET_SOURCES})

set_property(TARGET clarity_wallet PROPERTY OUTPUT_NAME "clarity_wallet")

target_include_directories(clarity_wallet
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/Apps/Common
)

target_link_libraries(clarity_wallet
  PRIVATE
    CoreLibs
)

set_property(TARGET clarity_wallet PROPERTY CXX_STANDARD 17)
set_property(TARGET clarity_wallet PROPERTY CXX_STANDARD_REQUIRED ON)

if (MSVC)
  target_compile_definitions(clarity_wallet PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX)
  find_package(Threads REQUIRED)
  target_link_libraries(clarity_wallet PRIVATE Threads::Threads)
endif()

source_group("Wallet" FILES ${WALLET_SOURCES})
source_group("Wallet\\Headers" FILES ${WALLET_HEADERS})

install(TARGETS clarity_wallet
  RUNTIME DESTINATION bin
)

message(STATUS "Wallet: Found ${WALLET_SOURCES} source files")