# Dependencies
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options filesystem system thread)

# Find MDBX
find_path(MDBX_INCLUDE_DIR NAMES mdbx.h PATHS /usr/include /usr/local/include ${CMAKE_SOURCE_DIR}/external/mdbx)
find_library(MDBX_LIBRARY NAMES mdbx libmdbx PATHS /usr/lib /usr/local/lib ${CMAKE_SOURCE_DIR}/external/mdbx)
if(MDBX_LIBRARY)
    set(MDBX_LIBRARY_TARGET ${MDBX_LIBRARY})
endif()

# Add definitions
add_definitions(-DMINIUPNP_STATICLIB)

# Grab src modules
add_subdirectory(Common)
add_subdirectory(Consensus)
add_subdirectory(Core)
add_subdirectory(Crypto)
add_subdirectory(Logging)
add_subdirectory(Node)
add_subdirectory(P2P)
add_subdirectory(Serialization)
add_subdirectory(State)

#Include directories
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/external/parallel_hashmap)
include_directories(${MDBX_INCLUDE_DIR})

# Bundle all object files into one static library
add_library(CoreLibs STATIC
  $<TARGET_OBJECTS:Common>
  $<TARGET_OBJECTS:Consensus>
  $<TARGET_OBJECTS:Core>
  $<TARGET_OBJECTS:Crypto>
  $<TARGET_OBJECTS:Logging>
  $<TARGET_OBJECTS:Node>
  $<TARGET_OBJECTS:P2P>
  $<TARGET_OBJECTS:Serialization>
  $<TARGET_OBJECTS:State>
)

# Set output name
set_property(TARGET CoreLibs PROPERTY OUTPUT_NAME "core_libs")

# Add all include directories
target_include_directories(CoreLibs
  PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/external/parallel_hashmap
    ${MDBX_INCLUDE_DIR}
)

# Add compile definitions
target_compile_definitions(CoreLibs
  PUBLIC
    -DMINIUPNP_STATICLIB
)

# Link all external dependencies
target_link_libraries(CoreLibs
  PUBLIC
    monocypher
    ${Boost_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    ${MDBX_LIBRARY_TARGET}
    libminiupnpc-static
    ${OPENSSL_LIBRARIES}
)

# Platform-specific libraries
if (MSVC)
  target_link_libraries(CoreLibs
    PUBLIC
      ws2_32
  )
elseif(MINGW)
  target_link_libraries(CoreLibs
    PUBLIC
      dnsapi
      bcrypt
      ws2_32
  )
endif()

# Build executables
add_subdirectory(Daemon)

if(BUILD_TESTS)
  add_subdirectory(Tests)
endif()