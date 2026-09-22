# external/monocypher/CMakeLists.txt
#
# Build description for the vendored Monocypher source tree.
# Monocypher doesn't ship a CMakeLists.txt; this provides one.

set(MONOCYPHER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/monocypher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/optional/monocypher-ed25519.c
)

add_library(monocypher STATIC ${MONOCYPHER_SOURCES})

target_include_directories(monocypher PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/optional
)

set_target_properties(monocypher PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

# Silence warnings from vendored code — we don't want to fix them.
if(NOT MSVC)
    target_compile_options(monocypher PRIVATE
        -Wno-unused-function
        -Wno-unused-variable
        -Wno-sign-compare
    )
endif()