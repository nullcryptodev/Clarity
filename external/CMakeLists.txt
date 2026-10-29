option(ENABLE_MDBX "Enable MDBX database backend" ON)

set(UPNPC_BUILD_STATIC ON CACHE BOOL "Build static library")
set(UPNPC_BUILD_SHARED OFF CACHE BOOL "Build shared library")
set(UPNPC_BUILD_TESTS OFF CACHE BOOL "Build test executables")

add_subdirectory(miniupnpc)
add_subdirectory(json)
add_subdirectory(monocypher)
add_subdirectory(linenoise)

if(TARGET linenoise)
  set_target_properties(linenoise PROPERTIES SYSTEM TRUE)
endif()

if (DO_TESTS)
  add_subdirectory(gtest)
endif()

if(ENABLE_MDBX)
    set(MDBX_BUILD_TOOLS OFF CACHE BOOL "Disable MDBX tools")
    set(MDBX_BUILD_TESTS OFF CACHE BOOL "Disable MDBX tests")

    set(CMAKE_C_FLAGS_BAK "${CMAKE_C_FLAGS}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-undef -Wno-logical-op -Wno-aggregate-return -Wno-nested-externs -Wno-discarded-qualifiers -Wno-strict-prototypes -Wno-old-style-definition")

    add_subdirectory(mdbx)
    
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_BAK}")

    if(TARGET mdbx-static)
      set_target_properties(mdbx-static PROPERTIES SYSTEM TRUE)
    endif()
    set(MDBX_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mdbx" PARENT_SCOPE)
    set(MDBX_LIBRARY_TARGET mdbx-static PARENT_SCOPE)
endif()

set_property(TARGET libminiupnpc-static PROPERTY FOLDER "external")

if(MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -wd4244 -wd4267")
elseif(NOT MSVC)
  set_property(TARGET libminiupnpc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-undef -Wno-unused-result -Wno-unused-value")
endif()

# libsecp256k1 v0.8.0 — Bitcoin curve arithmetic.
#
# Used only by src/Crypto/BitcoinBip32.cpp for:
#   - BIP32 non-hardened child derivation from an xpub
#     (secp256k1_ec_pubkey_tweak_add: parent_pub + IL*G)
#   - compressed pubkey parse/serialize (33 bytes)
#
# Core module only. No ECDH, no recovery, no Schnorr, no MuSig2,
# no ElligatorSwift: BIP84 P2WPKH needs none of them, and each
# module is extra audited surface we don't use. Static, tests/bench
# off.
#
# muSig2 depends on schnorrsig, so disabling schnorrsig requires
# disabling musig2 as well — v0.8.0 rejects the contradiction at
# configure time (this is why the first attempt failed).
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_DISABLE_SHARED ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDH OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
add_subdirectory(secp256k1)

if(TARGET secp256k1)
  set_target_properties(secp256k1 PROPERTIES SYSTEM TRUE)
endif()