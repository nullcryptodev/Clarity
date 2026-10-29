cmake_minimum_required(VERSION 3.12)

# ---------------------------------------------------------------------------
#  Bridge adapters library
#
#  The adapter layer (ChainAdapter.h and every per-chain implementation)
#  is what outside code — tests, tooling, future integrations — needs
#  to link against. The app (Session, Scan, Release, Repl, CLI) is
#  built separately and links against it.
#
#  Splitting them mirrors the rest of the tree: CoreLibs bundles the
#  modules other code builds on top of, and apps are leaf targets.
#  Without the split, nothing outside Apps/Bridge can link the
#  adapters.
#
#  Two things are load-bearing about the way BridgeAdapters is
#  defined:
#
#    1. Every adapter .cpp has a static-init registrar that calls
#       ChainAdapterRegistry::registerAdapter at load time. Static
#       libraries discard object files whose symbols are not
#       referenced by the linking executable, and discarded objects
#       do not run their static initializers. If nothing in the
#       executable directly references a symbol from
#       BitcoinAdapter.cpp, the linker omits that object and the
#       registry never sees BitcoinAdapter. The application then
#       fails at startup with `error: adapter vanished for 'btc'`.
#
#    2. The fix has two halves, applied here and in ChainAdapter.cpp:
#         (a) this file's BridgeAdapters::AlwaysLoad interface target
#             propagates --whole-archive so all objects survive the
#             link, and
#         (b) ChainAdapterRegistry.cpp provides
#             Bridge::registerAllChainAdapters(), which main() calls
#             at startup. That function directly references both
#             adapters, which forces them into the link regardless
#             of whether (a) is applied.
#
#       (a) alone works for the current set of adapters but breaks
#       the moment a new adapter file is added to Adapters/ without
#       adding a line to ChainAdapterRegistry.cpp. (b) alone works
#       and scales, but is easy to forget to call. Together they
#       guarantee the registry is populated and the addition of a
#       new adapter is a one-line change in registerAllChainAdapters.
#
# ---------------------------------------------------------------------------

file(GLOB_RECURSE BRIDGE_ADAPTER_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/Adapters/*.cpp
)

if(NOT BRIDGE_ADAPTER_SOURCES)
  message(FATAL_ERROR
    "No adapter source files found in "
    "${CMAKE_CURRENT_SOURCE_DIR}/Adapters")
endif()

add_library(BridgeAdapters STATIC ${BRIDGE_ADAPTER_SOURCES})

target_include_directories(BridgeAdapters
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(BridgeAdapters
  PUBLIC
    CoreLibs
)

set_property(TARGET BridgeAdapters PROPERTY CXX_STANDARD 17)
set_property(TARGET BridgeAdapters PROPERTY CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
#  BridgeAdaptersAlwaysLoad — interface target that bundles
#  BridgeAdapters for consumers.
#
#  Despite the name, this target does NOT use --whole-archive. The
#  earlier design tried to use --whole-archive to force every
#  adapter object into the final link, which is what guarantees the
#  static-init registrars run. But --whole-archive is a linker
#  REGION flag: everything between --whole-archive and
#  --no-whole-archive on the link line gets pulled in, including
#  transitive dependencies. That duplicated libcore_libs.a in
#  BridgeAdapters' transitive chain (when CoreLibs was PUBLIC), and
#  duplicated libmonocypher.a once anything explicitly listed
#  monocypher on the consumer side. Result: "multiple definition
#  of crypto_verify16" and every other symbol in libmonocypher.a.
#
#  The deterministic replacement is Bridge::registerAllChainAdapters()
#  in ChainAdapterRegistry.cpp. That function references both
#  BitcoinAdapter and CcxAdapter by name, which forces their .o
#  files onto the link line via normal static library resolution
#  — no linker flags required. main() calls it at startup. The
#  registry is populated regardless of --whole-archive.
#
#  This target therefore just forwards BridgeAdapters as a link
#  dependency. The name is kept (as a stable alias, see below) so
#  consumer CMake files don't need to change.
# ---------------------------------------------------------------------------

add_library(BridgeAdaptersAlwaysLoad INTERFACE)

target_link_libraries(BridgeAdaptersAlwaysLoad INTERFACE
  BridgeAdapters
)

#  Consumer-facing alias. `::` is reserved for imported/alias
#  targets; a plain `add_library(Foo::Bar ...)` is rejected by CMake.
add_library(BridgeAdapters::AlwaysLoad ALIAS BridgeAdaptersAlwaysLoad)

# ---------------------------------------------------------------------------
#  Bridge application
#
#  CLI, Session, Scan, Release, Repl. Everything under Apps/Bridge
#  that isn't under Adapters/. The easiest way to filter with
#  GLOB_RECURSE is to glob every .cpp and then remove the adapter
#  files that the library already built.
# ---------------------------------------------------------------------------

file(GLOB_RECURSE BRIDGE_ALL_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

set(BRIDGE_APP_SOURCES "")
foreach(src ${BRIDGE_ALL_SOURCES})
  if(NOT src MATCHES "/Adapters/")
    list(APPEND BRIDGE_APP_SOURCES ${src})
  endif()
endforeach()

if(NOT BRIDGE_APP_SOURCES)
  message(FATAL_ERROR
    "No app source files found for clarity_bridge in "
    "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

add_executable(clarity_bridge ${BRIDGE_APP_SOURCES})

set_property(TARGET clarity_bridge PROPERTY OUTPUT_NAME "clarity_bridge")

target_include_directories(clarity_bridge
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/Apps/Common
)

# Link BridgeAdapters::AlwaysLoad (not BridgeAdapters) so every
# adapter object survives the link and its static registrar runs.
# CoreLibs is linked transitively via BridgeAdapters (PUBLIC) but
# making it explicit keeps the link line readable.
target_link_libraries(clarity_bridge
  PRIVATE
    BridgeAdapters::AlwaysLoad
)

set_property(TARGET clarity_bridge PROPERTY CXX_STANDARD 17)
set_property(TARGET clarity_bridge PROPERTY CXX_STANDARD_REQUIRED ON)

if (MSVC)
  target_compile_definitions(clarity_bridge PRIVATE _CRT_SECURE_NO_WARNINGS)
elseif(UNIX)
  find_package(Threads REQUIRED)
  target_link_libraries(clarity_bridge PRIVATE Threads::Threads)
endif()

source_group("Bridge" FILES ${BRIDGE_APP_SOURCES})

install(TARGETS clarity_bridge
  RUNTIME DESTINATION bin
)

message(STATUS "Bridge: ${BRIDGE_ADAPTER_SOURCES} adapter source(s), "
               "${BRIDGE_APP_SOURCES} app source(s)")