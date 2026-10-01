# Each app links against CoreLibs, which is the static archive of every
# module under src/. Apps are leaf targets, nothing links against them.

add_subdirectory(Daemon)
add_subdirectory(Wallet)
add_subdirectory(Tools)