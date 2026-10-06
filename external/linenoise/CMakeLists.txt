# linenoise — small readline replacement, vendored.
#
# Upstream: https://github.com/antirez/linenoise
# License: BSD-2-Clause (see LICENSE.md)

add_library(linenoise STATIC
  linenoise.c
)

target_include_directories(linenoise PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# linenoise is plain C. Silence warnings we don't care about in
# vendored code, but keep the ones that matter.
if(NOT MSVC)
  target_compile_options(linenoise PRIVATE
    -Wno-unused-parameter
    -Wno-unused-but-set-variable
    -Wno-sign-compare
  )
endif()

# Mark as system include so its headers don't trip -Werror in our code.
set_target_properties(linenoise PROPERTIES
  SYSTEM TRUE
)

set_property(TARGET linenoise PROPERTY FOLDER "external")