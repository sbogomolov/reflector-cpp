cmake_minimum_required(VERSION 3.14)
project(reflector VERSION 0.1.0 LANGUAGES CXX)
include(CTest)

if(NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin"))
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}. Only Linux and macOS are supported.")
endif()

# Standard library bits used here (std::println, std::expected, std::format) need a recent toolchain.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "14")
    message(FATAL_ERROR "GCC ${CMAKE_CXX_COMPILER_VERSION} is too old; need GCC 14 or newer for std::println / std::expected.")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "18")
    message(FATAL_ERROR "Clang ${CMAKE_CXX_COMPILER_VERSION} is too old; need Clang 18 or newer (with libc++ or libstdc++ 14+).")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "16")
    message(FATAL_ERROR "AppleClang ${CMAKE_CXX_COMPILER_VERSION} is too old; need AppleClang 16 (Xcode 16) or newer.")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(_reflector_sanitize_default ON)
else()
    set(_reflector_sanitize_default OFF)
endif()
set(REFLECTOR_SANITIZE ${_reflector_sanitize_default} CACHE BOOL
    "Enable AddressSanitizer + UndefinedBehaviorSanitizer")
unset(_reflector_sanitize_default)

set(_reflector_release_compile_options)
if(NOT CMAKE_CXX_FLAGS_RELEASE MATCHES "(^|[ \t])-O3($|[ \t])")
    list(APPEND _reflector_release_compile_options $<$<CONFIG:Release>:-O3>)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT _reflector_ipo_supported OUTPUT _reflector_ipo_error)
if(NOT _reflector_ipo_supported AND CMAKE_BUILD_TYPE STREQUAL "Release")
    message(WARNING "IPO/LTO is not supported by this toolchain: ${_reflector_ipo_error}")
endif()

function(reflector_configure_project_target target)
    set_target_properties(${target} PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
    )
    target_compile_options(${target} PRIVATE
        -Werror
        -Wall
        -Wextra
        -Wpedantic
        $<$<CONFIG:Debug>:-ggdb3>
        ${_reflector_release_compile_options}
    )
    if(REFLECTOR_SANITIZE)
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer
        )
        target_link_options(${target} PRIVATE
            -fsanitize=address,undefined
        )
    endif()
    if(_reflector_ipo_supported)
        set_property(TARGET ${target} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    endif()
endfunction()

include(FetchContent)
FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

add_executable(reflector_app)
set_property(TARGET reflector_app PROPERTY OUTPUT_NAME reflector)
reflector_configure_project_target(reflector_app)
target_link_libraries(reflector_app PRIVATE reflector)

add_subdirectory(src)

if(BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
        GIT_SHALLOW FALSE  # ensure submodules are checked out
    )
    FetchContent_MakeAvailable(googletest)

    add_subdirectory(tests)
endif()
