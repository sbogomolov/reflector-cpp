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

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "-Werror -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -flto=auto")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(_reflector_sanitize_default ON)
else()
    set(_reflector_sanitize_default OFF)
endif()
set(REFLECTOR_SANITIZE ${_reflector_sanitize_default} CACHE BOOL
    "Enable AddressSanitizer + UndefinedBehaviorSanitizer")
unset(_reflector_sanitize_default)
if(REFLECTOR_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

include(FetchContent)
FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(tomlplusplus)

include_directories(
    ${CMAKE_SOURCE_DIR}/src)

add_executable(reflector_app)
target_link_libraries(reflector_app PRIVATE reflector)
set_property(TARGET reflector_app PROPERTY OUTPUT_NAME reflector)

add_subdirectory(src)

if(BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
        GIT_SHALLOW FALSE  # ensure submodules are checked out
    )
    FetchContent_MakeAvailable(googletest)

    # Workaround, see: https://github.com/google/googletest/issues/4762
    # TODO: remove when googletest is updated
    if((CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
            AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "21")
        target_compile_options(gtest PUBLIC -Wno-character-conversion)
    endif()

    add_subdirectory(tests)
endif()
