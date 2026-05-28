cmake_minimum_required(VERSION 3.22)
project(reflector VERSION 0.2.1 LANGUAGES CXX)
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

option(REFLECTOR_ENABLE_E2E_TESTS "Enable Docker-backed end-to-end tests" OFF)
option(REFLECTOR_ENABLE_DOCKER_TESTS "Enable Docker-backed build tests" OFF)
option(REFLECTOR_ENABLE_CCACHE "Use ccache as the compiler launcher when available" ON)

if(REFLECTOR_ENABLE_CCACHE)
    if(CMAKE_CXX_COMPILER_LAUNCHER)
        message(STATUS "Using explicit CXX compiler launcher: ${CMAKE_CXX_COMPILER_LAUNCHER}")
    else()
        find_program(CCACHE_EXECUTABLE ccache)
        if(CCACHE_EXECUTABLE)
            set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXECUTABLE}")
            message(STATUS "Using ccache: ${CCACHE_EXECUTABLE}")
        else()
            message(STATUS "ccache not found; building without a compiler launcher")
        endif()
    endif()
endif()

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
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wzero-as-null-pointer-constant
        -Wnull-dereference
        -Wconversion
        -Wsign-conversion
        -Wcast-qual
        -Wundef
        -Wformat=2
        -Wswitch-enum
        $<$<CXX_COMPILER_ID:GNU>:-Wcast-align=strict>
        $<$<CXX_COMPILER_ID:GNU>:-Wsuggest-override>
        $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-cond>
        $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-branches>
        $<$<CXX_COMPILER_ID:GNU>:-Wlogical-op>
        $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wcast-align>
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
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
        GIT_SHALLOW FALSE  # ensure submodules are checked out
    )
    FetchContent_MakeAvailable(googletest)

    add_subdirectory(tests)

    if(REFLECTOR_ENABLE_DOCKER_TESTS)
        find_program(DOCKER_EXECUTABLE docker)
        if(NOT DOCKER_EXECUTABLE)
            message(FATAL_ERROR "REFLECTOR_ENABLE_DOCKER_TESTS requires the docker executable")
        endif()
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            set(_reflector_docker_test_variant debug)
        else()
            set(_reflector_docker_test_variant release)
        endif()

        # docker_test.sh builds the test image and runs the suite in a container with
        # CAP_NET_ADMIN, so the veth-pair tests run rather than skip.
        add_test(
            NAME ReflectorDocker.UnitTests
            COMMAND ${PROJECT_SOURCE_DIR}/docker_test.sh ${_reflector_docker_test_variant}
        )
        set_tests_properties(ReflectorDocker.UnitTests PROPERTIES
            LABELS "docker"
            TIMEOUT 600
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
        unset(_reflector_docker_test_variant)
    endif()

    if(REFLECTOR_ENABLE_E2E_TESTS)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
        add_test(
            NAME ReflectorE2E.WolReflection
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/e2e/run.py
        )
        set_tests_properties(ReflectorE2E.WolReflection PROPERTIES
            LABELS "e2e;docker"
            TIMEOUT 180
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
    endif()
endif()
