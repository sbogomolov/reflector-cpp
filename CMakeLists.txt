cmake_minimum_required(VERSION 3.28)
project(reflector VERSION 0.4.1 LANGUAGES CXX)
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
option(REFLECTOR_ENABLE_VALGRIND_UNIT_TESTS "Enable the Docker-backed unit suite under Valgrind memcheck" OFF)
option(REFLECTOR_ENABLE_VALGRIND_E2E_TESTS "Enable the Docker-backed e2e suite with the reflector under Valgrind memcheck" OFF)
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
        -Wsuggest-override
        -Woverloaded-virtual
        -Wextra-semi
        # -Wshadow is per-compiler: GCC's catches a ctor parameter (and inherited-member) shadow; Clang needs
        # -Wshadow-all (a superset: + -Wshadow-field-in-constructor / -Wshadow-uncaptured-local) for parity.
        $<$<CXX_COMPILER_ID:GNU>:-Wshadow>
        $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wshadow-all>
        # Same check, different spelling: GCC's -Wcast-align=strict == Clang's plain -Wcast-align.
        $<$<CXX_COMPILER_ID:GNU>:-Wcast-align=strict>
        $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wcast-align>
        # GCC-only (no Clang equivalent):
        $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-cond>
        $<$<CXX_COMPILER_ID:GNU>:-Wduplicated-branches>
        $<$<CXX_COMPILER_ID:GNU>:-Wlogical-op>
        $<$<CXX_COMPILER_ID:GNU>:-Wuseless-cast>
        $<$<CXX_COMPILER_ID:GNU>:-Wformat-signedness>
        # Clang-only (no GCC equivalent):
        $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wcomma>
        $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wconditional-uninitialized>
        # A free function with no prior declaration should be static or in an anonymous namespace; GCC
        # spells this -Wmissing-declarations, Clang's C++ form is -Wmissing-prototypes.
        $<$<CXX_COMPILER_ID:GNU>:-Wmissing-declarations>
        $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wmissing-prototypes>
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
            NAME Docker.Unit
            COMMAND ${PROJECT_SOURCE_DIR}/docker_test.sh ${_reflector_docker_test_variant}
        )
        set_tests_properties(Docker.Unit PROPERTIES
            LABELS "unit;docker"
            TIMEOUT 600
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
        unset(_reflector_docker_test_variant)
    endif()

    if(REFLECTOR_ENABLE_E2E_TESTS)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
        add_test(
            NAME Docker.E2E
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/e2e/run.py
        )
        set_tests_properties(Docker.E2E PROPERTIES
            LABELS "e2e;docker"
            TIMEOUT 180
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
    endif()

    if(REFLECTOR_ENABLE_VALGRIND_UNIT_TESTS)
        find_program(DOCKER_EXECUTABLE docker)
        if(NOT DOCKER_EXECUTABLE)
            message(FATAL_ERROR "REFLECTOR_ENABLE_VALGRIND_UNIT_TESTS requires the docker executable")
        endif()

        # docker_test.sh valgrind builds the test-valgrind image and runs the whole unit binary under
        # memcheck in a CAP_NET_ADMIN container. Valgrind is ~20-40x slower, hence the long timeout.
        add_test(
            NAME Valgrind.Unit
            COMMAND ${PROJECT_SOURCE_DIR}/docker_test.sh valgrind
        )
        set_tests_properties(Valgrind.Unit PROPERTIES
            LABELS "unit;docker;valgrind"
            TIMEOUT 1800
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
    endif()

    if(REFLECTOR_ENABLE_VALGRIND_E2E_TESTS)
        find_package(Python3 COMPONENTS Interpreter REQUIRED)
        # run.py --valgrind runs the e2e suite with the reflector under memcheck (runtime-valgrind image),
        # SIGTERMing it per case so valgrind reports leaks at a clean exit. Much slower, hence the timeout.
        add_test(
            NAME Valgrind.E2E
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/e2e/run.py --valgrind
        )
        set_tests_properties(Valgrind.E2E PROPERTIES
            LABELS "e2e;docker;valgrind"
            TIMEOUT 1800
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
    endif()
endif()
