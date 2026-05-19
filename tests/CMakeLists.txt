add_executable(reflector_test
    ${CMAKE_CURRENT_SOURCE_DIR}/config_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/delegate_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dispatcher_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dispatcher_root_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/error_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/logger_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mac_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/packet_capture_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/packet_capture_socket_root_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_link_fanout_sender_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_listener_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_reflector_test.cpp
)
reflector_configure_project_target(reflector_test)
target_link_libraries(reflector_test PRIVATE reflector GTest::gtest_main)

# Every test carries the "unit" label so a plain `ctest -L unit` runs the full suite. The
# subset whose fixture names contain "RequiresRoot" additionally carries the "root" label
# — those need elevated capture privileges (CAP_NET_RAW on Linux, bpf group / root on
# macOS). The fixtures probe at SetUp and GTEST_SKIP when privileges are missing, so the
# default `ctest` run is green on an under-privileged box. Use `ctest -L root` to require
# them or `ctest -LE root` to skip them outright.
include(GoogleTest)
gtest_discover_tests(reflector_test
    TEST_FILTER -*RequiresRoot*
    TEST_PREFIX "unit."
    PROPERTIES LABELS "unit"
)
gtest_discover_tests(reflector_test
    TEST_FILTER *RequiresRoot*
    TEST_PREFIX "unit-root."
    PROPERTIES LABELS "unit\;root"
)
