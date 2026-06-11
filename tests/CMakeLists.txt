add_executable(reflector_test
    ${CMAKE_CURRENT_SOURCE_DIR}/default_address_monitor_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/address_family_pair_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/application_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/checksum_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/config_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/delegate_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dial_proxy_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/error_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/event_loop_dispatcher_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/family_capability_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/timer_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/frame_builder_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/http_message_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/interface_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/interface_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_endpoint_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/logger_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mac_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mdns_message_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mdns_reflector_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/port_reservation_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_message_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_reflector_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/default_packet_dispatcher_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/stream_buffer_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tcp_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/util/udp_socket.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_reflector_test.cpp
)
reflector_configure_project_target(reflector_test)
target_link_libraries(reflector_test PRIVATE reflector GTest::gtest_main)

# Every test carries the "unit" label so a plain `ctest -L unit` runs the full suite. The
# subset whose fixture names contain "RequiresRoot" additionally carries the "root" label
# — those need the privileges the reflector itself uses for loopback I/O: packet capture
# (CAP_NET_RAW on Linux, bpf group / root on macOS) or a SO_BINDTODEVICE sender. The
# fixtures probe at SetUp and GTEST_SKIP when privileges are missing, so the
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
