add_executable(reflector_test
    ${CMAKE_CURRENT_SOURCE_DIR}/config_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/delegate_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dispatcher_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/error_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/logger_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mac_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/packet_capture_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_link_fanout_sender_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_listener_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_reflector_test.cpp
)
reflector_configure_project_target(reflector_test)
target_link_libraries(reflector_test PRIVATE reflector GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(reflector_test
    PROPERTIES LABELS unit
)
