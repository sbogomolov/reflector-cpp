add_executable(reflector_test)
target_link_libraries(reflector_test PRIVATE reflector GTest::gtest_main)

target_sources(reflector_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/config_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/delegate_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dispatcher_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/error_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/logger_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mac_address_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_listener_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_sender_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udp_socket_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_listener_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_reflector_test.cpp
)

include(GoogleTest)
gtest_discover_tests(reflector_test)
