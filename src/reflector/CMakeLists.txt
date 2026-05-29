add_library(reflector STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/default_address_monitor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/application.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/checksum.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/config.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/event_loop_dispatcher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/error.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/frame_builder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/interface_address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ip_address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mac_address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mdns_message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mdns_reflector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ssdp_reflector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/default_packet_dispatcher.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/raw_socket.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/wol_reflector.cpp
)
reflector_configure_project_target(reflector)
target_include_directories(reflector PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(reflector PRIVATE tomlplusplus::tomlplusplus)
target_compile_definitions(reflector PRIVATE TOML_EXCEPTIONS=0)
