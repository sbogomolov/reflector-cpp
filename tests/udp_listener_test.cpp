#include "reflector/udp_listener.h"

#include <gtest/gtest.h>

namespace reflector {

TEST(UdpListenerTest, ConstructorBindsSocket) {
    UdpListener listener{UdpListener::Options{.local_ip = IpAddress::AnyV4()}};

    EXPECT_TRUE(listener.IsValid());
}

TEST(UdpListenerTest, UnknownInterfaceFails) {
    UdpListener listener{UdpListener::Options{
        .interface = "nonexistent-iface-xyz",
        .local_ip = IpAddress::AnyV4(),
    }};

    EXPECT_FALSE(listener.IsValid());
}

TEST(UdpListenerTest, ConstructorBindsV6Socket) {
    UdpListener listener{UdpListener::Options{.local_ip = IpAddress::AnyV6()}};

    EXPECT_TRUE(listener.IsValid());
}

} // namespace reflector
