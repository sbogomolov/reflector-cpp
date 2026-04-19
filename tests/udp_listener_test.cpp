#include "reflector/udp_listener.h"

#include <gtest/gtest.h>

namespace reflector {

TEST(UdpListenerTest, ConstructorBindsSocket) {
    UdpListener listener{UdpListener::Options{}};

    EXPECT_TRUE(listener.IsValid());
}

TEST(UdpListenerTest, UnknownInterfaceFails) {
    UdpListener listener{UdpListener::Options{.interface = "nonexistent-iface-xyz"}};

    EXPECT_FALSE(listener.IsValid());
}

} // namespace reflector
