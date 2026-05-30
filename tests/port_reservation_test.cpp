#include "reflector/port_reservation.h"

#include "reflector/ip_address.h"

#include <gtest/gtest.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace reflector {
namespace {

TEST(PortReservationTest, CreateReturnsANonZeroPort) {
    const auto reservation = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_NE(reservation->Port(), 0);
}

TEST(PortReservationTest, TwoReservationsGetDistinctPorts) {
    const auto first = PortReservation::Create(IpAddress::Family::V4);
    const auto second = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->Port(), second->Port());
}

TEST(PortReservationTest, ReservedPortIsClaimed) {
    const auto reservation = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(reservation.has_value());

    // A second plain bind to the same port must fail (EADDRINUSE) while the reservation holds it.
    const int probe = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(reservation->Port());
    EXPECT_NE(::bind(probe, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    EXPECT_EQ(errno, EADDRINUSE);
    ::close(probe);
}

TEST(PortReservationTest, SuppressesIcmpPortUnreachable) {
    // The core guarantee: with the port reserved, a datagram sent to it does NOT bounce an ICMP
    // port-unreachable. A connected UDP sender surfaces that ICMP as ECONNREFUSED on its next recv;
    // we assert the recv times out instead (no ICMP). The mirror "no reservation -> ECONNREFUSED"
    // case is not asserted here: an OS-assigned ephemeral port is not reliably free to re-probe.
    const auto reservation = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(reservation.has_value());

    const int sender = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    timeval tv{.tv_sec = 0, .tv_usec = 300000};
    ::setsockopt(sender, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(reservation->Port());
    ASSERT_EQ(::connect(sender, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    const std::byte one{1};
    ASSERT_EQ(::send(sender, &one, 1, 0), 1);

    std::array<std::byte, 8> buffer{};
    const auto received = ::recv(sender, buffer.data(), buffer.size(), 0);
    EXPECT_TRUE(received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        << "expected timeout (no ICMP), got received=" << received << " errno=" << errno;
    ::close(sender);
}

TEST(PortReservationTest, MoveTransfersOwnershipWithoutDoubleClose) {
    auto first = PortReservation::Create(IpAddress::Family::V4);
    ASSERT_TRUE(first.has_value());
    const auto port = first->Port();

    PortReservation moved = std::move(*first);
    EXPECT_EQ(moved.Port(), port);
    // No crash / ASan double-close when both `first` (moved-from) and `moved` destruct here.
}

TEST(PortReservationTest, CreateWorksForIpv6) {
    const auto reservation = PortReservation::Create(IpAddress::Family::V6);
    ASSERT_TRUE(reservation.has_value());
    EXPECT_NE(reservation->Port(), 0);
}

} // namespace
} // namespace reflector
