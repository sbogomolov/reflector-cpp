#pragma once

#include "reflector/dispatcher.h"
#include "reflector/packet.h"
#include "reflector/udp_socket.h"
#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>

namespace reflector {

struct PacketCounter {
    void OnPacket(const Packet&) { ++count; }

    int count = 0;
};

struct PacketRecorder {
    void OnPacket(const Packet& packet) {
        ++count;
        payload.assign(packet.payload.begin(), packet.payload.end());
        source_ip = packet.header.source_ip;
    }

    int count = 0;
    std::vector<std::byte> payload;
    IpAddress source_ip = IpAddress::Any();
};

inline Packet MakePacket(IpAddress source_ip = IpAddress::FromBytes(192, 0, 2, 1), uint16_t source_port = 12345) {
    return Packet{
        .header = PacketHeader{
            .source_ip = source_ip,
            .source_port = source_port,
        },
        .payload = {},
    };
}

inline uint16_t BoundPort(const UdpSocket& socket) {
    sockaddr_in address{};
    socklen_t address_size = sizeof(address);
    if (getsockname(socket.Fd(), reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        ADD_FAILURE() << "getsockname failed for fd " << socket.Fd() << ": " << std::strerror(errno);
        return 0;
    }
    return ntohs(address.sin_port);
}

inline uint16_t BindLoopback(UdpSocket& socket, uint16_t port = 0) {
    EXPECT_TRUE(socket.SetReuseAddr(true));
    EXPECT_TRUE(socket.Bind(IpAddress::Loopback(), port));
    const auto bound_port = BoundPort(socket);
    EXPECT_NE(bound_port, 0);
    return bound_port;
}

inline std::vector<uint16_t> FreeLoopbackPorts(size_t count) {
    std::vector<UdpSocket> sockets;
    std::vector<uint16_t> ports;
    sockets.reserve(count);
    ports.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        auto& socket = sockets.emplace_back();
        EXPECT_TRUE(socket.SetReuseAddr(true));
        EXPECT_TRUE(socket.Bind(IpAddress::Loopback(), 0));
        ports.push_back(BoundPort(socket));
    }

    return ports;
}

inline uint16_t FreeLoopbackPort() {
    const auto ports = FreeLoopbackPorts(1);
    return ports.front();
}

struct LoopbackReceiver {
    Dispatcher dispatcher;
    UdpSocket socket;
    PacketRecorder recorder;
    Dispatcher::Registration registration;

    explicit LoopbackReceiver(uint16_t port = 0) {
        BindLoopback(socket, port);
        registration = dispatcher.Register(
            socket, PacketFilter{}, CreateDelegate<&PacketRecorder::OnPacket>(&recorder));
        EXPECT_TRUE(registration.IsValid());
    }

    [[nodiscard]] uint16_t Port() const { return BoundPort(socket); }
    bool PollOnce(std::chrono::milliseconds timeout) { return dispatcher.PollOnce(timeout); }
};

} // namespace reflector
