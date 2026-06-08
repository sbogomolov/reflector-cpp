#pragma once

#include "reflector/link_socket.h"
#include "reflector/packet.h"
#include "reflector/packet_dispatcher.h"
#include "fake_dispatcher.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace reflector {

// Fake PacketDispatcher: records registrations and lets a test push a packet to the matching
// callbacks via Deliver — exercising a subscriber's callback through the real registration path,
// with no epoll/kqueue and no real socket. Uses the same PacketFilter::Matches as production.
class FakePacketDispatcher : public PacketDispatcher {
public:
    // 1-based index of a Register call to fail (return an invalid registration), or 0 to never
    // fail. Lets a test exercise a subscriber's mid-loop registration-failure handling.
    size_t fail_register_on_call = 0;

    [[nodiscard]] PacketDispatcher::Registration Register(LinkSocket& socket, const PacketFilter& filter,
        const PacketCallback& callback) override {
        if (++register_calls_ == fail_register_on_call) {
            return {};
        }
        const auto id = static_cast<PacketDispatcher::RegistrationId>(next_id_++);
        entries_.push_back(Entry{.id = id, .socket = &socket, .filter = filter, .callback = callback});
        return MakeRegistration(id);
    }

    // Dispatches `packet` to every registration whose filter matches, regardless of socket.
    void Deliver(const Packet& packet) {
        // Iterate a snapshot so a callback that Registers mid-dispatch (appending to entries_, which
        // may reallocate) can't invalidate the walk; the new entry isn't dispatched for this packet.
        // NOTE: this is safe only because no callback UNregisters during a Deliver — the snapshot
        // holds copied callbacks, so a registration removed mid-dispatch would still be invoked here,
        // with a possibly-dangling target. Production's DispatchPacket walks live to handle removal;
        // this fake deliberately doesn't, since no test removes a registration mid-Deliver.
        const auto snapshot = entries_;
        for (const auto& entry : snapshot) {
            if (entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
    }

    // Dispatches `packet` as if captured on `socket`: only registrations made on that socket whose
    // filter matches. Models the per-socket capture path a bidirectional reflector depends on.
    void Deliver(const LinkSocket& socket, const Packet& packet) {
        const auto snapshot = entries_;  // see Deliver(packet): append-safe, no removal mid-dispatch
        for (const auto& entry : snapshot) {
            if (entry.socket == &socket && entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
    }

    [[nodiscard]] Dispatcher& UnderlyingDispatcher() noexcept override { return dispatcher; }

    // Direct access so a test can drive the timers a subscriber registered (e.g. eviction sweeps).
    FakeDispatcher dispatcher;

    [[nodiscard]] size_t RegistrationCount() const noexcept { return entries_.size(); }

private:
    bool Unregister(PacketDispatcher::RegistrationId id) noexcept override {
        std::erase_if(entries_, [id](const Entry& entry) { return entry.id == id; });
        return true;
    }

    struct Entry {
        PacketDispatcher::RegistrationId id;
        const LinkSocket* socket;
        PacketFilter filter;
        PacketCallback callback;
    };

    std::vector<Entry> entries_;
    uint64_t next_id_ = 1;
    size_t register_calls_ = 0;
};

} // namespace reflector
