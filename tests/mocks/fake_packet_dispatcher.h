#pragma once

#include "reflector/packet.h"
#include "reflector/packet_dispatcher.h"
#include "reflector/receive_socket.h"

#include <cstddef>
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

    [[nodiscard]] PacketDispatcher::Registration Register(ReceiveSocket& /*socket*/, const PacketFilter& filter,
        const PacketCallback& callback) override {
        if (++register_calls_ == fail_register_on_call) {
            return {};
        }
        const auto id = next_id_++;
        entries_.push_back(Entry{.id = id, .filter = filter, .callback = callback});
        return MakeRegistration(id);
    }

    // Dispatches `packet` to every registration whose filter matches.
    void Deliver(const Packet& packet) {
        for (const auto& entry : entries_) {
            if (entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
    }

    [[nodiscard]] size_t RegistrationCount() const noexcept { return entries_.size(); }

private:
    bool Unregister(PacketDispatcher::RegistrationId id) noexcept override {
        std::erase_if(entries_, [id](const Entry& entry) { return entry.id == id; });
        return true;
    }

    struct Entry {
        PacketDispatcher::RegistrationId id;
        PacketFilter filter;
        PacketCallback callback;
    };

    std::vector<Entry> entries_;
    PacketDispatcher::RegistrationId next_id_ = 1;
    size_t register_calls_ = 0;
};

} // namespace reflector
