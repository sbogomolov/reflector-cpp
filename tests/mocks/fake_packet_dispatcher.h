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

    // Dispatches `packet` to every enabled registration whose filter matches, regardless of socket. A
    // callback may Register (appends -- index by position so a reallocation can't dangle the walk) or
    // Unregister (marks disabled: skipped here, swept after), matching production's deferred-removal walk.
    void Deliver(const Packet& packet) {
        dispatching_ = true;
        for (size_t idx = 0; idx < entries_.size(); ++idx) {
            const Entry& entry = entries_[idx];
            if (entry.enabled && entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
        dispatching_ = false;
        Sweep();
    }

    // Dispatches `packet` as if captured on `socket`: only registrations made on that socket whose
    // filter matches. Models the per-socket capture path a bidirectional reflector depends on.
    void Deliver(const LinkSocket& socket, const Packet& packet) {
        dispatching_ = true;
        for (size_t idx = 0; idx < entries_.size(); ++idx) {
            const Entry& entry = entries_[idx];
            if (entry.enabled && entry.socket == &socket && entry.filter.Matches(packet)) {
                entry.callback(packet);
            }
        }
        dispatching_ = false;
        Sweep();
    }

    [[nodiscard]] Dispatcher& UnderlyingDispatcher() noexcept override { return dispatcher; }

    // Direct access so a test can drive the timers a subscriber registered (e.g. eviction sweeps).
    FakeDispatcher dispatcher;

    [[nodiscard]] size_t RegistrationCount() const noexcept { return entries_.size(); }

private:
    bool Unregister(PacketDispatcher::RegistrationId id) noexcept override {
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->id == id && it->enabled) {  // at most one enabled entry per id
                if (dispatching_) {
                    it->enabled = false;  // a Deliver is walking; defer the erase to its post-walk sweep
                } else {
                    entries_.erase(it);  // no walk in progress; erase in place
                }
                return true;
            }
        }
        return false;
    }

    // Erases the entries Unregister marked disabled mid-Deliver. Runs after Deliver's walk -- never
    // during it, where a live erase would shift the vector. Named after production's Sweep.
    void Sweep() {
        std::erase_if(entries_, [](const Entry& entry) { return !entry.enabled; });
    }

    struct Entry {
        PacketDispatcher::RegistrationId id;
        const LinkSocket* socket;
        PacketFilter filter;
        PacketCallback callback;
        bool enabled = true;
    };

    std::vector<Entry> entries_;
    uint64_t next_id_ = 1;
    size_t register_calls_ = 0;
    bool dispatching_ = false;
};

} // namespace reflector
