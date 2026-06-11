#include "reflector/util/registration.h"

#include <gtest/gtest.h>

#include <utility>
#include <vector>

namespace reflector {

namespace {

// A deliberately non-default-constructible key, to pin that Registration works without `Key{}`
// (the optional<Key> generalization — Dispatcher uses int, but MulticastMembership keys on the
// non-default-constructible IpAddress).
struct Key {
    int value;
    explicit Key(int v) noexcept : value{v} {}
};

// Minimal Owner mirroring the Dispatcher pattern: records every Unregister(key) in order.
class Registry {
public:
    using Handle = Registration<Registry, Key>;

    [[nodiscard]] Handle Register(int value) noexcept { return Handle{this, Key{value}}; }

    std::vector<int> unregistered;

private:
    friend Handle;
    bool Unregister(Key key) noexcept {
        unregistered.push_back(key.value);
        return true;
    }
};

// Routes a self-move through two references so the call site doesn't trip -Wself-move while still
// exercising operator='s `this != &other` guard.
void MoveAssignInPlace(Registry::Handle& dst, Registry::Handle& src) noexcept { dst = std::move(src); }

} // namespace

TEST(RegistrationTest, DefaultConstructedIsInvalid) {
    const Registry::Handle handle;
    EXPECT_FALSE(handle.IsValid());
}

TEST(RegistrationTest, ResetUnregistersOnceThenIsANoOp) {
    Registry registry;
    auto handle = registry.Register(7);
    ASSERT_TRUE(handle.IsValid());

    EXPECT_TRUE(handle.Reset());   // unregisters key 7
    EXPECT_FALSE(handle.IsValid());
    EXPECT_FALSE(handle.Reset());  // idempotent: nothing left to unregister
    EXPECT_EQ(registry.unregistered, std::vector{7});
}

TEST(RegistrationTest, DestructorUnregisters) {
    Registry registry;
    {
        const auto handle = registry.Register(3);
    }
    EXPECT_EQ(registry.unregistered, std::vector{3});
}

TEST(RegistrationTest, MoveConstructionTransfersOwnershipWithoutUnregistering) {
    Registry registry;
    auto source = registry.Register(5);
    auto moved = std::move(source);

    EXPECT_FALSE(source.IsValid());  // NOLINT(bugprone-use-after-move) — moved-from is inert
    EXPECT_TRUE(moved.IsValid());
    EXPECT_TRUE(registry.unregistered.empty());  // a move never unregisters

    moved.Reset();
    EXPECT_EQ(registry.unregistered, std::vector{5});  // and the destination unregisters exactly once
}

TEST(RegistrationTest, MoveAssignmentUnregistersTheOldKeyThenAdoptsTheNew) {
    Registry registry;
    auto target = registry.Register(1);
    auto source = registry.Register(2);

    target = std::move(source);  // target's old key 1 is unregistered, then it adopts key 2
    EXPECT_EQ(registry.unregistered, std::vector{1});
    EXPECT_TRUE(target.IsValid());
    EXPECT_FALSE(source.IsValid());  // NOLINT(bugprone-use-after-move)

    target.Reset();
    EXPECT_EQ(registry.unregistered, (std::vector{1, 2}));  // then key 2 on the eventual reset
}

TEST(RegistrationTest, SelfMoveAssignmentKeepsTheRegistration) {
    Registry registry;
    auto handle = registry.Register(9);

    MoveAssignInPlace(handle, handle);  // the `this != &other` guard keeps it intact
    EXPECT_TRUE(handle.IsValid());
    EXPECT_TRUE(registry.unregistered.empty());

    handle.Reset();
    EXPECT_EQ(registry.unregistered, std::vector{9});
}

} // namespace reflector
