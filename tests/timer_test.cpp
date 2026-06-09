#include "reflector/timer.h"

#include "reflector/util/delegate.h"
#include "mocks/fake_dispatcher.h"

#include <gtest/gtest.h>

#include <chrono>
#include <utility>

namespace reflector {

struct Counter {
    int count = 0;
    void Tick(std::chrono::steady_clock::time_point) { ++count; }
};

using namespace std::chrono_literals;

TEST(TimerTest, ConstructedTimerIsNotRunning) {
    FakeDispatcher dispatcher;
    const Timer timer{dispatcher};
    EXPECT_FALSE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // a stable id is reserved; nothing is registered yet
}

TEST(TimerTest, StartRegistersAndStopUnregisters) {
    FakeDispatcher dispatcher;
    Counter counter;
    Timer timer{dispatcher};

    timer.Start(1s, CreateDelegate<&Counter::Tick>(&counter));
    EXPECT_TRUE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);

    timer.Stop();
    EXPECT_FALSE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, StartRejectsNonPositiveInterval) {
    FakeDispatcher dispatcher;
    Counter counter;
    Timer timer{dispatcher};
    timer.Start(0s, CreateDelegate<&Counter::Tick>(&counter));
    EXPECT_FALSE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, StartRejectsInvalidCallback) {
    FakeDispatcher dispatcher;
    Timer timer{dispatcher};
    timer.Start(1s, Dispatcher::OnTimerCallback{});  // unset
    EXPECT_FALSE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, StartOnARunningTimerRestartsIt) {
    FakeDispatcher dispatcher;
    Counter counter;
    Timer timer{dispatcher};
    timer.Start(1s, CreateDelegate<&Counter::Tick>(&counter));
    timer.Start(1s, CreateDelegate<&Counter::Tick>(&counter));  // restart, not a second registration
    EXPECT_TRUE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);
}

TEST(TimerTest, StopsOnDestruction) {
    FakeDispatcher dispatcher;
    Counter counter;
    {
        Timer timer{dispatcher};
        timer.Start(1s, CreateDelegate<&Counter::Tick>(&counter));
        ASSERT_EQ(dispatcher.TimerCount(), 1u);
    }
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, MoveTransfersTheRunningRegistrationWithoutDoubleUnregister) {
    FakeDispatcher dispatcher;
    Counter counter;
    {
        Timer first{dispatcher};
        first.Start(1s, CreateDelegate<&Counter::Tick>(&counter));
        Timer second = std::move(first);
        EXPECT_TRUE(second.IsRunning());
        EXPECT_EQ(dispatcher.TimerCount(), 1u);
    }
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // exactly one unregister, from `second`
}

TEST(TimerTest, FiringInvokesTheCallback) {
    FakeDispatcher dispatcher;
    Counter counter;
    Timer timer{dispatcher};
    timer.Start(1s, CreateDelegate<&Counter::Tick>(&counter));
    dispatcher.FireTimers(std::chrono::steady_clock::now());
    EXPECT_EQ(counter.count, 1);
}

// Stops then restarts the timer from inside its own fire: the mid-fire Stop defers the erase to the
// fake's sweep, and the restart must reclaim the disabled entry in place rather than append.
struct StopRestarter {
    Timer* self = nullptr;
    int count = 0;
    void Tick(std::chrono::steady_clock::time_point) {
        ++count;
        if (count == 1 && self != nullptr) {
            self->Stop();
            self->Start(1s, CreateDelegate<&StopRestarter::Tick>(this));
        }
    }
};

TEST(TimerTest, StopThenStartMidFireReclaimsTheTimer) {
    FakeDispatcher dispatcher;
    StopRestarter restarter;
    Timer timer{dispatcher};
    restarter.self = &timer;
    timer.Start(1s, CreateDelegate<&StopRestarter::Tick>(&restarter));

    dispatcher.FireTimers(std::chrono::steady_clock::now());
    EXPECT_EQ(restarter.count, 1);           // the restart did not fire it again in the same round
    EXPECT_TRUE(timer.IsRunning());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);  // reclaimed in place; the sweep spared it

    dispatcher.FireTimers(std::chrono::steady_clock::now());
    EXPECT_EQ(restarter.count, 2);  // still alive the next round
}

} // namespace reflector
