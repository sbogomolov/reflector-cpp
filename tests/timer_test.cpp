#include "reflector/timer.h"

#include "reflector/util/delegate.h"
#include "mocks/fake_dispatcher.h"

#include <gtest/gtest.h>

#include <chrono>
#include <utility>

namespace reflector {

struct Counter {
    int count = 0;
    void Tick() { ++count; }
};

using namespace std::chrono_literals;

TEST(TimerTest, RegistersOnConstructionAndIsValid) {
    FakeDispatcher dispatcher;
    Counter counter;
    const Timer timer{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
    EXPECT_TRUE(timer.IsValid());
    EXPECT_EQ(dispatcher.TimerCount(), 1u);
}

TEST(TimerTest, RejectsNonPositiveIntervalAndIsInvalid) {
    FakeDispatcher dispatcher;
    Counter counter;
    const Timer timer{dispatcher, 0s, CreateDelegate<&Counter::Tick>(&counter)};
    EXPECT_FALSE(timer.IsValid());
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, RejectsInvalidCallbackAndIsInvalid) {
    FakeDispatcher dispatcher;
    const Timer timer{dispatcher, 1s, Dispatcher::OnTimerCallback{}};  // default Delegate: unset
    EXPECT_FALSE(timer.IsValid());
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, DefaultConstructedIsInvalid) {
    const Timer timer;
    EXPECT_FALSE(timer.IsValid());
}

TEST(TimerTest, UnregistersOnDestruction) {
    FakeDispatcher dispatcher;
    Counter counter;
    {
        const Timer timer{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
        ASSERT_EQ(dispatcher.TimerCount(), 1u);
    }
    EXPECT_EQ(dispatcher.TimerCount(), 0u);
}

TEST(TimerTest, MoveDoesNotDoubleUnregister) {
    FakeDispatcher dispatcher;
    Counter counter;
    {
        Timer first{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
        Timer second = std::move(first);
        EXPECT_TRUE(second.IsValid());
        EXPECT_EQ(dispatcher.TimerCount(), 1u);
    }
    EXPECT_EQ(dispatcher.TimerCount(), 0u);  // exactly one unregister, from `second`
}

TEST(TimerTest, FiringInvokesTheCallback) {
    FakeDispatcher dispatcher;
    Counter counter;
    const Timer timer{dispatcher, 1s, CreateDelegate<&Counter::Tick>(&counter)};
    dispatcher.FireTimers();
    EXPECT_EQ(counter.count, 1);
}

} // namespace reflector
