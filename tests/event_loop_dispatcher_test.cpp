#include "reflector/event_loop_dispatcher.h"

#include "reflector/timer.h"
#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <cstddef>

#include <unistd.h>

namespace reflector {

class EventLoopDispatcherTest : public ::testing::Test {
protected:
    EventLoopDispatcher dispatcher;

    size_t RegistrationCount() const {
        return dispatcher.RegistrationCount();
    }
};

// A pipe whose read end stands in for a non-socket readable fd — the kind DefaultPacketDispatcher
// and the interface-address monitor register. Writing a byte makes the read end poll-readable.
struct ReadablePipe : NoCopy {
    ReadablePipe() noexcept {
        if (::pipe(fds) != 0) {
            fds[0] = -1;
            fds[1] = -1;
        }
    }
    ~ReadablePipe() noexcept {
        for (const int fd : fds) {
            if (fd >= 0) {
                ::close(fd);
            }
        }
    }

    int ReadEnd() const noexcept { return fds[0]; }
    bool Notify() const noexcept {
        const std::byte one{1};
        return ::write(fds[1], &one, 1) == 1;
    }

    int fds[2] = {-1, -1};
};

struct ReadableCounter {
    void OnReadable(int fd) {
        ++count;
        last_fd = fd;
    }
    int count = 0;
    int last_fd = -1;
};

// Resets its own registration the first time it fires — a callback that unregisters itself
// mid-poll, which is safe only because PollOnce copies the delegate before invoking it.
struct SelfUnregisteringReadable {
    void OnReadable(int) {
        ++count;
        if (registration_to_reset != nullptr) {
            reset_result = registration_to_reset->Reset();
        }
    }
    Dispatcher::Registration* registration_to_reset = nullptr;
    bool reset_result = false;
    int count = 0;
};

// Requests the loop stop the first time it fires, so Run() makes exactly one dispatch pass.
struct StopRequestingReadable {
    volatile std::sig_atomic_t* stop_requested = nullptr;
    int count = 0;
    void OnReadable(int) {
        ++count;
        *stop_requested = 1;
    }
};

TEST_F(EventLoopDispatcherTest, PollOnceInvokesCallbackWithItsFd) {
    ReadablePipe pipe;
    ASSERT_GE(pipe.ReadEnd(), 0);
    ReadableCounter counter;

    const auto registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&counter));
    ASSERT_TRUE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 1);

    ASSERT_TRUE(pipe.Notify());
    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(counter.count, 1);
    EXPECT_EQ(counter.last_fd, pipe.ReadEnd());
}

TEST_F(EventLoopDispatcherTest, RegisterRejectsInvalidFd) {
    ReadableCounter counter;

    const auto registration = dispatcher.Register(
        -1, CreateDelegate<&ReadableCounter::OnReadable>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
}

TEST_F(EventLoopDispatcherTest, RegisterRejectsAlreadyWatchedFd) {
    ReadablePipe pipe;
    ASSERT_GE(pipe.ReadEnd(), 0);
    ReadableCounter first;
    ReadableCounter second;

    const auto first_registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&first));
    ASSERT_TRUE(first_registration.IsValid());

    const auto second_registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&second));

    EXPECT_FALSE(second_registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 1);
}

TEST_F(EventLoopDispatcherTest, UnregisterStopsCallback) {
    ReadablePipe pipe;
    ASSERT_GE(pipe.ReadEnd(), 0);
    ReadableCounter counter;

    auto registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&counter));
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(registration.Reset());
    EXPECT_EQ(RegistrationCount(), 0);

    ASSERT_TRUE(pipe.Notify());
    // The fd was removed from the event queue, so the written byte wakes nothing.
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
    EXPECT_EQ(counter.count, 0);
}

TEST_F(EventLoopDispatcherTest, CallbackCanUnregisterItself) {
    ReadablePipe pipe;
    ASSERT_GE(pipe.ReadEnd(), 0);
    SelfUnregisteringReadable counter;

    auto registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&SelfUnregisteringReadable::OnReadable>(&counter));
    ASSERT_TRUE(registration.IsValid());
    counter.registration_to_reset = &registration;

    ASSERT_TRUE(pipe.Notify());
    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));

    EXPECT_EQ(counter.count, 1);
    EXPECT_TRUE(counter.reset_result);
    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
}

TEST_F(EventLoopDispatcherTest, EachFdInvokesItsOwnCallback) {
    ReadablePipe first_pipe;
    ReadablePipe second_pipe;
    ASSERT_GE(first_pipe.ReadEnd(), 0);
    ASSERT_GE(second_pipe.ReadEnd(), 0);
    ReadableCounter first;
    ReadableCounter second;

    const auto first_registration = dispatcher.Register(
        first_pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&first));
    const auto second_registration = dispatcher.Register(
        second_pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&second));
    ASSERT_TRUE(first_registration.IsValid());
    ASSERT_TRUE(second_registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 2);

    ASSERT_TRUE(second_pipe.Notify());
    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));

    EXPECT_EQ(first.count, 0);
    EXPECT_EQ(second.count, 1);
    EXPECT_EQ(second.last_fd, second_pipe.ReadEnd());
}

TEST_F(EventLoopDispatcherTest, PollOnceWithoutRegistrationsReturnsFalse) {
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
}

// Run() loops PollOnce until stop_requested is set. A callback that requests the stop when it
// fires lets the loop make a single pass — dispatching the event, then exiting — without threads.
TEST_F(EventLoopDispatcherTest, RunPollsUntilStopRequested) {
    ReadablePipe pipe;
    ASSERT_GE(pipe.ReadEnd(), 0);
    volatile std::sig_atomic_t stop_requested = 0;
    StopRequestingReadable counter{.stop_requested = &stop_requested};

    const auto registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&StopRequestingReadable::OnReadable>(&counter));
    ASSERT_TRUE(registration.IsValid());
    ASSERT_TRUE(pipe.Notify());

    dispatcher.Run(stop_requested);

    EXPECT_EQ(counter.count, 1);
}

struct TimerCounter {
    int count = 0;
    void Tick() { ++count; }
};

// Fires, then unregisters another timer mid-round (by resetting its handle) — used to prove a
// timer cancelled by an earlier callback in the same FireDueTimers pass does not itself fire.
struct TimerUnregisterer {
    Timer* other = nullptr;
    int count = 0;
    void Tick() {
        ++count;
        if (other != nullptr) {
            *other = {};
        }
    }
};

TEST_F(EventLoopDispatcherTest, NextTimeoutReturnsCapWhenNoTimers) {
    const auto now = std::chrono::steady_clock::now();
    EXPECT_EQ(dispatcher.NextTimeout(now), std::chrono::milliseconds{1000});
}

TEST_F(EventLoopDispatcherTest, FireDueTimersInvokesAndReschedulesDueTimer) {
    TimerCounter counter;
    Timer timer{dispatcher, std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter)};
    ASSERT_TRUE(timer.IsValid());
    const auto t0 = std::chrono::steady_clock::now();

    // Not yet due at t0: no fire.
    dispatcher.FireDueTimers(t0);
    EXPECT_EQ(counter.count, 0);

    // Due at t0 + interval: fires once, then reschedules — a second call at the same instant does not refire.
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{50});
    EXPECT_EQ(counter.count, 1);
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{50});
    EXPECT_EQ(counter.count, 1);

    // Due again a full interval later.
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{100});
    EXPECT_EQ(counter.count, 2);

    timer = {};  // RAII unregister
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{1000});
    EXPECT_EQ(counter.count, 2);  // unregistered: no further fires
}

TEST_F(EventLoopDispatcherTest, NextTimeoutClampsToSoonestDeadlineAndFloorsAtZero) {
    TimerCounter counter;
    const Timer timer{dispatcher, std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter)};
    ASSERT_TRUE(timer.IsValid());
    const auto t0 = std::chrono::steady_clock::now();

    // Halfway to the deadline: ~25ms remain, clamped under the 1000ms cap.
    const auto remaining = dispatcher.NextTimeout(t0 + std::chrono::milliseconds{25});
    EXPECT_GT(remaining, std::chrono::milliseconds{0});
    EXPECT_LE(remaining, std::chrono::milliseconds{50});

    // Past due: floored at 0 (never a negative timeout to the kernel).
    EXPECT_EQ(dispatcher.NextTimeout(t0 + std::chrono::milliseconds{100}), std::chrono::milliseconds{0});
}

TEST_F(EventLoopDispatcherTest, TimerRejectsNonPositiveInterval) {
    TimerCounter counter;
    const Timer timer{dispatcher, std::chrono::milliseconds{0}, CreateDelegate<&TimerCounter::Tick>(&counter)};
    EXPECT_FALSE(timer.IsValid());
}

TEST_F(EventLoopDispatcherTest, CallbackCanUnregisterAnotherDueTimerBeforeItFires) {
    TimerUnregisterer first;
    TimerCounter second;
    // Same interval, so both come due together; `first` (registered first, so fired first) cancels
    // `second` before the walk reaches it.
    Timer first_timer{dispatcher, std::chrono::milliseconds{50}, CreateDelegate<&TimerUnregisterer::Tick>(&first)};
    Timer second_timer{dispatcher, std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&second)};
    first.other = &second_timer;
    const auto t0 = std::chrono::steady_clock::now();

    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{50});
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 0);  // cancelled mid-round → never fired (a snapshot walk would fire it)
}

} // namespace reflector
