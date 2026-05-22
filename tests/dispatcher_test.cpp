#include "reflector/dispatcher.h"

#include "reflector/util/delegate.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>

#include <unistd.h>

namespace reflector {

class DispatcherTest : public ::testing::Test {
protected:
    Dispatcher dispatcher;

    size_t RegistrationCount() const {
        return dispatcher.RegistrationCount();
    }
};

// A pipe whose read end stands in for a non-socket readable fd — the kind PacketDispatcher
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

TEST_F(DispatcherTest, PollOnceInvokesCallbackWithItsFd) {
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

TEST_F(DispatcherTest, RegisterRejectsInvalidFd) {
    ReadableCounter counter;

    const auto registration = dispatcher.Register(
        -1, CreateDelegate<&ReadableCounter::OnReadable>(&counter));

    EXPECT_FALSE(registration.IsValid());
    EXPECT_EQ(RegistrationCount(), 0);
}

TEST_F(DispatcherTest, RegisterRejectsAlreadyWatchedFd) {
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

TEST_F(DispatcherTest, UnregisterStopsCallback) {
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

TEST_F(DispatcherTest, CallbackCanUnregisterItself) {
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

TEST_F(DispatcherTest, EachFdInvokesItsOwnCallback) {
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

TEST_F(DispatcherTest, PollOnceWithoutRegistrationsReturnsFalse) {
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
}

} // namespace reflector
