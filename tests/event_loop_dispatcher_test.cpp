#include "reflector/event_loop_dispatcher.h"

#include "reflector/timer.h"
#include "reflector/util/delegate.h"
#include "reflector/util/no_copy.h"

#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <cstddef>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>

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

struct WritableCounter {
    void OnWritable(int fd) {
        ++count;
        last_fd = fd;
    }
    int count = 0;
    int last_fd = -1;
};

// Creates a TCP socket bound to an ephemeral 127.0.0.1 port, filling `addr` with the assigned address.
// Returns the fd (or -1 on failure, socket closed). The caller decides what's next: listen() on it,
// connect a client to `addr`, or close it to leave `addr` pointing at an unused port.
inline int BindLoopbackV4(sockaddr_in& addr) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t len = sizeof(addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), len) != 0 ||
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// A connected loopback TCP socket pair: `client` is a non-blocking fd whose readability/writability
// the dispatcher watches; `server` is the peer used to push bytes at it. Needs no privilege —
// 127.0.0.1 loopback TCP is unprivileged — so this stays in the plain (non-RequiresRoot) fixture.
struct LoopbackPair : NoCopy {
    LoopbackPair() noexcept {
        sockaddr_in addr{};
        const int listener = BindLoopbackV4(addr);
        if (listener < 0) {
            return;
        }
        if (::listen(listener, 1) != 0) {
            ::close(listener);
            return;
        }
        const socklen_t len = sizeof(addr);
        const int c = ::socket(AF_INET, SOCK_STREAM, 0);
        if (c >= 0) {
            if (::connect(c, reinterpret_cast<sockaddr*>(&addr), len) == 0) {
                const int s = ::accept(listener, nullptr, nullptr);
                if (s >= 0) {
                    client = c;
                    server = s;
                } else {
                    ::close(c);
                }
            } else {
                ::close(c);
            }
        }
        ::close(listener);
    }
    ~LoopbackPair() noexcept {
        if (client >= 0) {
            ::close(client);
        }
        if (server >= 0) {
            ::close(server);
        }
    }
    bool Valid() const noexcept { return client >= 0 && server >= 0; }
    bool PushByteToClient() const noexcept {
        const std::byte one{1};
        return ::send(server, &one, 1, 0) == 1;
    }
    int client = -1;
    int server = -1;
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
    std::chrono::steady_clock::time_point last_now{};
    void Tick(std::chrono::steady_clock::time_point now) { ++count; last_now = now; }
};

// Fires, then unregisters another timer mid-round (by resetting its handle) — used to prove a
// timer cancelled by an earlier callback in the same FireDueTimers pass does not itself fire.
struct TimerUnregisterer {
    Timer* other = nullptr;
    int count = 0;
    void Tick(std::chrono::steady_clock::time_point) {
        ++count;
        if (other != nullptr) {
            other->Stop();
        }
    }
};

TEST_F(EventLoopDispatcherTest, NextTimeoutReturnsCapWhenNoTimers) {
    const auto now = std::chrono::steady_clock::now();
    EXPECT_EQ(dispatcher.NextTimeout(now), std::chrono::milliseconds{1000});
}

TEST_F(EventLoopDispatcherTest, FireDueTimersInvokesAndReschedulesDueTimer) {
    TimerCounter counter;
    Timer timer{dispatcher};
    timer.Start(std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter));
    ASSERT_TRUE(timer.IsRunning());
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

    timer.Stop();
    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{1000});
    EXPECT_EQ(counter.count, 2);  // stopped: no further fires
}

TEST_F(EventLoopDispatcherTest, FireDueTimersPassesItsNowToTheCallback) {
    TimerCounter counter;
    Timer timer{dispatcher};
    timer.Start(std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter));
    ASSERT_TRUE(timer.IsRunning());

    // The callback receives exactly the `now` FireDueTimers was given (the one fire-cycle clock read),
    // not a value it sampled itself.
    const auto fire_time = std::chrono::steady_clock::now() + std::chrono::milliseconds{50};
    dispatcher.FireDueTimers(fire_time);
    ASSERT_EQ(counter.count, 1);
    EXPECT_EQ(counter.last_now, fire_time);
}

TEST_F(EventLoopDispatcherTest, NextTimeoutClampsToSoonestDeadlineAndFloorsAtZero) {
    TimerCounter counter;
    Timer timer{dispatcher};
    timer.Start(std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&counter));
    ASSERT_TRUE(timer.IsRunning());
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
    Timer timer{dispatcher};
    timer.Start(std::chrono::milliseconds{0}, CreateDelegate<&TimerCounter::Tick>(&counter));
    EXPECT_FALSE(timer.IsRunning());
}

TEST_F(EventLoopDispatcherTest, CallbackCanUnregisterAnotherDueTimerBeforeItFires) {
    TimerUnregisterer first;
    TimerCounter second;
    // Same interval, so both come due together; `first` (registered first, so fired first) cancels
    // `second` before the walk reaches it.
    Timer first_timer{dispatcher};
    first_timer.Start(std::chrono::milliseconds{50}, CreateDelegate<&TimerUnregisterer::Tick>(&first));
    Timer second_timer{dispatcher};
    second_timer.Start(std::chrono::milliseconds{50}, CreateDelegate<&TimerCounter::Tick>(&second));
    first.other = &second_timer;
    const auto t0 = std::chrono::steady_clock::now();

    dispatcher.FireDueTimers(t0 + std::chrono::milliseconds{50});
    EXPECT_EQ(first.count, 1);
    EXPECT_EQ(second.count, 0);  // cancelled mid-round → never fired (a snapshot walk would fire it)
}

TEST_F(EventLoopDispatcherTest, SetWriteInterestRejectsUnwatchedFd) {
    EXPECT_FALSE(dispatcher.SetWriteInterest(999, true));
    EXPECT_FALSE(dispatcher.SetWriteInterest(999, false));
}

TEST_F(EventLoopDispatcherTest, SetWriteInterestArmsAndDisarmsAWatchedFd) {
    LoopbackPair pair;
    ASSERT_TRUE(pair.Valid());
    ReadableCounter reader;
    WritableCounter writer;

    const auto registration = dispatcher.Register(
        pair.client,
        {.read = CreateDelegate<&ReadableCounter::OnReadable>(&reader),
         .write = CreateDelegate<&WritableCounter::OnWritable>(&writer)});
    ASSERT_TRUE(registration.IsValid());

    // Write interest starts disarmed: a freshly-connected, writable socket fires no write callback.
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
    EXPECT_EQ(writer.count, 0);

    // Armed: the writable socket now fires the write callback (idempotent re-arm is harmless).
    EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, true));
    EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, true));
    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(writer.count, 1);
    EXPECT_EQ(writer.last_fd, pair.client);

    // Disarmed: no further write events even though the socket is still writable.
    EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, false));
    EXPECT_FALSE(dispatcher.PollOnce(std::chrono::milliseconds{0}));
    EXPECT_EQ(writer.count, 1);
}

TEST_F(EventLoopDispatcherTest, ExistingReadabilityIsUnaffectedByTheNewRegisterForm) {
    // The 2-arg convenience must keep read interest armed by default (no behavior change).
    ReadablePipe pipe;
    ASSERT_GE(pipe.ReadEnd(), 0);
    ReadableCounter counter;

    const auto registration = dispatcher.Register(
        pipe.ReadEnd(), CreateDelegate<&ReadableCounter::OnReadable>(&counter));
    ASSERT_TRUE(registration.IsValid());

    ASSERT_TRUE(pipe.Notify());
    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(counter.count, 1);
}

TEST_F(EventLoopDispatcherTest, CompletedLoopbackConnectSurfacesAsWritableWithNoSoError) {
    // A non-blocking connect to a listening loopback port completes via a writable event; SO_ERROR
    // reads 0 once connected. This drives the connect-completion path the proxy uses.
    sockaddr_in addr{};
    const int listener = BindLoopbackV4(addr);
    ASSERT_GE(listener, 0);
    ASSERT_EQ(::listen(listener, 1), 0);
    const socklen_t len = sizeof(addr);

    const int client = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(client, 0);
    ASSERT_EQ(::fcntl(client, F_SETFL, O_NONBLOCK), 0);
    const int rc = ::connect(client, reinterpret_cast<sockaddr*>(&addr), len);
    ASSERT_TRUE(rc == 0 || errno == EINPROGRESS);

    ReadableCounter reader;
    WritableCounter writer;
    // Watch writability (connect-completion) with write armed from the start; read is always armed too.
    // A silent server sends nothing, so only the writable event fires. This drives the connect-
    // completion path the proxy's connecting upstream uses.
    auto registration = dispatcher.Register(
        client,
        {.read = CreateDelegate<&ReadableCounter::OnReadable>(&reader),
         .write = CreateDelegate<&WritableCounter::OnWritable>(&writer),
         .write_armed = true});
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_EQ(writer.count, 1);
    EXPECT_EQ(writer.last_fd, client);
    EXPECT_EQ(reader.count, 0);  // a silent server speaks nothing, so read never fires

    int so_error = -1;
    socklen_t err_len = sizeof(so_error);
    ASSERT_EQ(::getsockopt(client, SOL_SOCKET, SO_ERROR, &so_error, &err_len), 0);
    EXPECT_EQ(so_error, 0);

    ASSERT_TRUE(registration.Reset());
    ::close(client);
    ::close(listener);
}

TEST_F(EventLoopDispatcherTest, ArmingWriteInterestWithNoHandlerIsRejected) {
    LoopbackPair pair;
    ASSERT_TRUE(pair.Valid());
    ReadableCounter reader;

    // Read-only registration (the 2-arg convenience leaves the write handler unset).
    const auto registration = dispatcher.Register(
        pair.client, CreateDelegate<&ReadableCounter::OnReadable>(&reader));
    ASSERT_TRUE(registration.IsValid());

    // Arming write with no write handler is refused — it would wake the reactor on a writable socket
    // with nothing to invoke and busy-spin. Disarming (already disarmed) is a harmless no-op.
    EXPECT_FALSE(dispatcher.SetWriteInterest(pair.client, true));
    EXPECT_TRUE(dispatcher.SetWriteInterest(pair.client, false));
}

TEST_F(EventLoopDispatcherTest, FailedConnectSurfacesToAnArmedHandler) {
    // A non-blocking connect to a loopback port with no listener fails. On Linux it arrives as EPOLLERR
    // (often no EPOLLIN/EPOLLOUT); err folds into READABLE, so the always-armed read handler is woken
    // (its recv() would return the error). On macOS it surfaces as EV_EOF on a filter. Either way an
    // armed handler fires — the dispatcher must NOT drop the error-only event. This is the regression.
    sockaddr_in addr{};
    const int probe = BindLoopbackV4(addr);
    ASSERT_GE(probe, 0);
    ::close(probe);  // release the port so the connect below finds nothing listening
    const socklen_t len = sizeof(addr);

    const int client = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(client, 0);
    ASSERT_EQ(::fcntl(client, F_SETFL, O_NONBLOCK), 0);
    const int rc = ::connect(client, reinterpret_cast<sockaddr*>(&addr), len);
    ASSERT_TRUE(rc == 0 || errno == EINPROGRESS || errno == ECONNREFUSED);

    ReadableCounter reader;
    WritableCounter writer;
    auto registration = dispatcher.Register(
        client,
        {.read = CreateDelegate<&ReadableCounter::OnReadable>(&reader),
         .write = CreateDelegate<&WritableCounter::OnWritable>(&writer),
         .write_armed = true});
    ASSERT_TRUE(registration.IsValid());

    EXPECT_TRUE(dispatcher.PollOnce(std::chrono::milliseconds{1000}));
    EXPECT_GE(reader.count + writer.count, 1);  // the failure reached an armed handler, not dropped

    ASSERT_TRUE(registration.Reset());
    ::close(client);
}

} // namespace reflector
