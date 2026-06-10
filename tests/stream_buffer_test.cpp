#include "reflector/util/stream_buffer.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using namespace reflector;

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out(text.size());
    std::memcpy(out.data(), text.data(), text.size());
    return out;
}

// A roomy cap for the FIFO-behaviour tests, where overflow is not the point.
constexpr size_t CAP = 64;

// Move-assigns through two distinct references so a self-assignment call site doesn't trip -Wself-move
// while still exercising operator='s `this != &other` guard.
void MoveAssignInPlace(StreamBuffer& dst, StreamBuffer& src) { dst = std::move(src); }

} // namespace

namespace reflector {

TEST(StreamBufferTest, StartsEmpty) {
    StreamBuffer buf{CAP};
    EXPECT_TRUE(buf.Empty());
    EXPECT_EQ(buf.Size(), 0u);
    EXPECT_EQ(buf.View().size(), 0u);
}

TEST(StreamBufferTest, AppendConsumeAndCompact) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("hello")));
    EXPECT_EQ(buf.Size(), 5u);
    EXPECT_FALSE(buf.Empty());

    buf.Consume(2);  // "llo" remains
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');

    ASSERT_TRUE(buf.Append(Bytes("X")));  // reclaims the consumed prefix, then appends -> "lloX"
    EXPECT_EQ(buf.Size(), 4u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(buf.View()[3]), 'X');
}

TEST(StreamBufferTest, FullConsumeClears) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("abc")));
    buf.Consume(3);
    EXPECT_TRUE(buf.Empty());
    EXPECT_EQ(buf.Size(), 0u);

    ASSERT_TRUE(buf.Append(Bytes("de")));  // reusable after a full drain
    EXPECT_EQ(buf.Size(), 2u);
}

TEST(StreamBufferTest, MultipleAppendsPreserveFifoOrder) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("abc")));
    ASSERT_TRUE(buf.Append(Bytes("def")));  // lands strictly after the first
    EXPECT_EQ(buf.Size(), 6u);
    const auto view = buf.View();
    ASSERT_EQ(view.size(), 6u);
    EXPECT_EQ(std::to_integer<char>(view[0]), 'a');
    EXPECT_EQ(std::to_integer<char>(view[3]), 'd');
    EXPECT_EQ(std::to_integer<char>(view[5]), 'f');
}

TEST(StreamBufferTest, SuccessivePartialConsumesWalkTheHead) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("hello")));
    buf.Consume(2);  // "llo"
    buf.Consume(1);  // "lo" — offsets accumulate without clearing while data remains
    EXPECT_EQ(buf.Size(), 2u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(buf.View()[1]), 'o');
}

TEST(StreamBufferTest, ConsumeBeyondRemainingClearsSafely) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("ab")));
    buf.Consume(5);  // over-report (>= remaining) must clear, not leave a stale offset or read OOB
    EXPECT_TRUE(buf.Empty());
    EXPECT_EQ(buf.Size(), 0u);
    EXPECT_EQ(buf.View().size(), 0u);

    ASSERT_TRUE(buf.Append(Bytes("z")));  // reusable, no residue
    EXPECT_EQ(buf.Size(), 1u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'z');
}

TEST(StreamBufferTest, ConsumeZeroIsANoOp) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("abc")));
    buf.Consume(0);  // no progress: nothing cleared while data remains
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'a');
}

TEST(StreamBufferTest, ZeroLengthAppendIsANoOpButStillReclaims) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append({}));  // empty append on an empty buffer
    EXPECT_TRUE(buf.Empty());

    ASSERT_TRUE(buf.Append(Bytes("abc")));
    buf.Consume(1);            // "bc", head > 0
    ASSERT_TRUE(buf.Append({}));  // empty append still reclaims the consumed prefix, live bytes intact
    EXPECT_EQ(buf.Size(), 2u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'b');
    EXPECT_EQ(std::to_integer<char>(buf.View()[1]), 'c');
}

TEST(StreamBufferTest, InterleavedAppendConsumePreservesBytes) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("ab")));
    buf.Consume(1);                       // "b"
    ASSERT_TRUE(buf.Append(Bytes("cd")));  // reclaim then grow -> "bcd"
    buf.Consume(2);                       // "d"
    ASSERT_TRUE(buf.Append(Bytes("ef")));  // "def"
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'd');
    EXPECT_EQ(std::to_integer<char>(buf.View()[1]), 'e');
    EXPECT_EQ(std::to_integer<char>(buf.View()[2]), 'f');
}

TEST(StreamBufferTest, ReserveTailReadCommitThenView) {
    // The receive path: hand out the writable tail, write into it (as read() would), commit the count.
    StreamBuffer buf{CAP};
    const std::span<std::byte> tail = buf.ReserveTail();
    EXPECT_EQ(tail.size(), CAP);  // whole capacity free on a fresh buffer
    const auto src = Bytes("abcd");
    std::memcpy(tail.data(), src.data(), src.size());
    buf.Commit(src.size());
    EXPECT_EQ(buf.Size(), 4u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'a');
    EXPECT_EQ(std::to_integer<char>(buf.View()[3]), 'd');
}

TEST(StreamBufferTest, ReserveTailCompactsConsumedPrefix) {
    // Compaction before exposing the tail is what keeps the read large: after consuming a prefix, the free
    // tail must reflect the reclaimed room, not the raw gap at the end.
    StreamBuffer buf{8};
    ASSERT_TRUE(buf.Append(Bytes("abcdef")));  // 6/8 used
    buf.Consume(4);                            // "ef" remains, head at 4
    const std::span<std::byte> tail = buf.ReserveTail();
    EXPECT_EQ(buf.Size(), 2u);                 // "ef" slid to the front
    EXPECT_EQ(tail.size(), 6u);                // 8 - 2 free, not 8 - 6
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'e');
}

TEST(StreamBufferTest, ReserveTailEmptyWhenFull) {
    StreamBuffer buf{4};
    ASSERT_TRUE(buf.Append(Bytes("abcd")));  // full
    EXPECT_TRUE(buf.ReserveTail().empty());   // no room to read into -> owner closes
}

TEST(StreamBufferTest, AppendReturnsFalseWhenItWouldExceedCapacity) {
    StreamBuffer buf{4};
    ASSERT_TRUE(buf.Append(Bytes("ab")));
    EXPECT_FALSE(buf.Append(Bytes("xyz")));  // 2 + 3 > 4 -> rejected, nothing written
    EXPECT_EQ(buf.Size(), 2u);               // content unchanged and still forwardable
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'a');
    ASSERT_TRUE(buf.Append(Bytes("cd")));    // 2 + 2 == 4 -> fits exactly
    EXPECT_EQ(buf.Size(), 4u);
}

TEST(StreamBufferTest, MoveConstructionLeavesSourceEmptyAndReusable) {
    StreamBuffer src{CAP};
    ASSERT_TRUE(src.Append(Bytes("hello")));
    src.Consume(2);  // head non-zero at move time — the case the default move mishandles

    StreamBuffer dst = std::move(src);
    EXPECT_EQ(dst.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(dst.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(dst.View()[2]), 'o');

    // The moved-from buffer must be clean, empty, and reusable (its capacity carries over) — the moved-from
    // TcpSocket relies on WantsWrite()==false, i.e. send_buffer_.Empty().
    EXPECT_TRUE(src.Empty());   // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(src.Size(), 0u);  // NOLINT(bugprone-use-after-move)
    ASSERT_TRUE(src.Append(Bytes("xy")));  // must not act on a stale offset / freed storage
    EXPECT_EQ(src.Size(), 2u);
    EXPECT_EQ(std::to_integer<char>(src.View()[0]), 'x');
}

TEST(StreamBufferTest, MoveAssignmentLeavesSourceEmptyAndReusable) {
    StreamBuffer src{CAP};
    ASSERT_TRUE(src.Append(Bytes("world")));
    src.Consume(1);  // "orld", head > 0

    StreamBuffer dst{CAP};
    ASSERT_TRUE(dst.Append(Bytes("zz")));  // dst has prior content that the assignment must replace
    dst = std::move(src);
    EXPECT_EQ(dst.Size(), 4u);
    EXPECT_EQ(std::to_integer<char>(dst.View()[0]), 'o');

    EXPECT_TRUE(src.Empty());  // NOLINT(bugprone-use-after-move)
    ASSERT_TRUE(src.Append(Bytes("q")));
    EXPECT_EQ(src.Size(), 1u);
}

TEST(StreamBufferTest, SelfMoveAssignmentIsANoOp) {
    StreamBuffer buf{CAP};
    ASSERT_TRUE(buf.Append(Bytes("hello")));
    buf.Consume(2);  // "llo", head > 0 — without the self-guard, data_ self-move would corrupt Size()

    MoveAssignInPlace(buf, buf);
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(buf.View()[2]), 'o');
}

} // namespace reflector
