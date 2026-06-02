#include "reflector/util/send_buffer.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>

namespace reflector {
namespace {

std::vector<std::byte> Bytes(std::string_view text) {
    std::vector<std::byte> out(text.size());
    std::memcpy(out.data(), text.data(), text.size());
    return out;
}

// Move-assigns through two distinct references so a self-assignment call site doesn't trip -Wself-move
// while still exercising operator='s `this != &other` guard.
void MoveAssignInPlace(SendBuffer& dst, SendBuffer& src) { dst = std::move(src); }

TEST(SendBufferTest, StartsEmpty) {
    SendBuffer buf;
    EXPECT_TRUE(buf.Empty());
    EXPECT_EQ(buf.Size(), 0u);
    EXPECT_EQ(buf.View().size(), 0u);
}

TEST(SendBufferTest, AppendConsumeAndCompact) {
    SendBuffer buf;
    buf.Append(Bytes("hello"));
    EXPECT_EQ(buf.Size(), 5u);
    EXPECT_FALSE(buf.Empty());

    buf.Consume(2);  // "llo" remains
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');

    buf.Append(Bytes("X"));  // reclaims the consumed prefix, then appends -> "lloX"
    EXPECT_EQ(buf.Size(), 4u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(buf.View()[3]), 'X');
}

TEST(SendBufferTest, FullConsumeClears) {
    SendBuffer buf;
    buf.Append(Bytes("abc"));
    buf.Consume(3);
    EXPECT_TRUE(buf.Empty());
    EXPECT_EQ(buf.Size(), 0u);

    buf.Append(Bytes("de"));  // reusable after a full drain
    EXPECT_EQ(buf.Size(), 2u);
}

TEST(SendBufferTest, MultipleAppendsPreserveFifoOrder) {
    SendBuffer buf;
    buf.Append(Bytes("abc"));
    buf.Append(Bytes("def"));  // lands strictly after the first
    EXPECT_EQ(buf.Size(), 6u);
    const auto view = buf.View();
    ASSERT_EQ(view.size(), 6u);
    EXPECT_EQ(std::to_integer<char>(view[0]), 'a');
    EXPECT_EQ(std::to_integer<char>(view[3]), 'd');
    EXPECT_EQ(std::to_integer<char>(view[5]), 'f');
}

TEST(SendBufferTest, SuccessivePartialConsumesWalkTheHead) {
    SendBuffer buf;
    buf.Append(Bytes("hello"));
    buf.Consume(2);  // "llo"
    buf.Consume(1);  // "lo" — offsets accumulate without clearing while data remains
    EXPECT_EQ(buf.Size(), 2u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(buf.View()[1]), 'o');
}

TEST(SendBufferTest, ConsumeBeyondRemainingClearsSafely) {
    SendBuffer buf;
    buf.Append(Bytes("ab"));
    buf.Consume(5);  // over-report (>= remaining) must clear, not leave a stale offset or read OOB
    EXPECT_TRUE(buf.Empty());
    EXPECT_EQ(buf.Size(), 0u);
    EXPECT_EQ(buf.View().size(), 0u);

    buf.Append(Bytes("z"));  // reusable, no residue
    EXPECT_EQ(buf.Size(), 1u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'z');
}

TEST(SendBufferTest, ConsumeZeroIsANoOp) {
    SendBuffer buf;
    buf.Append(Bytes("abc"));
    buf.Consume(0);  // no progress: nothing cleared while data remains
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'a');
}

TEST(SendBufferTest, ZeroLengthAppendIsANoOpButStillReclaims) {
    SendBuffer buf;
    buf.Append({});  // empty append on an empty buffer
    EXPECT_TRUE(buf.Empty());

    buf.Append(Bytes("abc"));
    buf.Consume(1);   // "bc", consumed_ > 0
    buf.Append({});   // empty append still reclaims the consumed prefix, leaving the live bytes intact
    EXPECT_EQ(buf.Size(), 2u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'b');
    EXPECT_EQ(std::to_integer<char>(buf.View()[1]), 'c');
}

TEST(SendBufferTest, InterleavedAppendConsumePreservesBytes) {
    SendBuffer buf;
    buf.Append(Bytes("ab"));
    buf.Consume(1);            // "b"
    buf.Append(Bytes("cd"));   // reclaim then grow -> "bcd"
    buf.Consume(2);            // "d"
    buf.Append(Bytes("ef"));   // "def"
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'd');
    EXPECT_EQ(std::to_integer<char>(buf.View()[1]), 'e');
    EXPECT_EQ(std::to_integer<char>(buf.View()[2]), 'f');
}

TEST(SendBufferTest, MoveConstructionLeavesSourceEmptyAndReusable) {
    SendBuffer src;
    src.Append(Bytes("hello"));
    src.Consume(2);  // consumed_ is non-zero at move time — the case the default move mishandles

    SendBuffer dst = std::move(src);
    EXPECT_EQ(dst.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(dst.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(dst.View()[2]), 'o');

    // The moved-from buffer must be a clean, empty, reusable buffer — the moved-from TcpSocket relies on
    // WantsWrite()==false, i.e. send_buffer_.Empty().
    EXPECT_TRUE(src.Empty());   // NOLINT(bugprone-use-after-move)
    EXPECT_EQ(src.Size(), 0u);  // NOLINT(bugprone-use-after-move)
    src.Append(Bytes("xy"));    // must not act on a stale offset / freed storage
    EXPECT_EQ(src.Size(), 2u);
    EXPECT_EQ(std::to_integer<char>(src.View()[0]), 'x');
}

TEST(SendBufferTest, MoveAssignmentLeavesSourceEmptyAndReusable) {
    SendBuffer src;
    src.Append(Bytes("world"));
    src.Consume(1);  // "orld", consumed_ > 0

    SendBuffer dst;
    dst.Append(Bytes("zz"));  // dst has prior content that the assignment must replace
    dst = std::move(src);
    EXPECT_EQ(dst.Size(), 4u);
    EXPECT_EQ(std::to_integer<char>(dst.View()[0]), 'o');

    EXPECT_TRUE(src.Empty());  // NOLINT(bugprone-use-after-move)
    src.Append(Bytes("q"));
    EXPECT_EQ(src.Size(), 1u);
}

TEST(SendBufferTest, SelfMoveAssignmentIsANoOp) {
    SendBuffer buf;
    buf.Append(Bytes("hello"));
    buf.Consume(2);  // "llo", consumed_ > 0 — without the self-guard, data_ self-move would corrupt Size()

    MoveAssignInPlace(buf, buf);
    EXPECT_EQ(buf.Size(), 3u);
    EXPECT_EQ(std::to_integer<char>(buf.View()[0]), 'l');
    EXPECT_EQ(std::to_integer<char>(buf.View()[2]), 'o');
}

} // namespace
} // namespace reflector
