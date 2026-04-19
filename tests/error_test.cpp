#include "reflector/error.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <format>
#include <system_error>

using namespace reflector;

TEST(ErrorTest, ConstructsFromStringLvalue) {
    std::string test_error = "test error";
    Error error{test_error};

    EXPECT_EQ(test_error, "test error");
    EXPECT_EQ(error.Message(), "test error");
}

TEST(ErrorTest, ConstructsFromStringRvalue) {
    Error error{std::string{"test error"}};

    EXPECT_EQ(error.Message(), "test error");
}

TEST(ErrorTest, ConstructsFromStringViewLvalue) {
    std::string_view test_error{"test error"};
    Error error{test_error};

    EXPECT_EQ(test_error, "test error");
    EXPECT_EQ(error.Message(), "test error");
}

TEST(ErrorTest, ConstructsFromStringViewTemporary) {
    Error error{std::string_view{"test error"}};

    EXPECT_EQ(error.Message(), "test error");
}

TEST(ErrorTest, ConstructsFromCStringLiteral) {
    Error error{"test error"};

    EXPECT_EQ(error.Message(), "test error");
}

TEST(ErrorTest, FormatsMessage) {
    Error error{"test error {}", 123};

    EXPECT_EQ(error.Message(), "test error 123");
}

TEST(ErrorTest, CapturesErrnoMessage) {
    errno = ENOENT;
    auto error = Error::FromErrno();

    EXPECT_EQ(error.Message(), std::format("({}) {}", ENOENT, std::system_category().message(ENOENT)));
}
