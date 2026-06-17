#pragma once
// AuditForwarder - Common type definitions and result/error handling.

#include "build_config.h"
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>
#include <chrono>
#include <memory>

namespace af {

// ---- Basic types ----
using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8  = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;
using usize = std::size_t;

using ByteBuffer = std::vector<u8>;
using StringList = std::vector<std::string>;

// ---- Time ----
using Clock     = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using SysClock  = std::chrono::system_clock;
using SysTime   = SysClock::time_point;

// ---- Result type (Rust-inspired) ----
class Error {
public:
    enum class Code : int {
        Ok              = 0,
        Unknown         = -1,
        InvalidArgument = -2,
        NotFound        = -3,
        PermissionDenied= -4,
        Timeout         = -5,
        AlreadyExists   = -6,
        IoError         = -7,
        Network         = -8,
        Crypto          = -9,
        Parse           = -10,
        Overflow        = -11,
        NotSupported    = -12,
        Integrity       = -13,
        Cancelled       = -14,
    };

    Error() = default;
    explicit Error(Code c, std::string m = {}) : code_(c), message_(std::move(m)) {}

    Code code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }
    bool ok() const noexcept { return code_ == Code::Ok; }
    explicit operator bool() const noexcept { return !ok(); }

    static Error success() { return Error(Code::Ok); }
    static Error make(Code c, std::string m = {}) { return Error(c, std::move(m)); }

private:
    Code        code_   { Code::Ok };
    std::string message_;
};

template <typename T>
class Result {
public:
    Result(T value) : data_(std::move(value)) {}
    Result(Error err) : data_(std::move(err)) {}
    Result(Error::Code c, std::string m) : data_(Error(c, std::move(m))) {}

    bool is_ok() const { return std::holds_alternative<T>(data_); }
    bool is_err() const { return !is_ok(); }
    explicit operator bool() const { return is_ok(); }

    const T& value() const&  { return std::get<T>(data_); }
    T&       value() &       { return std::get<T>(data_); }
    T        value() &&      { return std::move(std::get<T>(data_)); }

    const Error& error() const& { return std::get<Error>(data_); }
    Error        error() &&     { return std::move(std::get<Error>(data_)); }

    T value_or(T default_value) const& {
        return is_ok() ? std::get<T>(data_) : std::move(default_value);
    }

private:
    std::variant<T, Error> data_;
};

template <>
class Result<void> {
public:
    Result() = default;
    Result(Error err) : err_(std::move(err)) {}
    Result(Error::Code c, std::string m) : err_(Error(c, std::move(m))) {}

    bool is_ok() const { return err_.ok(); }
    bool is_err() const { return !is_ok(); }
    explicit operator bool() const { return is_ok(); }
    const Error& error() const { return err_; }

    static Result<void> ok() { return Result<void>(); }
    static Result<void> make_error(Error::Code c, std::string m = {}) {
        return Result<void>(Error(c, std::move(m)));
    }

private:
    Error err_;
};

// ---- Severity / classification ----
enum class Severity : u8 {
    Debug    = 0,
    Info     = 1,
    Notice   = 2,
    Warning  = 3,
    Error    = 4,
    Critical = 5,
    Alert    = 6,
    Emergency= 7,
};

const char* to_string(Severity s) noexcept;
Severity    severity_from_string(const std::string& s) noexcept;

}  // namespace af
