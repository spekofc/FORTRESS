// FORTRESS Error Handling
// Error codes, exceptions, and result types

#pragma once

#include <fortress/core/types.h>
#include <string>
#include <system_error>
#include <optional>
#include <variant>
#include <vector>

namespace fortress {

// Forward declaration
class Error;

// Error code enumeration
enum class ErrorCode : int {
    Success = 0,

    // Generic errors (1-99)
    UnknownError           = 1,
    InvalidArgument        = 2,
    OutOfMemory            = 3,
    BufferTooSmall         = 4,
    NotImplemented         = 5,
    UnsupportedOperation   = 6,
    PermissionDenied       = 7,
    ResourceExhausted      = 8,
    Timeout                = 9,
    Cancelled              = 10,

    // File/IO errors (100-199)
    FileNotFound           = 100,
    FileReadError          = 101,
    FileWriteError         = 102,
    FileSeekError          = 103,
    FileTooLarge           = 104,
    FileTooSmall           = 105,
    FileMappingFailed      = 106,
    InvalidPath            = 107,

    // Binary parsing errors (200-299)
    InvalidBinaryFormat    = 200,
    InvalidHeader          = 201,
    InvalidSection         = 202,
    InvalidSymbol          = 203,
    InvalidRelocation      = 204,
    InvalidImport          = 205,
    InvalidExport          = 206,
    InvalidDebugInfo       = 207,
    TruncatedBinary        = 208,
    OverlappingSections    = 209,
    CorruptedData          = 210,
    UnsupportedArchitecture = 211,
    UnsupportedFormat      = 212,
    MultipleArchitectures  = 213,
    InvalidChecksum        = 214,
    MissingRequiredSection = 215,
    InvalidStringTable     = 216,
    InvalidSymbolTable     = 217,

    // Analysis errors (300-399)
    AnalysisFailed         = 300,
    DisassemblyFailed      = 301,
    FunctionDiscoveryFailed = 302,
    CFGConstructionFailed  = 303,
    SymbolResolutionFailed = 304,
    TypeRecoveryFailed     = 305,

    // Crypto/hash errors (400-499)
    HashComputationFailed  = 400,
    UnsupportedHashAlgorithm = 401,
    VerificationFailed     = 402,
    SignatureVerificationFailed = 403,
};

// Error category for std::error_code integration
class ErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override { return "fortress"; }
    std::string message(int code) const override;
    std::error_condition default_error_condition(int code) const noexcept override;
};

const ErrorCategory& error_category();

// Error class with rich context
class Error {
public:
    Error() noexcept : code_(ErrorCode::Success) {}
    explicit Error(ErrorCode code, std::string message = "") noexcept
        : code_(code), message_(std::move(message)) {}
    Error(ErrorCode code, std::string message, std::string context) noexcept
        : code_(code), message_(std::move(message)), context_(std::move(context)) {}

    // Factory methods
    static Error success() { return Error(ErrorCode::Success); }
    static Error unknown(std::string msg = "") { return Error(ErrorCode::UnknownError, std::move(msg)); }
    static Error invalid_argument(std::string msg) { return Error(ErrorCode::InvalidArgument, std::move(msg)); }
    static Error not_implemented(std::string msg = "") { return Error(ErrorCode::NotImplemented, std::move(msg)); }
    static Error unsupported(std::string msg = "") { return Error(ErrorCode::UnsupportedOperation, std::move(msg)); }
    static Error out_of_memory() { return Error(ErrorCode::OutOfMemory, "Out of memory"); }
    static Error file_not_found(std::string path) { return Error(ErrorCode::FileNotFound, "File not found: " + path); }
    static Error file_read_error(std::string msg) { return Error(ErrorCode::FileReadError, std::move(msg)); }
    static Error file_write_error(std::string msg) { return Error(ErrorCode::FileWriteError, std::move(msg)); }
    static Error file_seek_error(std::string msg) { return Error(ErrorCode::FileSeekError, std::move(msg)); }
    static Error file_mapping_error(std::string msg) { return Error(ErrorCode::FileMappingFailed, std::move(msg)); }
    static Error file_too_large(std::string msg) { return Error(ErrorCode::FileTooLarge, std::move(msg)); }
    static Error invalid_format(std::string msg) { return Error(ErrorCode::InvalidBinaryFormat, std::move(msg)); }
    static Error invalid_header(std::string msg) { return Error(ErrorCode::InvalidHeader, std::move(msg)); }
    static Error truncated(std::string msg) { return Error(ErrorCode::TruncatedBinary, std::move(msg)); }
    static Error overlapping_sections(std::string msg) { return Error(ErrorCode::OverlappingSections, std::move(msg)); }
    static Error unsupported_arch(std::string msg) { return Error(ErrorCode::UnsupportedArchitecture, std::move(msg)); }
    static Error unsupported_format(std::string msg) { return Error(ErrorCode::UnsupportedFormat, std::move(msg)); }
    static Error unsupported_operation(std::string msg) { return Error(ErrorCode::UnsupportedOperation, std::move(msg)); }
    static Error analysis_failed(std::string msg) { return Error(ErrorCode::AnalysisFailed, std::move(msg)); }
    static Error disassembly_failed(std::string msg) { return Error(ErrorCode::DisassemblyFailed, std::move(msg)); }

    // Accessors
    ErrorCode code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }
    const std::string& context() const noexcept { return context_; }
    bool has_context() const noexcept { return !context_.empty(); }

    // Boolean conversion
    explicit operator bool() const noexcept { return code_ != ErrorCode::Success; }
    bool operator!() const noexcept { return code_ == ErrorCode::Success; }

    // Comparison
    bool operator==(ErrorCode other) const noexcept { return code_ == other; }
    bool operator!=(ErrorCode other) const noexcept { return code_ != other; }

    // Convert to std::error_code
    std::error_code to_error_code() const noexcept;

    // Add context
    Error with_context(std::string ctx) const {
        Error result = *this;
        if (!result.context_.empty()) result.context_ += " -> ";
        result.context_ += ctx;
        return result;
    }

    // Format for output
    std::string to_string() const;

private:
    ErrorCode code_;
    std::string message_;
    std::string context_;
};

// Result type - either a value or an error
template<typename T>
class Result {
public:
    // Success constructors
    Result() = delete; // Require explicit success/error
    Result(T&& value) noexcept : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(const T& value) noexcept : storage_(std::in_place_index<0>, value) {}
    Result(Error&& error) noexcept : storage_(std::in_place_index<1>, std::move(error)) {}
    Result(const Error& error) noexcept : storage_(std::in_place_index<1>, error) {}

    // Move/copy
    Result(Result&&) = default;
    Result(const Result&) = default;
    Result& operator=(Result&&) = default;
    Result& operator=(const Result&) = default;

    // Factory methods
    static Result<T> ok(T&& value) { return Result<T>(std::move(value)); }
    static Result<T> ok(const T& value) { return Result<T>(value); }
    static Result<T> err(Error&& error) { return Result<T>(std::move(error)); }
    static Result<T> err(const Error& error) { return Result<T>(error); }
    static Result<T> err(ErrorCode code, std::string msg = "") { return Result<T>(Error(code, std::move(msg))); }

    // State queries
    bool is_ok() const noexcept { return storage_.index() == 0; }
    bool is_err() const noexcept { return storage_.index() == 1; }
    explicit operator bool() const noexcept { return is_ok(); }

    // Value access (undefined behavior if error)
    T& value() & { return std::get<0>(storage_); }
    const T& value() const& { return std::get<0>(storage_); }
    T&& value() && { return std::get<0>(std::move(storage_)); }

    // Error access (undefined behavior if success)
    Error& error() & { return std::get<1>(storage_); }
    const Error& error() const& { return std::get<1>(storage_); }
    Error&& error() && { return std::get<1>(std::move(storage_)); }

    // Safe access with default
    T value_or(T&& default_value) & { return is_ok() ? value() : std::move(default_value); }
    const T& value_or(const T& default_value) const& { return is_ok() ? value() : default_value; }

    // Transform
    template<typename F>
    auto map(F&& f) & -> Result<decltype(f(std::declval<T&>()))> {
        using U = decltype(f(std::declval<T&>()));
        if (is_ok()) return Result<U>::ok(f(value()));
        return Result<U>::err(error());
    }

    template<typename F>
    auto map(F&& f) && -> Result<decltype(f(std::declval<T&&>()))> {
        using U = decltype(f(std::declval<T&&>()));
        if (is_ok()) return Result<U>::ok(f(std::move(value())));
        return Result<U>::err(std::move(error()));
    }

    // Monadic bind
    template<typename F>
    auto and_then(F&& f) & -> decltype(f(std::declval<T&>())) {
        using U = decltype(f(std::declval<T&>()));
        if (is_ok()) return f(value());
        return U::err(error());
    }

    template<typename F>
    auto and_then(F&& f) && -> decltype(f(std::declval<T&&>())) {
        using U = decltype(f(std::declval<T&&>()));
        if (is_ok()) return f(std::move(value()));
        return U::err(std::move(error()));
    }

private:
    std::variant<T, Error> storage_;
};

// Specialization for void
template<>
class Result<void> {
public:
    Result() noexcept : storage_(std::in_place_index<0>) {}
    Result(Error&& error) noexcept : storage_(std::in_place_index<1>, std::move(error)) {}
    Result(const Error& error) noexcept : storage_(std::in_place_index<1>, error) {}

    Result(Result&&) = default;
    Result(const Result&) = default;
    Result& operator=(Result&&) = default;
    Result& operator=(const Result&) = default;

    static Result<void> ok() { return Result<void>(); }
    static Result<void> err(Error&& error) { return Result<void>(std::move(error)); }
    static Result<void> err(const Error& error) { return Result<void>(error); }
    static Result<void> err(ErrorCode code, std::string msg = "") { return Result<void>(Error(code, std::move(msg))); }

    bool is_ok() const noexcept { return storage_.index() == 0; }
    bool is_err() const noexcept { return storage_.index() == 1; }
    explicit operator bool() const noexcept { return is_ok(); }

    void value() const { if (is_err()) throw std::bad_variant_access(); }
    Error& error() & { return std::get<1>(storage_); }
    const Error& error() const& { return std::get<1>(storage_); }
    Error&& error() && { return std::get<1>(std::move(storage_)); }

    template<typename F>
    auto and_then(F&& f) & -> decltype(f()) {
        using U = decltype(f());
        if (is_ok()) return f();
        return U::err(error());
    }

    template<typename F>
    auto and_then(F&& f) && -> decltype(f()) {
        using U = decltype(f());
        if (is_ok()) return f();
        return U::err(std::move(error()));
    }

private:
    std::variant<std::monostate, Error> storage_;
};

// Helper macro for error propagation
#define FORTRESS_TRY(expr) \
    ({ auto&& _result = (expr); \
       if (!_result) return Result<decltype(_result.value())>::err(std::move(_result.error())); \
       std::move(_result.value()); })

#define FORTRESS_TRY_VOID(expr) \
    ({ auto&& _result = (expr); \
       if (!_result) return Result<void>::err(std::move(_result.error())); })

// Exception class for cases where exceptions are preferred
class FortressException : public std::runtime_error {
public:
    explicit FortressException(const Error& error)
        : std::runtime_error(error.to_string()), error_(error) {}
    explicit FortressException(Error&& error)
        : std::runtime_error(error.to_string()), error_(std::move(error)) {}

    const Error& error() const noexcept { return error_; }

private:
    Error error_;
};

// Throw if error
inline void throw_if_error(const Error& error) {
    if (error) throw FortressException(error);
}

template<typename T>
inline T unwrap(Result<T>&& result) {
    if (!result) throw FortressException(std::move(result.error()));
    return std::move(result.value());
}

inline void unwrap(Result<void>&& result) {
    if (!result) throw FortressException(std::move(result.error()));
}

} // namespace fortress

// std::hash specialization for ErrorCode
namespace std {
    template<>
    struct hash<fortress::ErrorCode> {
        size_t operator()(fortress::ErrorCode code) const noexcept {
            return static_cast<size_t>(static_cast<int>(code));
        }
    };
}