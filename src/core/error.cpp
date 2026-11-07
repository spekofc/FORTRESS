// FORTRESS Error Handling Implementation

#include <fortress/core/error.h>
#include <sstream>
#include <iomanip>

namespace fortress {

// ErrorCategory implementation
std::string ErrorCategory::message(int code) const {
    switch (static_cast<ErrorCode>(code)) {
        case ErrorCode::Success:                    return "Success";
        case ErrorCode::UnknownError:               return "Unknown error";
        case ErrorCode::InvalidArgument:            return "Invalid argument";
        case ErrorCode::OutOfMemory:                return "Out of memory";
        case ErrorCode::BufferTooSmall:             return "Buffer too small";
        case ErrorCode::NotImplemented:             return "Not implemented";
        case ErrorCode::UnsupportedOperation:       return "Unsupported operation";
        case ErrorCode::PermissionDenied:           return "Permission denied";
        case ErrorCode::ResourceExhausted:          return "Resource exhausted";
        case ErrorCode::Timeout:                    return "Timeout";
        case ErrorCode::Cancelled:                  return "Cancelled";

        case ErrorCode::FileNotFound:               return "File not found";
        case ErrorCode::FileReadError:              return "File read error";
        case ErrorCode::FileWriteError:             return "File write error";
        case ErrorCode::FileSeekError:              return "File seek error";
        case ErrorCode::FileTooLarge:               return "File too large";
        case ErrorCode::FileTooSmall:               return "File too small";
        case ErrorCode::FileMappingFailed:          return "File mapping failed";
        case ErrorCode::InvalidPath:                return "Invalid path";

        case ErrorCode::InvalidBinaryFormat:        return "Invalid binary format";
        case ErrorCode::InvalidHeader:              return "Invalid header";
        case ErrorCode::InvalidSection:             return "Invalid section";
        case ErrorCode::InvalidSymbol:              return "Invalid symbol";
        case ErrorCode::InvalidRelocation:          return "Invalid relocation";
        case ErrorCode::InvalidImport:              return "Invalid import";
        case ErrorCode::InvalidExport:              return "Invalid export";
        case ErrorCode::InvalidDebugInfo:           return "Invalid debug info";
        case ErrorCode::TruncatedBinary:            return "Truncated binary";
        case ErrorCode::OverlappingSections:        return "Overlapping sections";
        case ErrorCode::CorruptedData:              return "Corrupted data";
        case ErrorCode::UnsupportedArchitecture:    return "Unsupported architecture";
        case ErrorCode::UnsupportedFormat:          return "Unsupported format";
        case ErrorCode::MultipleArchitectures:      return "Multiple architectures";
        case ErrorCode::InvalidChecksum:            return "Invalid checksum";
        case ErrorCode::MissingRequiredSection:     return "Missing required section";
        case ErrorCode::InvalidStringTable:         return "Invalid string table";
        case ErrorCode::InvalidSymbolTable:         return "Invalid symbol table";

        case ErrorCode::AnalysisFailed:             return "Analysis failed";
        case ErrorCode::DisassemblyFailed:          return "Disassembly failed";
        case ErrorCode::FunctionDiscoveryFailed:    return "Function discovery failed";
        case ErrorCode::CFGConstructionFailed:      return "CFG construction failed";
        case ErrorCode::SymbolResolutionFailed:     return "Symbol resolution failed";
        case ErrorCode::TypeRecoveryFailed:         return "Type recovery failed";

        case ErrorCode::HashComputationFailed:      return "Hash computation failed";
        case ErrorCode::UnsupportedHashAlgorithm:   return "Unsupported hash algorithm";
        case ErrorCode::VerificationFailed:         return "Verification failed";
        case ErrorCode::SignatureVerificationFailed: return "Signature verification failed";

        default:                                    return "Unknown error code";
    }
}

std::error_condition ErrorCategory::default_error_condition(int code) const noexcept {
    switch (static_cast<ErrorCode>(code)) {
        case ErrorCode::FileNotFound:   return std::errc::no_such_file_or_directory;
        case ErrorCode::PermissionDenied: return std::errc::permission_denied;
        case ErrorCode::OutOfMemory:    return std::errc::not_enough_memory;
        case ErrorCode::InvalidArgument: return std::errc::invalid_argument;
        case ErrorCode::Timeout:        return std::errc::timed_out;
        default:                        return std::error_condition(code, *this);
    }
}

const ErrorCategory& error_category() {
    static ErrorCategory instance;
    return instance;
}

// Error implementation
std::error_code Error::to_error_code() const noexcept {
    return std::error_code(static_cast<int>(code_), error_category());
}

std::string Error::to_string() const {
    std::ostringstream oss;
    oss << "[" << static_cast<int>(code_) << "] " << error_category().message(static_cast<int>(code_));
    if (!message_.empty()) {
        oss << ": " << message_;
    }
    if (!context_.empty()) {
        oss << " (" << context_ << ")";
    }
    return oss.str();
}

} // namespace fortress