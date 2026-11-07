// FORTRESS Core Types
// Common type definitions and architecture enums

#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace fortress {

// Architecture enumeration
enum class Architecture : uint8_t {
    Unknown = 0,
    X86     = 1,   // 32-bit x86
    X64     = 2,   // 64-bit x86-64
    ARM64   = 3,   // 64-bit ARM (AArch64)
    ARM32   = 4,   // 32-bit ARM
    MIPS32  = 5,
    MIPS64  = 6,
    PPC32   = 7,
    PPC64   = 8,
    RISCV32 = 9,
    RISCV64 = 10,
    WASM32  = 11,
    WASM64  = 12,
};

inline std::string to_string(Architecture arch) {
    switch (arch) {
        case Architecture::X86:     return "x86";
        case Architecture::X64:     return "x64";
        case Architecture::ARM64:   return "arm64";
        case Architecture::ARM32:   return "arm32";
        case Architecture::MIPS32:  return "mips32";
        case Architecture::MIPS64:  return "mips64";
        case Architecture::PPC32:   return "ppc32";
        case Architecture::PPC64:   return "ppc64";
        case Architecture::RISCV32: return "riscv32";
        case Architecture::RISCV64: return "riscv64";
        case Architecture::WASM32:  return "wasm32";
        case Architecture::WASM64:  return "wasm64";
        default:                    return "unknown";
    }
}

inline Architecture architecture_from_string(const std::string& str) {
    if (str == "x86" || str == "i386" || str == "i686") return Architecture::X86;
    if (str == "x64" || str == "x86_64" || str == "amd64") return Architecture::X64;
    if (str == "arm64" || str == "aarch64") return Architecture::ARM64;
    if (str == "arm32" || str == "arm" || str == "armv7") return Architecture::ARM32;
    if (str == "mips32") return Architecture::MIPS32;
    if (str == "mips64") return Architecture::MIPS64;
    if (str == "ppc32" || str == "powerpc") return Architecture::PPC32;
    if (str == "ppc64" || str == "powerpc64") return Architecture::PPC64;
    if (str == "riscv32") return Architecture::RISCV32;
    if (str == "riscv64") return Architecture::RISCV64;
    if (str == "wasm32") return Architecture::WASM32;
    if (str == "wasm64") return Architecture::WASM64;
    return Architecture::Unknown;
}

// Executable format
enum class BinaryFormat : uint8_t {
    Unknown = 0,
    PE      = 1,      // Windows PE/PE+
    ELF     = 2,      // Linux/Unix ELF
    MachO   = 3,      // macOS Mach-O
    COFF    = 4,      // COFF object
    WASM    = 5,      // WebAssembly
};

inline std::string to_string(BinaryFormat fmt) {
    switch (fmt) {
        case BinaryFormat::PE:    return "PE";
        case BinaryFormat::ELF:   return "ELF";
        case BinaryFormat::MachO: return "Mach-O";
        case BinaryFormat::COFF:  return "COFF";
        case BinaryFormat::WASM:  return "WASM";
        default:                  return "unknown";
    }
}

// Endianness
enum class Endianness : uint8_t {
    Unknown = 0,
    Little  = 1,
    Big     = 2,
};

// Section permissions (bitmask)
enum class SectionPermission : uint32_t {
    None        = 0,
    Read        = 1 << 0,
    Write       = 1 << 1,
    Execute     = 1 << 2,
    ReadWrite   = Read | Write,
    ReadExecute = Read | Execute,
    All         = Read | Write | Execute,
};

inline SectionPermission operator|(SectionPermission a, SectionPermission b) {
    return static_cast<SectionPermission>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline SectionPermission operator&(SectionPermission a, SectionPermission b) {
    return static_cast<SectionPermission>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool has_permission(SectionPermission perms, SectionPermission flag) {
    return (perms & flag) == flag;
}

// Symbol types
enum class SymbolType : uint8_t {
    Unknown   = 0,
    Function  = 1,
    Data      = 2,
    Section   = 3,
    File      = 4,
    TLS       = 5,
    IFunc     = 6,
};

// Symbol binding
enum class SymbolBinding : uint8_t {
    Local   = 0,
    Global  = 1,
    Weak    = 2,
    Unique  = 3,
};

// Symbol visibility
enum class SymbolVisibility : uint8_t {
    Default   = 0,
    Internal  = 1,
    Hidden    = 2,
    Protected = 3,
};

// Relocation types (generic, format-specific ones in format headers)
enum class RelocationKind : uint32_t {
    Unknown = 0,
    // Generic
    Absolute,
    Relative,
    PCRelative,
    GOTRelative,
    PLTRelative,
    TLSCall,
    TLSDesc,
    // Format-specific values start at 0x1000
};

// Function discovery confidence levels
enum class ConfidenceLevel : uint8_t {
    Unknown     = 0,
    VeryLow     = 10,
    Low         = 25,
    Medium      = 50,
    High        = 75,
    VeryHigh    = 90,
    Confirmed   = 100,
};

inline std::string to_string(ConfidenceLevel level) {
    switch (level) {
        case ConfidenceLevel::Confirmed:   return "confirmed";
        case ConfidenceLevel::VeryHigh:    return "very_high";
        case ConfidenceLevel::High:        return "high";
        case ConfidenceLevel::Medium:      return "medium";
        case ConfidenceLevel::Low:         return "low";
        case ConfidenceLevel::VeryLow:     return "very_low";
        default:                           return "unknown";
    }
}

// Function discovery source
enum class FunctionSource : uint8_t {
    Unknown         = 0,
    ExportTable     = 1,
    SymbolTable     = 2,
    DebugSymbols    = 3,
    UnwindInfo      = 4,
    ExceptionTable  = 5,
    EntryPoint      = 6,
    Disassembly     = 7,
    Heuristic       = 8,
    PatternMatch    = 9,
    ImportThunk     = 10,
};

inline std::string to_string(FunctionSource source) {
    switch (source) {
        case FunctionSource::ExportTable:    return "export_table";
        case FunctionSource::SymbolTable:    return "symbol_table";
        case FunctionSource::DebugSymbols:   return "debug_symbols";
        case FunctionSource::UnwindInfo:     return "unwind_info";
        case FunctionSource::ExceptionTable: return "exception_table";
        case FunctionSource::EntryPoint:     return "entry_point";
        case FunctionSource::Disassembly:    return "disassembly";
        case FunctionSource::Heuristic:      return "heuristic";
        case FunctionSource::PatternMatch:   return "pattern_match";
        case FunctionSource::ImportThunk:    return "import_thunk";
        default:                             return "unknown";
    }
}

// Address type
using Address = uint64_t;
using Offset  = uint64_t;
using Size    = uint64_t;

// Invalid address constant
constexpr Address INVALID_ADDRESS = static_cast<Address>(-1);
constexpr Offset  INVALID_OFFSET  = static_cast<Offset>(-1);
constexpr Size    INVALID_SIZE    = static_cast<Size>(-1);

// Hash algorithms
enum class HashAlgorithm : uint8_t {
    None     = 0,
    MD5      = 1,
    SHA1     = 2,
    SHA256   = 3,
    SHA384   = 4,
    SHA512   = 5,
    SHA3_256 = 6,
    SHA3_512 = 7,
    BLAKE2b  = 8,
    BLAKE3   = 9,
};

// Error categories for binary analysis
enum class BinaryErrorCategory : uint8_t {
    None              = 0,
    FileNotFound      = 1,
    FileTooLarge      = 2,
    FileTooSmall      = 3,
    InvalidFormat     = 4,
    InvalidHeader     = 5,
    InvalidSection    = 6,
    InvalidSymbol     = 7,
    InvalidRelocation = 8,
    TruncatedData     = 9,
    OverlappingSections = 10,
    UnsupportedFeature = 11,
    MemoryError       = 12,
    ParseError        = 13,
    VerificationFailed = 14,
};

} // namespace fortress