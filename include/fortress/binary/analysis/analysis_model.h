// FORTRESS Analysis Data Model
// Unified normalized representation of binary analysis results across PE, ELF, and Mach-O

#pragma once

#include <fortress/core/types.h>
#include <fortress/core/hash.h>
#include <fortress/binary/analysis/binary_info.h>  // For BinaryAnalysisResult, RelocationInfo, etc.
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <variant>
#include <chrono>
#include <filesystem>
#include <memory>

namespace fortress {

// ============================================================================
// Forward Declarations
// ============================================================================

struct SegmentMapping;
struct FatArchInfo;

// ============================================================================
// Typed Address System
// ============================================================================

// Strongly-typed address kinds to prevent accidental mixing of address spaces
enum class AddressSpace : uint8_t {
    Invalid   = 0,
    FileOffset = 1,   // Raw file offset (bytes from start of file)
    RVA       = 2,    // Relative Virtual Address (PE: relative to ImageBase)
    VA        = 3,    // Virtual Address (absolute runtime address)
    SegmentVA = 4,    // Virtual address within a specific segment (Mach-O)
};

/// Strongly-typed address wrapper that carries its address space
/// Prevents implicit conversions between different address spaces
class TypedAddress {
public:
    constexpr TypedAddress() noexcept : value_(0), space_(AddressSpace::Invalid) {}
    constexpr TypedAddress(uint64_t value, AddressSpace space) noexcept : value_(value), space_(space) {}

    // Factory methods for clarity
    static TypedAddress file_offset(uint64_t offset) noexcept { return TypedAddress(offset, AddressSpace::FileOffset); }
    static TypedAddress rva(uint64_t rva) noexcept { return TypedAddress(rva, AddressSpace::RVA); }
    static TypedAddress va(uint64_t va) noexcept { return TypedAddress(va, AddressSpace::VA); }
    // SegmentVA with explicit segment identifier (for Mach-O)
    // Encodes segment index in upper 16 bits, offset in lower 48 bits
    // Validates that offset fits in 48 bits and segment_index fits in 16 bits
    static Result<TypedAddress> make_segment_va(uint16_t segment_index, uint64_t offset_in_segment) noexcept {
        if (offset_in_segment > 0xFFFFFFFFFFFFull) {
            return Result<TypedAddress>::err(Error::invalid_argument("SegmentVA offset exceeds 48-bit limit"));
        }
        if (segment_index == 0 && offset_in_segment == 0) {
            // Allow zero but document it represents segment 0, offset 0
        }
        uint64_t value = (static_cast<uint64_t>(segment_index) << 48) | (offset_in_segment & 0xFFFFFFFFFFFFull);
        return Result<TypedAddress>::ok(TypedAddress(value, AddressSpace::SegmentVA));
    }
    
    // Convenience factory for tests - creates SegmentVA with segment index and offset
    static TypedAddress segment_va(uint16_t segment_index, uint64_t offset_in_segment) noexcept {
        if (offset_in_segment > 0xFFFFFFFFFFFFull) {
            // In debug builds, this would be an assertion failure
        }
        uint64_t value = (static_cast<uint64_t>(segment_index) << 48) | (offset_in_segment & 0xFFFFFFFFFFFFull);
        return TypedAddress(value, AddressSpace::SegmentVA);
    }
    
    // Legacy factory - DEPRECATED: creates SegmentVA without segment identity (segment_index=0)
    // Use segment_va(segment_index, offset) for proper segment identification
    [[deprecated("Use segment_va(segment_index, offset) for proper segment identification")]]
    static TypedAddress segment_va(uint64_t va) noexcept { return TypedAddress(va, AddressSpace::SegmentVA); }
    
    // Accessors
    constexpr uint64_t value() const noexcept { return value_; }
    constexpr AddressSpace space() const noexcept { return space_; }
    constexpr bool valid() const noexcept { return space_ != AddressSpace::Invalid; }
    
    // SegmentVA specific accessors
    constexpr uint16_t segment_index() const noexcept { 
        return static_cast<uint16_t>(value_ >> 48); 
    }
    constexpr uint64_t segment_offset() const noexcept { 
        return value_ & 0xFFFFFFFFFFFFull; 
    }

    // Explicit conversion to raw value (use with caution)
    constexpr explicit operator uint64_t() const noexcept { return value_; }

    // String representation
    std::string to_string() const;

    // Equality
    constexpr bool operator==(const TypedAddress& other) const noexcept {
        return value_ == other.value_ && space_ == other.space_;
    }
    constexpr bool operator!=(const TypedAddress& other) const noexcept {
        return !(*this == other);
    }
    constexpr bool operator<(const TypedAddress& other) const noexcept {
        if (space_ != other.space_) return static_cast<uint8_t>(space_) < static_cast<uint8_t>(other.space_);
        return value_ < other.value_;
    }

private:
    uint64_t value_;
    AddressSpace space_;
};

// Conversion result with validation
struct AddressConversionResult {
    TypedAddress address;
    bool success = false;
    std::string error;
};

// Segment mapping for Mach-O/ELF (segment VA range -> file offset)
struct SegmentMapping {
    std::string segment_name;
    TypedAddress vm_address;    // Virtual memory address (VA)
    TypedAddress vm_size;       // Virtual memory size
    TypedAddress file_offset;   // File offset
    TypedAddress file_size;     // File size
    uint32_t max_protection = 0;
    uint32_t init_protection = 0;
};

/// Address converter that knows how to translate between address spaces
/// using binary-specific metadata (ImageBase, segment mappings, etc.)
class AddressConverter {
public:
    virtual ~AddressConverter() = default;

    // Convert between address spaces
    virtual AddressConversionResult convert(const TypedAddress& from, AddressSpace to_space) const = 0;

    // Check if conversion is possible
    virtual bool can_convert(AddressSpace from, AddressSpace to) const = 0;

    // Get base address for RVA -> VA conversion
    virtual std::optional<uint64_t> image_base() const = 0;

    // Get segment mappings for Mach-O/ELF
    virtual std::vector<SegmentMapping> segments() const = 0;
};

// ============================================================================
// Normalized Binary Metadata
// ============================================================================

struct FatArchInfo {
    Architecture architecture = Architecture::Unknown;
    uint32_t cputype = 0;
    uint32_t cpusubtype = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
};

struct BinaryMetadata {
    // File identification
    std::filesystem::path file_path;
    BinaryFormat format = BinaryFormat::Unknown;
    Architecture architecture = Architecture::Unknown;
    Endianness endianness = Endianness::Little;
    bool is_64bit = false;
    bool is_32bit = false;
    std::string os_abi;              // "windows", "linux", "macos", "freebsd", etc.
    std::string machine_type;        // Format-specific machine type string

    // Entry point (always VA)
    TypedAddress entry_point = TypedAddress::va(0);
    TypedAddress entry_point_file_offset = TypedAddress::file_offset(INVALID_OFFSET);

    // Image base (for RVA -> VA conversion in PE)
    uint64_t image_base = 0;

    // Hashes
    MultiHashResult hashes;

    // Format-specific raw data (preserved for detailed analysis)
    struct FormatSpecificData {
        // PE specific
        struct PEData {
            uint32_t characteristics = 0;
            uint16_t subsystem = 0;
            uint16_t dll_characteristics = 0;
            uint32_t size_of_image = 0;
            uint32_t size_of_headers = 0;
            uint32_t checksum = 0;
            std::vector<std::string> debug_directories;
        };
        std::optional<PEData> pe;

        // ELF specific
        struct ELFData {
            uint32_t e_flags = 0;
            uint16_t e_type = 0;
            std::string abi_version;
            std::vector<std::string> dynamic_tags;
            std::string build_id;
            std::string soname;
            std::vector<std::string> needed_libraries;
        };
        std::optional<ELFData> elf;

        // Mach-O specific
        struct MachOData {
            uint32_t filetype = 0;
            uint32_t flags = 0;
            std::string min_os_version;
            std::string sdk_version;
            std::vector<std::string> rpaths;
            std::string uuid;
            bool is_fat = false;
            std::vector<FatArchInfo> fat_archs;
        };
        std::optional<MachOData> macho;
    };
    FormatSpecificData format_specific;
};

// ============================================================================
// Normalized Section
// ============================================================================

struct NormalizedSection {
    std::string name;
    TypedAddress file_offset = TypedAddress::file_offset(0);
    TypedAddress virtual_address = TypedAddress::va(0);  // VA
    TypedAddress rva = TypedAddress::rva(0);             // RVA (if applicable)
    uint64_t virtual_size = 0;
    uint64_t raw_size = 0;
    uint64_t alignment = 0;
    SectionPermission permissions = SectionPermission::None;
    std::string characteristics;  // Format-specific flags as string
    double entropy = 0.0;

    // Format-specific section index
    uint32_t section_index = 0;

    // Segment name (Mach-O)
    std::string segment_name;

    // Derived properties (using existing has_permission from types.h)
    bool is_executable() const noexcept { return (static_cast<uint32_t>(permissions) & static_cast<uint32_t>(SectionPermission::Execute)) != 0; }
    bool is_writable() const noexcept { return (static_cast<uint32_t>(permissions) & static_cast<uint32_t>(SectionPermission::Write)) != 0; }
    bool is_readable() const noexcept { return (static_cast<uint32_t>(permissions) & static_cast<uint32_t>(SectionPermission::Read)) != 0; }
    bool is_code() const noexcept { return is_executable() && !is_writable(); }
    bool is_data() const noexcept { return !is_executable() && is_writable(); }
    bool is_rdata() const noexcept { return is_readable() && !is_writable() && !is_executable(); }

    // Check if section contains a given address (VA)
    bool contains_va(TypedAddress va) const noexcept {
        if (va.space() != AddressSpace::VA) return false;
        uint64_t start = virtual_address.value();
        uint64_t end = start + virtual_size;
        return va.value() >= start && va.value() < end;
    }

    // Check if section contains a given file offset
    bool contains_file_offset(TypedAddress offset) const noexcept {
        if (offset.space() != AddressSpace::FileOffset) return false;
        uint64_t start = file_offset.value();
        uint64_t end = start + raw_size;
        return offset.value() >= start && offset.value() < end;
    }
};

// ============================================================================
// Normalized Symbol
// ============================================================================

struct NormalizedSymbol {
    std::string name;
    TypedAddress address = TypedAddress::va(0);  // VA
    uint64_t size = 0;
    SymbolType type = SymbolType::Unknown;
    SymbolBinding binding = SymbolBinding::Local;
    SymbolVisibility visibility = SymbolVisibility::Default;
    std::string section_name;
    uint32_t section_index = 0;
    bool is_imported = false;
    bool is_exported = false;
    std::string import_library;
    uint16_t import_ordinal = 0;
    bool is_weak = false;
    bool is_thread_local = false;
};

// ============================================================================
// Normalized Import/Export
// ============================================================================

struct NormalizedImport {
    std::string library_name;
    std::vector<NormalizedSymbol> functions;
    bool is_delay_load = false;
    bool is_bound = false;
    // PE: IAT/RVA info
    TypedAddress iat_rva = TypedAddress::rva(0);
    // ELF: GOT/PLT info
    TypedAddress got_offset = TypedAddress::file_offset(0);
    TypedAddress plt_offset = TypedAddress::file_offset(0);
};

struct NormalizedExport {
    std::string library_name;
    std::vector<NormalizedSymbol> functions;
    uint32_t ordinal_base = 0;
    uint32_t number_of_functions = 0;
    uint32_t number_of_names = 0;
    // PE: Export directory RVA
    TypedAddress export_dir_rva = TypedAddress::rva(0);
    // ELF: .dynsym/.dynstr info
    TypedAddress dynsym_offset = TypedAddress::file_offset(0);
    TypedAddress dynstr_offset = TypedAddress::file_offset(0);
};

// ============================================================================
// Normalized Relocation
// ============================================================================

struct NormalizedRelocation {
    TypedAddress offset = TypedAddress::file_offset(0);        // Offset in section (file offset)
    TypedAddress virtual_address = TypedAddress::va(0);        // VA where relocation applies
    RelocationKind kind = RelocationKind::Unknown;
    std::string symbol_name;
    uint32_t symbol_index = 0;
    int64_t addend = 0;
    std::string section_name;    // Section containing this relocation
    uint32_t section_index = 0;
    // Format-specific relocation type
    uint32_t format_type = 0;
    std::string format_type_name;
};

// ============================================================================
// Normalized Function
// ============================================================================

struct NormalizedFunction {
    TypedAddress address = TypedAddress::va(0);           // VA
    TypedAddress file_offset = TypedAddress::file_offset(INVALID_OFFSET);
    uint64_t size = 0;
    Architecture architecture = Architecture::Unknown;
    ConfidenceLevel confidence = ConfidenceLevel::Unknown;
    FunctionSource source = FunctionSource::Unknown;
    std::string name;
    std::string section_name;
    std::string mangled_name;
    std::string demangled_name;

    // Analysis
    bool has_symbol = false;
    bool is_exported = false;
    bool is_imported = false;
    bool is_thunk = false;
    bool has_unwind_info = false;
    bool has_exception_handler = false;
    std::vector<TypedAddress> call_targets;    // VAs
    std::vector<TypedAddress> jump_targets;    // VAs
    std::vector<TypedAddress> basic_block_starts;  // VAs

    // For virtualization planning
    bool virtualizable = true;
    std::string virtualization_notes;

    // Boundaries (refined by FunctionRefiner)
    std::optional<TypedAddress> refined_start;  // VA
    std::optional<TypedAddress> refined_end;    // VA (exclusive)
    bool boundaries_refined = false;

    // Prologue/epilogue detection
    std::vector<uint8_t> prologue_bytes;
    std::vector<uint8_t> epilogue_bytes;
};

// ============================================================================
// Normalized Analysis Result
// ============================================================================

struct NormalizedAnalysisResult {
    // Core metadata
    BinaryMetadata metadata;

    // Normalized structures
    std::vector<NormalizedSection> sections;
    std::vector<NormalizedSymbol> symbols;
    std::vector<NormalizedImport> imports;
    std::vector<NormalizedExport> exports;
    std::vector<NormalizedRelocation> relocations;
    std::vector<NormalizedFunction> functions;

    // Address converter for this binary
    std::shared_ptr<AddressConverter> converter;

    // Analysis metadata
    std::chrono::system_clock::time_point analysis_time;
    std::chrono::milliseconds analysis_duration;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::vector<std::string> limitations;

    // Statistics
    size_t total_functions = 0;
    size_t confirmed_functions = 0;
    size_t estimated_functions = 0;
    size_t total_imports = 0;
    size_t total_exports = 0;
    size_t total_sections = 0;
    size_t total_symbols = 0;
    size_t total_relocations = 0;

    // Validation
    bool valid_format = false;
    bool truncated = false;
    bool corrupted = false;
    bool overlapping_sections = false;

    // Summary methods
    std::string summary() const;
    std::string to_json() const;

    // Lookup helpers
    std::optional<const NormalizedSection*> find_section_by_va(TypedAddress va) const;
    std::optional<const NormalizedSection*> find_section_by_file_offset(TypedAddress offset) const;
    std::optional<const NormalizedFunction*> find_function_by_va(TypedAddress va) const;
    std::optional<const NormalizedSymbol*> find_symbol_by_name(const std::string& name) const;
    std::vector<const NormalizedRelocation*> find_relocations_in_section(const std::string& section_name) const;
};

// ============================================================================
// Conversion utilities
// ============================================================================

/// Convert BinaryAnalysisResult to NormalizedAnalysisResult
/// This is the main integration point from Phase 2 parsers to Phase 3 model
NormalizedAnalysisResult normalize_analysis_result(
    const BinaryAnalysisResult& result,
    std::shared_ptr<AddressConverter> converter = nullptr);

/// Convert NormalizedAnalysisResult back to BinaryAnalysisResult (for compatibility)
BinaryAnalysisResult denormalize_analysis_result(const NormalizedAnalysisResult& result);

} // namespace fortress