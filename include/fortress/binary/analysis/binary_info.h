// FORTRESS Binary Analysis - Core Data Structures

#pragma once

#include <fortress/core/types.h>
#include <fortress/core/hash.h>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <chrono>
#include <filesystem>

namespace fortress {

// ============================================================================
// Section Information
// ============================================================================

struct SectionInfo {
    std::string name;
    Offset file_offset = 0;
    Address virtual_address = 0;
    Size virtual_size = 0;
    Size raw_size = 0;
    Size alignment = 0;
    SectionPermission permissions = SectionPermission::None;
    std::string characteristics; // Format-specific flags
    double entropy = 0.0;

    // Derived
    bool is_executable() const noexcept { return has_permission(permissions, SectionPermission::Execute); }
    bool is_writable() const noexcept { return has_permission(permissions, SectionPermission::Write); }
    bool is_readable() const noexcept { return has_permission(permissions, SectionPermission::Read); }
    bool is_code() const noexcept { return is_executable() && !is_writable(); }
    bool is_data() const noexcept { return !is_executable() && is_writable(); }
    bool is_rdata() const noexcept { return is_readable() && !is_writable() && !is_executable(); }
};

// ============================================================================
// Symbol Information
// ============================================================================

struct SymbolInfo {
    std::string name;
    Address address = 0;
    Size size = 0;
    SymbolType type = SymbolType::Unknown;
    SymbolBinding binding = SymbolBinding::Local;
    SymbolVisibility visibility = SymbolVisibility::Default;
    std::string section_name;
    uint32_t section_index = 0;
    bool is_imported = false;
    bool is_exported = false;
    std::string import_library; // For imports
    uint16_t import_ordinal = 0; // For ordinal imports
};

// ============================================================================
// Import/Export Information
// ============================================================================

struct ImportInfo {
    std::string library_name;
    std::vector<SymbolInfo> functions;
    bool is_delay_load = false;
    bool is_bound = false;
};

struct ExportInfo {
    std::string library_name;
    std::vector<SymbolInfo> functions;
    uint32_t ordinal_base = 0;
    uint32_t number_of_functions = 0;
    uint32_t number_of_names = 0;
};

// ============================================================================
// Relocation Information
// ============================================================================

struct RelocationInfo {
    Offset offset = 0;           // Offset in section
    Address virtual_address = 0; // Virtual address
    RelocationKind kind = RelocationKind::Unknown;
    std::string symbol_name;     // Referenced symbol
    uint32_t symbol_index = 0;
    int64_t addend = 0;
    std::string section_name;    // Section containing this relocation
};

// ============================================================================
// Function Information
// ============================================================================

struct FunctionInfo {
    Address address = 0;
    Offset file_offset = INVALID_OFFSET;
    Size size = 0;
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
    std::vector<Address> call_targets;
    std::vector<Address> jump_targets;
    std::vector<Offset> basic_block_offsets; // Offsets within function

    // For virtualization planning
    bool virtualizable = true;
    std::string virtualization_notes;
};

// ============================================================================
// Disassembly
// ============================================================================

struct InstructionInfo {
    Offset offset = 0;
    Address address = 0;
    Size size = 0;
    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;
    bool is_call = false;
    bool is_jump = false;
    bool is_conditional_jump = false;
    bool is_return = false;
    bool is_indirect = false;
    std::optional<Address> target_address; // Resolved target if known
    std::string format; // "intel" or "att"
};

struct BasicBlockInfo {
    Offset start_offset = 0;
    Address start_address = 0;
    Size size = 0;
    std::vector<InstructionInfo> instructions;
    std::vector<Offset> successors; // Offsets to successor blocks
    std::vector<Offset> predecessors;
    bool is_entry = false;
    bool is_exit = false;
};

struct DisassemblyInfo {
    std::vector<InstructionInfo> instructions;
    std::vector<BasicBlockInfo> basic_blocks;
    Address base_address = 0;
    Architecture architecture = Architecture::Unknown;
    Size total_size = 0;
    Size analyzed_size = 0;
    bool complete = false;
    std::string error_message;
};

// ============================================================================
// Debug Information
// ============================================================================

struct DebugInfo {
    bool has_debug_symbols = false;
    std::string debug_type; // "dwarf", "pdb", "stabs", "codeview"
    std::string debug_directory; // Path to external debug file
    std::string build_id; // ELF Build ID / PDB GUID
    std::vector<std::string> source_files;
    bool stripped = false;
};

// ============================================================================
// Binary Analysis Result
// ============================================================================

struct BinaryAnalysisResult {
    // File identification
    std::filesystem::path file_path;
    BinaryFormat format = BinaryFormat::Unknown;
    Architecture architecture = Architecture::Unknown;
    Endianness endianness = Endianness::Little;
    bool is_64bit = false;
    bool is_32bit = false;
    std::string os_abi; // "windows", "linux", "macos", "freebsd", etc.
    std::string machine_type; // Format-specific machine type string

    // Entry point
    Address entry_point = 0;
    Offset entry_point_offset = INVALID_OFFSET;

    // Hashes
    MultiHashResult hashes;

    // Sections
    std::vector<SectionInfo> sections;

    // Symbols
    std::vector<SymbolInfo> symbols;
    std::vector<ImportInfo> imports;
    std::vector<ExportInfo> exports;

    // Relocations
    std::vector<RelocationInfo> relocations;

    // Functions
    std::vector<FunctionInfo> functions;

    // Disassembly
    std::optional<DisassemblyInfo> disassembly;

    // Debug
    DebugInfo debug_info;

    // Metadata
    std::chrono::system_clock::time_point analysis_time;
    std::chrono::milliseconds analysis_duration;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::vector<std::string> limitations;

    // Statistics
    Size total_functions = 0;
    Size confirmed_functions = 0;
    Size estimated_functions = 0;
    Size total_imports = 0;
    Size total_exports = 0;
    Size total_sections = 0;
    Size total_symbols = 0;
    Size total_relocations = 0;

    // Validation
    bool valid_format = false;
    bool truncated = false;
    bool corrupted = false;
    bool overlapping_sections = false;

    // Summary methods
    std::string summary() const;
    std::string to_json() const;
};

} // namespace fortress