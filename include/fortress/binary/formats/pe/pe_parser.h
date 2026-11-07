// FORTRESS PE Parser
// Windows Portable Executable format parsing

#pragma once

#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/error.h>
#include <span>
#include <vector>
#include <string>
#include <optional>

namespace fortress::pe {

// PE Constants
constexpr uint16_t DOS_SIGNATURE = 0x5A4D; // "MZ"
constexpr uint32_t PE_SIGNATURE = 0x00004550; // "PE\0\0"

// Machine types
constexpr uint16_t MACHINE_UNKNOWN = 0x0000;
constexpr uint16_t MACHINE_I386 = 0x014c;
constexpr uint16_t MACHINE_R3000 = 0x0162;
constexpr uint16_t MACHINE_R4000 = 0x0166;
constexpr uint16_t MACHINE_R10000 = 0x0168;
constexpr uint16_t MACHINE_WCEMIPSV2 = 0x0169;
constexpr uint16_t MACHINE_ALPHA = 0x0184;
constexpr uint16_t MACHINE_SH3 = 0x01a2;
constexpr uint16_t MACHINE_SH3DSP = 0x01a3;
constexpr uint16_t MACHINE_SH4 = 0x01a6;
constexpr uint16_t MACHINE_SH5 = 0x01a8;
constexpr uint16_t MACHINE_ARM = 0x01c0;
constexpr uint16_t MACHINE_THUMB = 0x01c2;
constexpr uint16_t MACHINE_ARMNT = 0x01c4;
constexpr uint16_t MACHINE_AM33 = 0x01d3;
constexpr uint16_t MACHINE_POWERPC = 0x01f0;
constexpr uint16_t MACHINE_POWERPCFP = 0x01f1;
constexpr uint16_t MACHINE_IA64 = 0x0200;
constexpr uint16_t MACHINE_MIPS16 = 0x0266;
constexpr uint16_t MACHINE_ALPHA64 = 0x0284;
constexpr uint16_t MACHINE_MIPSFPU = 0x0366;
constexpr uint16_t MACHINE_MIPSFPU16 = 0x0466;
constexpr uint16_t MACHINE_AXP64 = MACHINE_ALPHA64;
constexpr uint16_t MACHINE_TRICORE = 0x0520;
constexpr uint16_t MACHINE_CEF = 0x0CEF;
constexpr uint16_t MACHINE_EBC = 0x0EBC;
constexpr uint16_t MACHINE_AMD64 = 0x8664;
constexpr uint16_t MACHINE_M32R = 0x9041;
constexpr uint16_t MACHINE_CEE = 0xC0EE;
constexpr uint16_t MACHINE_ARM64 = 0xAA64;

// Subsystems
constexpr uint16_t SUBSYSTEM_UNKNOWN = 0;
constexpr uint16_t SUBSYSTEM_NATIVE = 1;
constexpr uint16_t SUBSYSTEM_WINDOWS_GUI = 2;
constexpr uint16_t SUBSYSTEM_WINDOWS_CUI = 3;
constexpr uint16_t SUBSYSTEM_OS2_CUI = 5;
constexpr uint16_t SUBSYSTEM_POSIX_CUI = 7;
constexpr uint16_t SUBSYSTEM_WINDOWS_CE_GUI = 9;
constexpr uint16_t SUBSYSTEM_EFI_APPLICATION = 10;
constexpr uint16_t SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11;
constexpr uint16_t SUBSYSTEM_EFI_RUNTIME_DRIVER = 12;
constexpr uint16_t SUBSYSTEM_EFI_ROM = 13;
constexpr uint16_t SUBSYSTEM_XBOX = 14;
constexpr uint16_t SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16;

// DLL Characteristics
constexpr uint16_t DLL_HIGH_ENTROPY_VA = 0x0020;
constexpr uint16_t DLL_DYNAMIC_BASE = 0x0040;
constexpr uint16_t DLL_FORCE_INTEGRITY = 0x0080;
constexpr uint16_t DLL_NX_COMPAT = 0x0100;
constexpr uint16_t DLL_NO_ISOLATION = 0x0200;
constexpr uint16_t DLL_NO_SEH = 0x0400;
constexpr uint16_t DLL_NO_BIND = 0x0800;
constexpr uint16_t DLL_APPCONTAINER = 0x1000;
constexpr uint16_t DLL_WDM_DRIVER = 0x2000;
constexpr uint16_t DLL_GUARD_CF = 0x4000;
constexpr uint16_t DLL_TERMINAL_SERVER_AWARE = 0x8000;

// Section Characteristics
constexpr uint32_t SECTION_TYPE_NO_PAD = 0x00000008;
constexpr uint32_t SECTION_CNT_CODE = 0x00000020;
constexpr uint32_t SECTION_CNT_INITIALIZED_DATA = 0x00000040;
constexpr uint32_t SECTION_CNT_UNINITIALIZED_DATA = 0x00000080;
constexpr uint32_t SECTION_LNK_OTHER = 0x00000100;
constexpr uint32_t SECTION_LNK_INFO = 0x00000200;
constexpr uint32_t SECTION_LNK_REMOVE = 0x00000800;
constexpr uint32_t SECTION_LNK_COMDAT = 0x00001000;
constexpr uint32_t SECTION_NO_DEFER_SPEC_EXC = 0x00004000;
constexpr uint32_t SECTION_GPREL = 0x00008000;
constexpr uint32_t SECTION_MEM_FARDATA = 0x00008000;
constexpr uint32_t SECTION_MEM_SYSHEAP = 0x00010000;
constexpr uint32_t SECTION_MEM_PURGEABLE = 0x00020000;
constexpr uint32_t SECTION_MEM_16BIT = 0x00020000;
constexpr uint32_t SECTION_MEM_LOCKED = 0x00040000;
constexpr uint32_t SECTION_MEM_PRELOAD = 0x00080000;
constexpr uint32_t SECTION_ALIGN_1BYTES = 0x00100000;
constexpr uint32_t SECTION_ALIGN_2BYTES = 0x00200000;
constexpr uint32_t SECTION_ALIGN_4BYTES = 0x00300000;
constexpr uint32_t SECTION_ALIGN_8BYTES = 0x00400000;
constexpr uint32_t SECTION_ALIGN_16BYTES = 0x00500000;
constexpr uint32_t SECTION_ALIGN_32BYTES = 0x00600000;
constexpr uint32_t SECTION_ALIGN_64BYTES = 0x00700000;
constexpr uint32_t SECTION_ALIGN_128BYTES = 0x00800000;
constexpr uint32_t SECTION_ALIGN_256BYTES = 0x00900000;
constexpr uint32_t SECTION_ALIGN_512BYTES = 0x00A00000;
constexpr uint32_t SECTION_ALIGN_1024BYTES = 0x00B00000;
constexpr uint32_t SECTION_ALIGN_2048BYTES = 0x00C00000;
constexpr uint32_t SECTION_ALIGN_4096BYTES = 0x00D00000;
constexpr uint32_t SECTION_ALIGN_8192BYTES = 0x00E00000;
constexpr uint32_t SECTION_ALIGN_MASK = 0x00F00000;
constexpr uint32_t SECTION_LNK_NRELOC_OVFL = 0x01000000;
constexpr uint32_t SECTION_MEM_DISCARDABLE = 0x02000000;
constexpr uint32_t SECTION_MEM_NOT_CACHED = 0x04000000;
constexpr uint32_t SECTION_MEM_NOT_PAGED = 0x08000000;
constexpr uint32_t SECTION_MEM_SHARED = 0x10000000;
constexpr uint32_t SECTION_MEM_EXECUTE = 0x20000000;
constexpr uint32_t SECTION_MEM_READ = 0x40000000;
constexpr uint32_t SECTION_MEM_WRITE = 0x80000000;

// Data Directory Indices
constexpr size_t DIRECTORY_EXPORT = 0;
constexpr size_t DIRECTORY_IMPORT = 1;
constexpr size_t DIRECTORY_RESOURCE = 2;
constexpr size_t DIRECTORY_EXCEPTION = 3;
constexpr size_t DIRECTORY_SECURITY = 4;
constexpr size_t DIRECTORY_BASERELOC = 5;
constexpr size_t DIRECTORY_DEBUG = 6;
constexpr size_t DIRECTORY_ARCHITECTURE = 7;
constexpr size_t DIRECTORY_GLOBALPTR = 8;
constexpr size_t DIRECTORY_TLS = 9;
constexpr size_t DIRECTORY_LOAD_CONFIG = 10;
constexpr size_t DIRECTORY_BOUND_IMPORT = 11;
constexpr size_t DIRECTORY_IAT = 12;
constexpr size_t DIRECTORY_DELAY_IMPORT = 13;
constexpr size_t DIRECTORY_COM_DESCRIPTOR = 14;
constexpr size_t NUMBER_OF_DIRECTORIES = 16;

// Structures (packed)
#pragma pack(push, 1)
struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct COFFHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

struct OptionalHeader32 {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    // Data directories follow
};

struct OptionalHeader64 {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    // Data directories follow
};

struct DataDirectory {
    uint32_t virtual_address;
    uint32_t size;
};

struct SectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
};

struct ExportDirectory {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name_rva;
    uint32_t ordinal_base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
};

struct ImportDescriptor {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;
    uint32_t first_thunk;
};

struct BaseRelocationBlock {
    uint32_t page_rva;
    uint32_t block_size;
    // uint16_t entries[]; // (block_size - 8) / 2 entries
};

struct DebugDirectory {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t type;
    uint32_t size_of_data;
    uint32_t address_of_raw_data;
    uint32_t pointer_to_raw_data;
};

struct TLS_Directory32 {
    uint32_t start_address_of_raw_data;
    uint32_t end_address_of_raw_data;
    uint32_t address_of_index;
    uint32_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
};

struct TLS_Directory64 {
    uint64_t start_address_of_raw_data;
    uint64_t end_address_of_raw_data;
    uint64_t address_of_index;
    uint64_t address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
};

struct LoadConfigDirectory32 {
    uint32_t size;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t global_flags_clear;
    uint32_t global_flags_set;
    uint32_t critical_section_default_timeout;
    uint32_t decommit_free_block_threshold;
    uint32_t decommit_total_free_threshold;
    uint32_t lock_prefix_table;
    uint32_t maximum_allocation_size;
    uint32_t virtual_memory_threshold;
    uint32_t process_heap_flags;
    uint32_t process_affinity_mask;
    uint16_t csd_version;
    uint16_t dependent_load_flags;
    uint32_t edit_list;
    uint32_t security_cookie;
    uint32_t se_handler_table;
    uint32_t se_handler_count;
};

struct LoadConfigDirectory64 {
    uint32_t size;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t global_flags_clear;
    uint32_t global_flags_set;
    uint32_t critical_section_default_timeout;
    uint64_t decommit_free_block_threshold;
    uint64_t decommit_total_free_threshold;
    uint64_t lock_prefix_table;
    uint64_t maximum_allocation_size;
    uint64_t virtual_memory_threshold;
    uint64_t process_heap_flags;
    uint64_t process_affinity_mask;
    uint16_t csd_version;
    uint16_t dependent_load_flags;
    uint64_t edit_list;
    uint64_t security_cookie;
    uint64_t se_handler_table;
    uint64_t se_handler_count;
};
#pragma pack(pop)

// Architecture detection
inline Architecture machine_to_architecture(uint16_t machine) {
    switch (machine) {
        case MACHINE_I386: return Architecture::X86;
        case MACHINE_AMD64: return Architecture::X64;
        case MACHINE_ARM: case MACHINE_THUMB: case MACHINE_ARMNT: return Architecture::ARM32;
        case MACHINE_ARM64: return Architecture::ARM64;
        case MACHINE_IA64: return Architecture::Unknown; // Itanium
        case MACHINE_POWERPC: case MACHINE_POWERPCFP: return Architecture::PPC32;
        default: return Architecture::Unknown;
    }
}

inline bool is_pe32plus(uint16_t magic) { return magic == 0x20B; }
inline bool is_pe32(uint16_t magic) { return magic == 0x10B; }

// PE Parser Class
class PEParser {
public:
    PEParser() = default;
    ~PEParser() = default;

    // Parse from file mapping
    Result<BinaryAnalysisResult> parse(const FileMapping& mapping);

    // Parse from raw data
    Result<BinaryAnalysisResult> parse(std::span<const std::byte> data);

private:
    struct Context {
        const std::byte* base = nullptr;
        Size size = 0;
        const DOSHeader* dos_header = nullptr;
        const COFFHeader* coff_header = nullptr;
        const void* optional_header = nullptr; // 32 or 64 bit
        const DataDirectory* directories = nullptr;
        const SectionHeader* sections = nullptr;
        uint16_t number_of_sections = 0;
        bool is_64bit = false;
        uint64_t image_base = 0;
        uint32_t section_alignment = 0;
        uint32_t file_alignment = 0;
        BinaryAnalysisResult* result = nullptr;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };

    // Validation
    Result<void> validate_dos_header(Context& ctx);
    Result<void> validate_pe_signature(Context& ctx);
    Result<void> parse_coff_header(Context& ctx);
    Result<void> parse_optional_header(Context& ctx);
    Result<void> parse_sections(Context& ctx);
    Result<void> validate_sections(Context& ctx);

    // Data directory parsing
    Result<void> parse_exports(Context& ctx, BinaryAnalysisResult& result);
    Result<void> parse_imports(Context& ctx, BinaryAnalysisResult& result);
    Result<void> parse_relocations(Context& ctx, BinaryAnalysisResult& result);
    Result<void> parse_debug(Context& ctx, BinaryAnalysisResult& result);
    Result<void> parse_tls(Context& ctx, BinaryAnalysisResult& result);
    Result<void> parse_load_config(Context& ctx, BinaryAnalysisResult& result);
    Result<void> parse_resources(Context& ctx, BinaryAnalysisResult& result);

    // Helpers
    const std::byte* rva_to_raw(Context& ctx, uint32_t rva) const;
    Address rva_to_va(Context& ctx, uint32_t rva) const;
    std::string read_string(Context& ctx, uint32_t rva) const;
    std::string read_string_at(const std::byte* ptr, Size max_len = 256) const;
    SectionPermission section_characteristics_to_permissions(uint32_t characteristics) const;
    std::string section_characteristics_to_string(uint32_t characteristics) const;

    // Function discovery
    Result<void> discover_functions(Context& ctx, BinaryAnalysisResult& result);
};

} // namespace fortress::pe