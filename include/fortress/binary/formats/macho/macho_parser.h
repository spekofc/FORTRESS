// FORTRESS Mach-O Parser
// macOS Mach-O format parsing

#pragma once

#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/error.h>
#include <fortress/core/string_utils.h>
#include <span>
#include <vector>
#include <string>
#include <optional>

namespace fortress::macho {

// Mach-O Constants
constexpr uint32_t MH_MAGIC = 0xFEEDFACE;      // 32-bit
constexpr uint32_t MH_CIGAM = 0xCEFAEDFE;      // 32-bit swapped
constexpr uint32_t MH_MAGIC_64 = 0xFEEDFACF;   // 64-bit
constexpr uint32_t MH_CIGAM_64 = 0xCFFACFED;   // 64-bit swapped
constexpr uint32_t FAT_MAGIC = 0xCAFEBABE;     // Universal binary
constexpr uint32_t FAT_CIGAM = 0xBEBAFECA;     // Universal binary swapped

// CPU Types
constexpr uint32_t CPU_TYPE_VAX = 1;
constexpr uint32_t CPU_TYPE_MC680x0 = 6;
constexpr uint32_t CPU_TYPE_X86 = 7;
constexpr uint32_t CPU_TYPE_MIPS = 8;
constexpr uint32_t CPU_TYPE_MC98000 = 10;
constexpr uint32_t CPU_TYPE_HPPA = 11;
constexpr uint32_t CPU_TYPE_ARM = 12;
constexpr uint32_t CPU_TYPE_MC88000 = 13;
constexpr uint32_t CPU_TYPE_SPARC = 14;
constexpr uint32_t CPU_TYPE_I860 = 15;
constexpr uint32_t CPU_TYPE_ALPHA = 16;
constexpr uint32_t CPU_TYPE_POWERPC = 18;
constexpr uint32_t CPU_TYPE_POWERPC64 = CPU_TYPE_POWERPC | 0x01000000;

// CPU Subtypes (x86)
constexpr uint32_t CPU_SUBTYPE_X86_ALL = 3;
constexpr uint32_t CPU_SUBTYPE_X86_64_ALL = 3;
constexpr uint32_t CPU_SUBTYPE_X86_64_H = 8;

// CPU Subtypes (ARM)
constexpr uint32_t CPU_SUBTYPE_ARM_ALL = 0;
constexpr uint32_t CPU_SUBTYPE_ARM_V7 = 9;
constexpr uint32_t CPU_SUBTYPE_ARM_V7S = 11;
constexpr uint32_t CPU_SUBTYPE_ARM_V7K = 12;
constexpr uint32_t CPU_SUBTYPE_ARM64_ALL = 0;
constexpr uint32_t CPU_SUBTYPE_ARM64_V8 = 1;
constexpr uint32_t CPU_SUBTYPE_ARM64E = 2;

// File Types
constexpr uint32_t MH_OBJECT = 0x1;
constexpr uint32_t MH_EXECUTE = 0x2;
constexpr uint32_t MH_FVMLIB = 0x3;
constexpr uint32_t MH_CORE = 0x4;
constexpr uint32_t MH_PRELOAD = 0x5;
constexpr uint32_t MH_DYLIB = 0x6;
constexpr uint32_t MH_DYLINKER = 0x7;
constexpr uint32_t MH_BUNDLE = 0x8;
constexpr uint32_t MH_DYLIB_STUB = 0x9;
constexpr uint32_t MH_DSYM = 0xA;
constexpr uint32_t MH_KEXT_BUNDLE = 0xB;

// Flags
constexpr uint32_t MH_NOUNDEFS = 0x1;
constexpr uint32_t MH_INCRLINK = 0x2;
constexpr uint32_t MH_DYLDLINK = 0x4;
constexpr uint32_t MH_BINDATLOAD = 0x8;
constexpr uint32_t MH_PREBOUND = 0x10;
constexpr uint32_t MH_SPLIT_SEGS = 0x20;
constexpr uint32_t MH_LAZY_INIT = 0x40;
constexpr uint32_t MH_TWOLEVEL = 0x80;
constexpr uint32_t MH_FORCE_FLAT = 0x100;
constexpr uint32_t MH_NOMULTIDEFS = 0x200;
constexpr uint32_t MH_NOFIXPREBINDING = 0x400;
constexpr uint32_t MH_PREBINDABLE = 0x800;
constexpr uint32_t MH_ALLMODSBOUND = 0x1000;
constexpr uint32_t MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000;
constexpr uint32_t MH_CANONICAL = 0x4000;
constexpr uint32_t MH_DEAD_STRIPPABLE_DYLIB = 0x8000;
constexpr uint32_t MH_HAS_TLV_DESCRIPTORS = 0x10000;
constexpr uint32_t MH_NO_HEAP_EXECUTION = 0x20000;
constexpr uint32_t MH_APP_EXTENSION_SAFE = 0x40000;
constexpr uint32_t MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x80000;
constexpr uint32_t MH_SIMULATED_NATIVE = 0x100000;

// Load Commands
constexpr uint32_t LC_SEGMENT = 0x1;
constexpr uint32_t LC_SYMTAB = 0x2;
constexpr uint32_t LC_SYMSEG = 0x3;
constexpr uint32_t LC_THREAD = 0x4;
constexpr uint32_t LC_UNIXTHREAD = 0x5;
constexpr uint32_t LC_LOADFVMLIB = 0x6;
constexpr uint32_t LC_IDFVMLIB = 0x7;
constexpr uint32_t LC_IDENT = 0x8;
constexpr uint32_t LC_FVMFILE = 0x9;
constexpr uint32_t LC_PREPAGE = 0xA;
constexpr uint32_t LC_DYSYMTAB = 0xB;
constexpr uint32_t LC_LOAD_DYLIB = 0xC;
constexpr uint32_t LC_ID_DYLIB = 0xD;
constexpr uint32_t LC_LOAD_DYLINKER = 0xE;
constexpr uint32_t LC_ID_DYLINKER = 0xF;
constexpr uint32_t LC_PREBOUND_DYLIB = 0x10;
constexpr uint32_t LC_ROUTINES = 0x11;
constexpr uint32_t LC_SUB_FRAMEWORK = 0x12;
constexpr uint32_t LC_SUB_UMBRELLA = 0x13;
constexpr uint32_t LC_SUB_CLIENT = 0x14;
constexpr uint32_t LC_SUB_LIBRARY = 0x15;
constexpr uint32_t LC_TWOLEVEL_HINTS = 0x16;
constexpr uint32_t LC_PREBIND_CKSUM = 0x17;
constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x18 | 0x80000000;
constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_ROUTINES_64 = 0x1A;
constexpr uint32_t LC_UUID = 0x1B;
constexpr uint32_t LC_RPATH = 0x1C | 0x80000000;
constexpr uint32_t LC_CODE_SIGNATURE = 0x1D;
constexpr uint32_t LC_SEGMENT_SPLIT_INFO = 0x1E;
constexpr uint32_t LC_REEXPORT_DYLIB = 0x1F | 0x80000000;
constexpr uint32_t LC_LAZY_LOAD_DYLIB = 0x20 | 0x80000000;
constexpr uint32_t LC_ENCRYPTION_INFO = 0x21;
constexpr uint32_t LC_DYLD_INFO = 0x22;
constexpr uint32_t LC_DYLD_INFO_ONLY = 0x22 | 0x80000000;
constexpr uint32_t LC_LOAD_UPWARD_DYLIB = 0x23 | 0x80000000;
constexpr uint32_t LC_VERSION_MIN_MACOSX = 0x24;
constexpr uint32_t LC_VERSION_MIN_IPHONEOS = 0x25;
constexpr uint32_t LC_FUNCTION_STARTS = 0x26;
constexpr uint32_t LC_DYLD_ENVIRONMENT = 0x27;
constexpr uint32_t LC_MAIN = 0x28 | 0x80000000;
constexpr uint32_t LC_DATA_IN_CODE = 0x29;
constexpr uint32_t LC_SOURCE_VERSION = 0x2A;
constexpr uint32_t LC_DYLIB_CODE_SIGN_DRS = 0x2B;
constexpr uint32_t LC_ENCRYPTION_INFO_64 = 0x2C;
constexpr uint32_t LC_LINKER_OPTION = 0x2D;
constexpr uint32_t LC_LINKER_OPTIMIZATION_HINT = 0x2E;
constexpr uint32_t LC_VERSION_MIN_TVOS = 0x2F;
constexpr uint32_t LC_VERSION_MIN_WATCHOS = 0x30;
constexpr uint32_t LC_NOTE = 0x31;
constexpr uint32_t LC_BUILD_VERSION = 0x32;
constexpr uint32_t LC_DYLD_EXPORTS_TRIE = 0x33 | 0x80000000;
constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = 0x34 | 0x80000000;

// Segment Flags
constexpr uint32_t SG_HIGHVM = 0x1;
constexpr uint32_t SG_FVMLIB = 0x2;
constexpr uint32_t SG_NORELOC = 0x4;
constexpr uint32_t SG_PROTECTED_VERSION_1 = 0x8;

// Section Types
constexpr uint32_t S_REGULAR = 0x0;
constexpr uint32_t S_ZEROFILL = 0x1;
constexpr uint32_t S_CSTRING_LITERALS = 0x2;
constexpr uint32_t S_4BYTE_LITERALS = 0x3;
constexpr uint32_t S_8BYTE_LITERALS = 0x4;
constexpr uint32_t S_LITERAL_POINTERS = 0x5;
constexpr uint32_t S_NON_LAZY_SYMBOL_POINTERS = 0x6;
constexpr uint32_t S_LAZY_SYMBOL_POINTERS = 0x7;
constexpr uint32_t S_SYMBOL_STUBS = 0x8;
constexpr uint32_t S_MOD_INIT_FUNC_POINTERS = 0x9;
constexpr uint32_t S_MOD_TERM_FUNC_POINTERS = 0xA;
constexpr uint32_t S_COALESCED = 0xB;
constexpr uint32_t S_GB_ZEROFILL = 0xC;
constexpr uint32_t S_INTERPOSING = 0xD;
constexpr uint32_t S_16BYTE_LITERALS = 0xE;
constexpr uint32_t S_DTRACE_DOF = 0xF;
constexpr uint32_t S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10;
constexpr uint32_t S_THREAD_LOCAL_REGULAR = 0x11;
constexpr uint32_t S_THREAD_LOCAL_ZEROFILL = 0x12;
constexpr uint32_t S_THREAD_LOCAL_VARIABLES = 0x13;
constexpr uint32_t S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14;
constexpr uint32_t S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15;

// Section Attributes
constexpr uint32_t SECTION_ATTRIBUTES_USR = 0xFF000000;
constexpr uint32_t S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
constexpr uint32_t S_ATTR_NO_TOC = 0x40000000;
constexpr uint32_t S_ATTR_STRIP_STATIC_SYMS = 0x20000000;
constexpr uint32_t S_ATTR_NO_DEAD_STRIP = 0x10000000;
constexpr uint32_t S_ATTR_LIVE_SUPPORT = 0x08000000;
constexpr uint32_t S_ATTR_SELF_MODIFYING_CODE = 0x04000000;
constexpr uint32_t S_ATTR_DEBUG = 0x02000000;
constexpr uint32_t S_ATTR_SOME_INSTRUCTIONS = 0x01000000;
constexpr uint32_t S_ATTR_EXT_RELOC = 0x00800000;
constexpr uint32_t S_ATTR_LOC_RELOC = 0x00400000;

// Nlist Types
constexpr uint8_t N_UNDF = 0x0;
constexpr uint8_t N_ABS = 0x2;
constexpr uint8_t N_SECT = 0xE;
constexpr uint8_t N_PBUD = 0xC;
constexpr uint8_t N_INDR = 0xA;

constexpr uint8_t N_EXT = 0x01;
constexpr uint8_t N_TYPE = 0x0E;
constexpr uint8_t N_STAB = 0xE0;

// Structures
#pragma pack(push, 1)
struct FatHeader {
    uint32_t magic;
    uint32_t nfat_arch;
};

struct FatArch {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
};

struct MachHeader {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
};

struct MachHeader64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct LoadCommand {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct SegmentCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct SegmentCommand64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct Section {
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct Section64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct SymtabCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct DysymtabCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
};

struct DylibCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dylib_name_offset;
    uint32_t timestamp;
    uint32_t current_version;
    uint32_t compatibility_version;
};

struct DylinkerCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t name_offset;
};

struct ThreadCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t flavor;
    uint32_t count;
    // struct <flavor> state;
};

struct UuidCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[16];
};

struct MainCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

struct Nlist {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    int16_t n_desc;
    uint32_t n_value;
};

struct Nlist64 {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    int16_t n_desc;
    uint64_t n_value;
};

struct RelocationInfo {
    int32_t r_address;
    uint32_t r_symbolnum : 24;
    uint32_t r_pcrel : 1;
    uint32_t r_length : 2;
    uint32_t r_extern : 1;
    uint32_t r_type : 4;
};

struct ScatteredRelocationInfo {
    uint32_t r_scattered : 1;
    uint32_t r_address : 24;
    uint32_t r_type : 4;
    uint32_t r_reserved : 2;
    uint32_t r_pcrel : 1;
    uint32_t r_length : 2;
};

struct FunctionStartsCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct DataInCodeCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct LinkeditDataCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

struct BuildVersionCommand {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;
    uint32_t minos;
    uint32_t sdk;
    uint32_t ntools;
    // struct build_tool_version tools[ntools];
};

struct BuildToolVersion {
    uint32_t tool;
    uint32_t version;
};
#pragma pack(pop)

// Architecture detection
inline Architecture cputype_to_architecture(uint32_t cputype, uint32_t /*cpusubtype*/) {
    uint32_t base_type = cputype & ~0x01000000u; // Remove 64-bit flag
    switch (base_type) {
        case CPU_TYPE_X86:
            return Architecture::X86;
        case CPU_TYPE_X86 | 0x01000000u: // x86_64
            return Architecture::X64;
        case CPU_TYPE_ARM:
            return Architecture::ARM32;
        case CPU_TYPE_ARM | 0x01000000u: // arm64
            return Architecture::ARM64;
        case CPU_TYPE_POWERPC:
            return Architecture::PPC32;
        case CPU_TYPE_POWERPC64:
            return Architecture::PPC64;
        default:
            return Architecture::Unknown;
    }
}

inline std::string cputype_to_string(uint32_t cputype, uint32_t /*cpusubtype*/) {
    uint32_t base_type = cputype & ~0x01000000u;
    switch (base_type) {
        case CPU_TYPE_X86: return "x86";
        case CPU_TYPE_X86 | 0x01000000u: return "x86_64";
        case CPU_TYPE_ARM: return "arm";
        case CPU_TYPE_ARM | 0x01000000u: return "arm64";
        case CPU_TYPE_POWERPC: return "ppc";
        case CPU_TYPE_POWERPC64: return "ppc64";
        default: return "0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&base_type), 4));
    }
}

inline std::string filetype_to_string(uint32_t filetype) {
    switch (filetype) {
        case MH_OBJECT: return "object";
        case MH_EXECUTE: return "execute";
        case MH_FVMLIB: return "fvmlib";
        case MH_CORE: return "core";
        case MH_PRELOAD: return "preload";
        case MH_DYLIB: return "dylib";
        case MH_DYLINKER: return "dylinker";
        case MH_BUNDLE: return "bundle";
        case MH_DYLIB_STUB: return "dylib_stub";
        case MH_DSYM: return "dsym";
        case MH_KEXT_BUNDLE: return "kext_bundle";
        default: return "0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&filetype), 4));
    }
}

// Mach-O Parser Class
class MachOParser {
public:
    MachOParser() = default;
    ~MachOParser() = default;

    Result<BinaryAnalysisResult> parse(const FileMapping& mapping);
    Result<BinaryAnalysisResult> parse(std::span<const std::byte> data);

private:
    struct Context {
        const std::byte* base = nullptr;
        Size size = 0;
        bool is_64bit = false;
        bool is_little_endian = true;
        bool is_fat = false;
        uint32_t fat_offset = 0;

        const MachHeader* header = nullptr;
        const MachHeader64* header64 = nullptr;
        const LoadCommand* load_commands = nullptr;

        // Parsed structures
        std::vector<const SegmentCommand*> segments32;
        std::vector<const SegmentCommand64*> segments64;
        std::vector<const Section*> sections32;
        std::vector<const Section64*> sections64;
        const SymtabCommand* symtab = nullptr;
        const DysymtabCommand* dysymtab = nullptr;
        std::vector<const DylibCommand*> dylibs;
        std::vector<std::string> rpaths;
        const UuidCommand* uuid_cmd = nullptr;
        const MainCommand* main_cmd = nullptr;
        const ThreadCommand* thread_cmd = nullptr;
        const FunctionStartsCommand* func_starts = nullptr;
        const DataInCodeCommand* data_in_code = nullptr;
        const LinkeditDataCommand* code_sig = nullptr;
        const LinkeditDataCommand* dyld_info = nullptr;
        const LinkeditDataCommand* chained_fixups = nullptr;
        const BuildVersionCommand* build_version = nullptr;

        const std::byte* symtab_data = nullptr;
        const std::byte* strtab_data = nullptr;
        const std::byte* indirect_symtab = nullptr;

        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        BinaryAnalysisResult* result = nullptr;
    };

    // Fat binary handling
    Result<void> parse_fat_header(Context& ctx);
    Result<void> parse_fat_archs(Context& ctx);
    Result<void> select_architecture(Context& ctx, Architecture target = Architecture::Unknown);

    // Main parsing
    Result<void> validate_header(Context& ctx);
    Result<void> parse_load_commands(Context& ctx);
    Result<void> parse_segments(Context& ctx);
    Result<void> parse_sections(Context& ctx);
    Result<void> parse_symbols(Context& ctx);
    Result<void> parse_dynamic_libraries(Context& ctx);
    Result<void> parse_function_starts(Context& ctx);
    Result<void> parse_uuid(Context& ctx);
    Result<void> parse_entry_point(Context& ctx);
    Result<void> parse_code_signature(Context& ctx);
    Result<void> parse_build_version(Context& ctx);

    // Helpers
    const std::byte* offset_to_ptr(Context& ctx, uint64_t offset) const;
    const std::byte* vaddr_to_ptr(Context& ctx, uint64_t vaddr) const;
    std::string read_string(Context& ctx, const std::byte* strtab, uint32_t offset) const;
    std::string read_cstring(const std::byte* ptr, Size max_len = 256) const;
    SectionPermission section_flags_to_permissions(uint32_t flags, uint32_t type) const;
    std::string section_type_to_string(uint32_t type) const;
    std::string segment_name(const char* name) const;

    // Function discovery
    Result<void> discover_functions(Context& ctx);

    // Template for 32/64 bit
    template<typename MachHeaderT, typename SegmentCommandT, typename SectionT, typename NlistT>
    Result<void> parse_typed(Context& ctx);
};

} // namespace fortress::macho