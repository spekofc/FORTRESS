// FORTRESS ELF Parser
// Linux/Unix ELF format parsing

#pragma once

#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/error.h>
#include <span>
#include <vector>
#include <string>
#include <optional>

namespace fortress::elf {

// ELF Constants
constexpr uint32_t ELF_MAGIC = 0x464C457F; // "\x7FELF"

// Class
constexpr uint8_t ELFCLASSNONE = 0;
constexpr uint8_t ELFCLASS32 = 1;
constexpr uint8_t ELFCLASS64 = 2;

// Data encoding
constexpr uint8_t ELFDATANONE = 0;
constexpr uint8_t ELFDATA2LSB = 1;
constexpr uint8_t ELFDATA2MSB = 2;

// OS/ABI
constexpr uint8_t ELFOSABI_NONE = 0;
constexpr uint8_t ELFOSABI_HPUX = 1;
constexpr uint8_t ELFOSABI_NETBSD = 2;
constexpr uint8_t ELFOSABI_LINUX = 3;
constexpr uint8_t ELFOSABI_SOLARIS = 6;
constexpr uint8_t ELFOSABI_AIX = 7;
constexpr uint8_t ELFOSABI_IRIX = 8;
constexpr uint8_t ELFOSABI_FREEBSD = 9;
constexpr uint8_t ELFOSABI_OPENBSD = 12;
constexpr uint8_t ELFOSABI_STANDALONE = 255;

// Type
constexpr uint16_t ET_NONE = 0;
constexpr uint16_t ET_REL = 1;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t ET_DYN = 3;
constexpr uint16_t ET_CORE = 4;

// Machine
constexpr uint16_t EM_NONE = 0;
constexpr uint16_t EM_M32 = 1;
constexpr uint16_t EM_SPARC = 2;
constexpr uint16_t EM_386 = 3;
constexpr uint16_t EM_68K = 4;
constexpr uint16_t EM_88K = 5;
constexpr uint16_t EM_860 = 7;
constexpr uint16_t EM_MIPS = 8;
constexpr uint16_t EM_PPC = 20;
constexpr uint16_t EM_PPC64 = 21;
constexpr uint16_t EM_ARM = 40;
constexpr uint16_t EM_X86_64 = 62;
constexpr uint16_t EM_AARCH64 = 183;
constexpr uint16_t EM_RISCV = 243;

// Section Types
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_RELA = 4;
constexpr uint32_t SHT_HASH = 5;
constexpr uint32_t SHT_DYNAMIC = 6;
constexpr uint32_t SHT_NOTE = 7;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_REL = 9;
constexpr uint32_t SHT_SHLIB = 10;
constexpr uint32_t SHT_DYNSYM = 11;
constexpr uint32_t SHT_INIT_ARRAY = 14;
constexpr uint32_t SHT_FINI_ARRAY = 15;
constexpr uint32_t SHT_PREINIT_ARRAY = 16;
constexpr uint32_t SHT_GROUP = 17;
constexpr uint32_t SHT_SYMTAB_SHNDX = 18;
constexpr uint32_t SHT_GNU_ATTRIBUTES = 0x6ffffff5;
constexpr uint32_t SHT_GNU_HASH = 0x6ffffff6;
constexpr uint32_t SHT_GNU_VERDEF = 0x6ffffffd;
constexpr uint32_t SHT_GNU_VERNEED = 0x6ffffffe;
constexpr uint32_t SHT_GNU_VERSYM = 0x6fffffff;

// Section Flags
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;
constexpr uint64_t SHF_MERGE = 0x10;
constexpr uint64_t SHF_STRINGS = 0x20;
constexpr uint64_t SHF_INFO_LINK = 0x40;
constexpr uint64_t SHF_LINK_ORDER = 0x80;
constexpr uint64_t SHF_OS_NONCONFORMING = 0x100;
constexpr uint64_t SHF_GROUP = 0x200;
constexpr uint64_t SHF_TLS = 0x400;
constexpr uint64_t SHF_COMPRESSED = 0x800;
constexpr uint64_t SHF_MASKOS = 0x0ff00000;
constexpr uint64_t SHF_MASKPROC = 0xf0000000;

// Symbol Binding
constexpr uint8_t STB_LOCAL = 0;
constexpr uint8_t STB_GLOBAL = 1;
constexpr uint8_t STB_WEAK = 2;
constexpr uint8_t STB_GNU_UNIQUE = 10;

// Symbol Type
constexpr uint8_t STT_NOTYPE = 0;
constexpr uint8_t STT_FUNC = 2;
constexpr uint8_t STT_SECTION = 3;
constexpr uint8_t STT_FILE = 4;
constexpr uint8_t STT_COMMON = 5;
constexpr uint8_t STT_TLS = 6;
constexpr uint8_t STT_GNU_IFUNC = 10;

// Symbol Visibility
constexpr uint8_t STV_DEFAULT = 0;
constexpr uint8_t STV_INTERNAL = 1;
constexpr uint8_t STV_HIDDEN = 2;
constexpr uint8_t STV_PROTECTED = 3;

// Dynamic Tags
constexpr int64_t DT_NULL = 0;
constexpr int64_t DT_NEEDED = 1;
constexpr int64_t DT_PLTRELSZ = 2;
constexpr int64_t DT_PLTGOT = 3;
constexpr int64_t DT_HASH = 4;
constexpr int64_t DT_STRTAB = 5;
constexpr int64_t DT_SYMTAB = 6;
constexpr int64_t DT_RELA = 7;
constexpr int64_t DT_RELASZ = 8;
constexpr int64_t DT_RELAENT = 9;
constexpr int64_t DT_STRSZ = 10;
constexpr int64_t DT_SYMENT = 11;
constexpr int64_t DT_INIT = 12;
constexpr int64_t DT_FINI = 13;
constexpr int64_t DT_SONAME = 14;
constexpr int64_t DT_RPATH = 15;
constexpr int64_t DT_SYMBOLIC = 16;
constexpr int64_t DT_REL = 17;
constexpr int64_t DT_RELSZ = 18;
constexpr int64_t DT_RELENT = 19;
constexpr int64_t DT_PLTREL = 20;
constexpr int64_t DT_DEBUG = 21;
constexpr int64_t DT_TEXTREL = 22;
constexpr int64_t DT_JMPREL = 23;
constexpr int64_t DT_BIND_NOW = 24;
constexpr int64_t DT_INIT_ARRAY = 25;
constexpr int64_t DT_FINI_ARRAY = 26;
constexpr int64_t DT_INIT_ARRAYSZ = 27;
constexpr int64_t DT_FINI_ARRAYSZ = 28;
constexpr int64_t DT_RUNPATH = 29;
constexpr int64_t DT_FLAGS = 30;
constexpr int64_t DT_ENCODING = 32;
constexpr int64_t DT_PREINIT_ARRAY = 32;
constexpr int64_t DT_PREINIT_ARRAYSZ = 33;
constexpr int64_t DT_SYMINSZ = 34;
constexpr int64_t DT_SYMINENT = 35;
constexpr int64_t DT_GNU_HASH = 0x6ffffef5;
constexpr int64_t DT_VERSYM = 0x6ffffff0;
constexpr int64_t DT_VERDEF = 0x6ffffffc;
constexpr int64_t DT_VERDEFNUM = 0x6ffffffd;
constexpr int64_t DT_VERNEED = 0x6ffffffe;
constexpr int64_t DT_VERNEEDNUM = 0x6fffffff;

// Note Types
constexpr uint32_t NT_GNU_BUILD_ID = 3;

// Structures
#pragma pack(push, 1)
struct Ehdr32 {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Ehdr64 {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Phdr32 {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Phdr64 {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

struct Shdr32 {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct Shdr64 {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Sym32 {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
};

struct Sym64 {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Rel32 {
    uint32_t r_offset;
    uint32_t r_info;
};

struct Rel64 {
    uint64_t r_offset;
    uint64_t r_info;
};

struct Rela32 {
    uint32_t r_offset;
    uint32_t r_info;
    int32_t r_addend;
};

struct Rela64 {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t r_addend;
};

struct Dyn32 {
    int32_t d_tag;
    uint32_t d_val;
};

struct Dyn64 {
    int64_t d_tag;
    uint64_t d_val;
};

struct Note {
    uint32_t n_namesz;
    uint32_t n_descsz;
    uint32_t n_type;
    // char name[n_namesz];
    // char desc[n_descsz];
};

struct Gnuhash {
    uint32_t nbuckets;
    uint32_t symndx;
    uint32_t maskwords;
    uint32_t shift2;
    // buckets[nbuckets]
    // chain[...]
    // bloom[maskwords]
};
#pragma pack(pop)

// Macros
#define ELF_ST_BIND(info)  ((info) >> 4)
#define ELF_ST_TYPE(info)  ((info) & 0xF)
#define ELF_ST_VISIBILITY(other) ((other) & 0x3)
#define ELF32_R_SYM(info)  ((info) >> 8)
#define ELF32_R_TYPE(info) ((info) & 0xFF)
#define ELF64_R_SYM(info)  (static_cast<uint32_t>((info) >> 32))
#define ELF64_R_TYPE(info) ((info) & 0xFFFFFFFF)

// Architecture detection
inline Architecture machine_to_architecture(uint16_t machine) {
    switch (machine) {
        case EM_386: return Architecture::X86;
        case EM_X86_64: return Architecture::X64;
        case EM_ARM: return Architecture::ARM32;
        case EM_AARCH64: return Architecture::ARM64;
        case EM_PPC: return Architecture::PPC32;
        case EM_PPC64: return Architecture::PPC64;
        case EM_MIPS: return Architecture::MIPS32;
        case EM_RISCV: return Architecture::RISCV64; // Could be 32 or 64
        case EM_SPARC: return Architecture::Unknown; // SPARC32/64
        default: return Architecture::Unknown;
    }
}

inline std::string osabi_to_string(uint8_t osabi) {
    switch (osabi) {
        case ELFOSABI_NONE: return "none";
        case ELFOSABI_LINUX: return "linux";
        case ELFOSABI_FREEBSD: return "freebsd";
        case ELFOSABI_OPENBSD: return "openbsd";
        case ELFOSABI_NETBSD: return "netbsd";
        case ELFOSABI_SOLARIS: return "solaris";
        case ELFOSABI_AIX: return "aix";
        case ELFOSABI_IRIX: return "irix";
        case ELFOSABI_HPUX: return "hpux";
        case ELFOSABI_STANDALONE: return "standalone";
        default: return "unknown";
    }
}

inline std::string machine_to_string(uint16_t machine) {
    switch (machine) {
        case EM_386: return "x86";
        case EM_X86_64: return "x86_64";
        case EM_ARM: return "arm";
        case EM_AARCH64: return "aarch64";
        case EM_PPC: return "ppc32";
        case EM_PPC64: return "ppc64";
        case EM_MIPS: return "mips";
        case EM_RISCV: return "riscv";
        default: return std::to_string(machine);
    }
}

// ELF Parser Class
class ELFParser {
public:
    ELFParser() = default;
    ~ELFParser() = default;

    Result<BinaryAnalysisResult> parse(const FileMapping& mapping);
    Result<BinaryAnalysisResult> parse(std::span<const std::byte> data);

private:
    struct Context {
        const std::byte* base = nullptr;
        Size size = 0;
        bool is_64bit = false;
        bool is_little_endian = true;
        uint8_t ei_class = 0;
        uint8_t ei_data = 0;
        uint8_t ei_osabi = 0;

        const Ehdr32* ehdr32 = nullptr;
        const Ehdr64* ehdr64 = nullptr;
        const Phdr32* phdrs32 = nullptr;
        const Phdr64* phdrs64 = nullptr;
        const Shdr32* shdrs32 = nullptr;
        const Shdr64* shdrs64 = nullptr;
        const std::byte* shstrtab = nullptr;

        uint16_t phnum = 0;
        uint16_t shnum = 0;
        uint16_t shstrndx = 0;

        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        BinaryAnalysisResult* result = nullptr;
    };

    // Validation
    Result<void> validate_header(Context& ctx);
    Result<void> parse_program_headers(Context& ctx);
    Result<void> parse_section_headers(Context& ctx);
    Result<void> parse_sections(Context& ctx);
    Result<void> parse_symbols(Context& ctx);
    Result<void> parse_dynamic(Context& ctx);
    Result<void> parse_relocations(Context& ctx);
    Result<void> parse_notes(Context& ctx);

    // Helpers
    const std::byte* offset_to_ptr(Context& ctx, uint64_t offset) const;
    const std::byte* vaddr_to_ptr(Context& ctx, uint64_t vaddr) const;
    std::string read_string(Context& ctx, const std::byte* strtab, uint32_t offset) const;
    SectionPermission section_flags_to_permissions(uint64_t flags) const;
    std::string section_flags_to_string(uint64_t flags) const;
    std::string section_type_to_string(uint32_t type) const;
    SymbolBinding symbol_binding(uint8_t info) const;
    SymbolType symbol_type(uint8_t info) const;
    SymbolVisibility symbol_visibility(uint8_t other) const;

    // Function discovery
    Result<void> discover_functions(Context& ctx);

    // Template helpers for 32/64 bit
    template<typename Ehdr, typename Phdr, typename Shdr, typename Sym, typename Rel, typename Rela, typename Dyn>
    Result<void> parse_typed(Context& ctx);
};

} // namespace fortress::elf