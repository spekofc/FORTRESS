// FORTRESS Mach-O Parser Tests

#include <fortress/binary/formats/macho/macho_parser.h>
#include <gtest/gtest.h>
#include <cstring>

using namespace fortress;

static std::vector<std::byte> create_minimal_macho64() {
    // Need enough space for: header (32) + load commands (~400) + text (0x2000) + data (0x1000) + symtab (0x400) + strtab (0x100)
    // Total ~ 0x5000 (20KB) to be safe
    std::vector<std::byte> data(0x6000, std::byte{0});
    auto* ptr = data.data();

    // Mach Header 64
    auto* hdr = reinterpret_cast<macho::MachHeader64*>(ptr);
    hdr->magic = macho::MH_MAGIC_64;
    hdr->cputype = macho::CPU_TYPE_X86 | 0x01000000; // x86_64
    hdr->cpusubtype = macho::CPU_SUBTYPE_X86_64_ALL;
    hdr->filetype = macho::MH_EXECUTE;
    hdr->ncmds = 6;
    hdr->sizeofcmds = sizeof(macho::SegmentCommand64) * 2 + sizeof(macho::Section64) * 2
                    + sizeof(macho::SymtabCommand)
                    + sizeof(macho::DysymtabCommand)
                    + sizeof(macho::UuidCommand)
                    + sizeof(macho::MainCommand);
    hdr->flags = macho::MH_NOUNDEFS | macho::MH_DYLDLINK | macho::MH_TWOLEVEL;
    hdr->reserved = 0;

    // Load Commands
    auto* lc_ptr = ptr + sizeof(macho::MachHeader64);

    // LC_SEGMENT_64: __TEXT
    auto* seg_text = reinterpret_cast<macho::SegmentCommand64*>(lc_ptr);
    seg_text->cmd = macho::LC_SEGMENT_64;
    seg_text->cmdsize = sizeof(macho::SegmentCommand64) + sizeof(macho::Section64) * 2;
    std::memcpy(seg_text->segname, "__TEXT", 6);
    seg_text->vmaddr = 0x100000000;
    seg_text->vmsize = 0x2000;
    seg_text->fileoff = 0x1000;
    seg_text->filesize = 0x2000;
    seg_text->maxprot = 7; // RWX
    seg_text->initprot = 5; // RX
    seg_text->nsects = 2;
    seg_text->flags = 0;

    // Sections in __TEXT
    auto* sect_ptr = reinterpret_cast<macho::Section64*>(reinterpret_cast<std::byte*>(seg_text) + sizeof(macho::SegmentCommand64));

    // __text section
    auto* sect_text = sect_ptr;
    std::memcpy(sect_text->sectname, "__text", 6);
    std::memcpy(sect_text->segname, "__TEXT", 6);
    sect_text->addr = 0x100001000;
    sect_text->size = 0x1000;
    sect_text->offset = 0x1000;
    sect_text->align = 4; // 16-byte aligned
    sect_text->flags = macho::S_REGULAR | macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS;

    // __stubs section
    auto* sect_stubs = sect_ptr + 1;
    std::memcpy(sect_stubs->sectname, "__stubs", 7);
    std::memcpy(sect_stubs->segname, "__TEXT", 6);
    sect_stubs->addr = 0x100002000;
    sect_stubs->size = 0x100;
    sect_stubs->offset = 0x2000;
    sect_stubs->align = 2; // 4-byte aligned
    sect_stubs->flags = macho::S_SYMBOL_STUBS | macho::S_ATTR_PURE_INSTRUCTIONS;

    // LC_SEGMENT_64: __DATA
    auto* seg_data = reinterpret_cast<macho::SegmentCommand64*>(reinterpret_cast<std::byte*>(seg_text) + seg_text->cmdsize);
    seg_data->cmd = macho::LC_SEGMENT_64;
    seg_data->cmdsize = sizeof(macho::SegmentCommand64);
    std::memcpy(seg_data->segname, "__DATA", 6);
    seg_data->vmaddr = 0x100003000;
    seg_data->vmsize = 0x1000;
    seg_data->fileoff = 0x3000;
    seg_data->filesize = 0x1000;
    seg_data->maxprot = 7;
    seg_data->initprot = 3; // RW
    seg_data->nsects = 0;
    seg_data->flags = 0;

    // LC_SYMTAB - place symtab and strtab after the segments
    // text: 0x1000-0x3000 (0x2000 bytes)
    // data: 0x3000-0x4000 (0x1000 bytes)
    // symtab at 0x4000, strtab at 0x4100
    auto* symtab = reinterpret_cast<macho::SymtabCommand*>(reinterpret_cast<std::byte*>(seg_data) + sizeof(macho::SegmentCommand64));
    symtab->cmd = macho::LC_SYMTAB;
    symtab->cmdsize = sizeof(macho::SymtabCommand);
    symtab->symoff = 0x4000;
    symtab->nsyms = 2;
    symtab->stroff = 0x4100;
    symtab->strsize = 64;

    // LC_DYSYMTAB
    auto* dysymtab = reinterpret_cast<macho::DysymtabCommand*>(reinterpret_cast<std::byte*>(symtab) + sizeof(macho::SymtabCommand));
    dysymtab->cmd = macho::LC_DYSYMTAB;
    dysymtab->cmdsize = sizeof(macho::DysymtabCommand);
    dysymtab->ilocalsym = 0;
    dysymtab->nlocalsym = 1;
    dysymtab->iextdefsym = 1;
    dysymtab->nextdefsym = 1;
    dysymtab->iundefsym = 0;
    dysymtab->nundefsym = 0;

    // LC_UUID
    auto* uuid = reinterpret_cast<macho::UuidCommand*>(reinterpret_cast<std::byte*>(dysymtab) + sizeof(macho::DysymtabCommand));
    uuid->cmd = macho::LC_UUID;
    uuid->cmdsize = sizeof(macho::UuidCommand);
    for (int i = 0; i < 16; ++i) uuid->uuid[i] = static_cast<uint8_t>(i + 1);

    // LC_MAIN
    auto* main_cmd = reinterpret_cast<macho::MainCommand*>(reinterpret_cast<std::byte*>(uuid) + sizeof(macho::UuidCommand));
    main_cmd->cmd = macho::LC_MAIN;
    main_cmd->cmdsize = sizeof(macho::MainCommand);
    main_cmd->entryoff = 0x1000; // Offset from __TEXT base
    main_cmd->stacksize = 0x20000;

    // Symbol table at 0x4000
    auto* symtab_data = reinterpret_cast<macho::Nlist64*>(ptr + 0x4000);
    // Local symbol
    symtab_data[0].n_strx = 0;
    symtab_data[0].n_type = macho::N_SECT | macho::N_EXT;
    symtab_data[0].n_sect = 1; // __text
    symtab_data[0].n_desc = 0;
    symtab_data[0].n_value = 0x100001000;

    // External symbol
    symtab_data[1].n_strx = 1; // Points to "_main" in strtab
    symtab_data[1].n_type = macho::N_SECT | macho::N_EXT;
    symtab_data[1].n_sect = 1;
    symtab_data[1].n_desc = 0;
    symtab_data[1].n_value = 0x100001000;

    // String table at 0x4100
    auto* strtab = ptr + 0x4100;
    strtab[0] = std::byte{0}; // Empty string for index 0
    std::memcpy(strtab + 1, "_main\0", 6);

    // Fill __text with NOPs
    std::memset(ptr + 0x1000, 0x90, 0x1000);

    return data;
}

static std::vector<std::byte> create_minimal_macho32() {
    std::vector<std::byte> data(4096, std::byte{0});
    auto* ptr = data.data();

    auto* hdr = reinterpret_cast<macho::MachHeader*>(ptr);
    hdr->magic = macho::MH_MAGIC;
    hdr->cputype = macho::CPU_TYPE_X86;
    hdr->cpusubtype = macho::CPU_SUBTYPE_X86_ALL;
    hdr->filetype = macho::MH_EXECUTE;
    hdr->ncmds = 2;
    hdr->sizeofcmds = sizeof(macho::SegmentCommand) + sizeof(macho::Section) * 1 + sizeof(macho::SymtabCommand);
    hdr->flags = macho::MH_NOUNDEFS | macho::MH_DYLDLINK;

    auto* lc_ptr = ptr + sizeof(macho::MachHeader);

    // LC_SEGMENT: __TEXT
    auto* seg = reinterpret_cast<macho::SegmentCommand*>(lc_ptr);
    seg->cmd = macho::LC_SEGMENT;
    seg->cmdsize = sizeof(macho::SegmentCommand) + sizeof(macho::Section);
    std::memcpy(seg->segname, "__TEXT", 6);
    seg->vmaddr = 0x1000;
    seg->vmsize = 0x1000;
    seg->fileoff = 0x1000;
    seg->filesize = 0x1000;
    seg->maxprot = 7;
    seg->initprot = 5;
    seg->nsects = 1;
    seg->flags = 0;

    // Section
    auto* sect = reinterpret_cast<macho::Section*>(reinterpret_cast<std::byte*>(seg) + sizeof(macho::SegmentCommand));
    std::memcpy(sect->sectname, "__text", 6);
    std::memcpy(sect->segname, "__TEXT", 6);
    sect->addr = 0x2000;
    sect->size = 0x1000;
    sect->offset = 0x1000;
    sect->align = 4;
    sect->flags = macho::S_REGULAR | macho::S_ATTR_PURE_INSTRUCTIONS;

    // LC_SYMTAB
    auto* symtab = reinterpret_cast<macho::SymtabCommand*>(reinterpret_cast<std::byte*>(seg) + seg->cmdsize);
    symtab->cmd = macho::LC_SYMTAB;
    symtab->cmdsize = sizeof(macho::SymtabCommand);
    symtab->symoff = 0x4000;
    symtab->nsyms = 1;
    symtab->stroff = 0x4100;
    symtab->strsize = 32;

    // Symbol table
    auto* sym = reinterpret_cast<macho::Nlist*>(ptr + 0x4000);
    sym[0].n_strx = 1;
    sym[0].n_type = macho::N_SECT | macho::N_EXT;
    sym[0].n_sect = 1;
    sym[0].n_desc = 0;
    sym[0].n_value = 0x2000;

    // String table
    auto* strtab = ptr + 0x4100;
    strtab[0] = std::byte{0};
    std::memcpy(strtab + 1, "_start\0", 7);

    std::memset(ptr + 0x1000, 0x90, 0x1000);

    return data;
}

TEST(MachOParser, ParseMachO64) {
    auto macho_data = create_minimal_macho64();
    macho::MachOParser parser;
    auto result = parser.parse(macho_data);

    ASSERT_TRUE(result) << "Mach-O 64 parse failed: " << result.error().to_string();

    auto& analysis = result.value();
    EXPECT_EQ(analysis.format, BinaryFormat::MachO);
    EXPECT_EQ(analysis.architecture, Architecture::X64);
    EXPECT_TRUE(analysis.is_64bit);
    EXPECT_EQ(analysis.os_abi, "macos");
    EXPECT_EQ(analysis.entry_point, 0x100001000); // __TEXT base + entryoff
    EXPECT_GE(analysis.sections.size(), 2); // __text, __stubs
}

TEST(MachOParser, ParseMachO32) {
    auto macho_data = create_minimal_macho32();
    macho::MachOParser parser;
    auto result = parser.parse(macho_data);

    ASSERT_TRUE(result) << "Mach-O 32 parse failed: " << result.error().to_string();

    auto& analysis = result.value();
    EXPECT_EQ(analysis.format, BinaryFormat::MachO);
    EXPECT_EQ(analysis.architecture, Architecture::X86);
    EXPECT_TRUE(analysis.is_32bit);
}

TEST(MachOParser, InvalidMagic) {
    std::vector<std::byte> data(64, std::byte{0});
    // No Mach-O magic

    macho::MachOParser parser;
    auto result = parser.parse(data);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidBinaryFormat);
}

TEST(MachOParser, SectionPermissions) {
    auto macho_data = create_minimal_macho64();
    macho::MachOParser parser;
    auto result = parser.parse(macho_data);
    ASSERT_TRUE(result);

    auto& analysis = result.value();
    bool found_text = false;
    for (const auto& sec : analysis.sections) {
        if (sec.name.find("__text") != std::string::npos) {
            found_text = true;
            EXPECT_TRUE(sec.is_executable());
            EXPECT_FALSE(sec.is_writable());
        }
    }
    EXPECT_TRUE(found_text);
}

TEST(MachOParser, UUID) {
    auto macho_data = create_minimal_macho64();
    macho::MachOParser parser;
    auto result = parser.parse(macho_data);
    ASSERT_TRUE(result);

    auto& analysis = result.value();
    EXPECT_TRUE(analysis.debug_info.has_debug_symbols);
    EXPECT_FALSE(analysis.debug_info.build_id.empty());
    EXPECT_EQ(analysis.debug_info.build_id.length(), 36); // UUID with dashes
}

TEST(MachOParser, EntryPoint) {
    auto macho_data = create_minimal_macho64();
    macho::MachOParser parser;
    auto result = parser.parse(macho_data);
    ASSERT_TRUE(result);

    auto& analysis = result.value();
    // Entry point should be __TEXT base (0x100000000) + entryoff (0x1000) = 0x100001000
    EXPECT_EQ(analysis.entry_point, 0x100001000);
}

TEST(MachOParser, Functions) {
    auto macho_data = create_minimal_macho64();
    macho::MachOParser parser;
    auto result = parser.parse(macho_data);
    ASSERT_TRUE(result);

    auto& analysis = result.value();
    // Should find entry point function and symbol table function
    EXPECT_GE(analysis.functions.size(), 1);

    // Check for main/entry function
    bool has_entry = false;
    for (const auto& fn : analysis.functions) {
        if (fn.address == 0x100001000) {
            has_entry = true;
            EXPECT_EQ(fn.source, FunctionSource::EntryPoint);
        }
    }
    EXPECT_TRUE(has_entry);
}