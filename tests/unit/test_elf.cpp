// FORTRESS ELF Parser Tests

#include <fortress/binary/formats/elf/elf_parser.h>
#include <gtest/gtest.h>
#include <cstring>

using namespace fortress;

static std::vector<std::byte> create_minimal_elf64() {
    std::vector<std::byte> data(1024, std::byte{0});
    auto* ptr = data.data();

    // ELF Header
    auto* ehdr = reinterpret_cast<elf::Ehdr64*>(ptr);
    ehdr->e_ident[0] = 0x7F;
    ehdr->e_ident[1] = 'E';
    ehdr->e_ident[2] = 'L';
    ehdr->e_ident[3] = 'F';
    ehdr->e_ident[4] = elf::ELFCLASS64;
    ehdr->e_ident[5] = elf::ELFDATA2LSB;
    ehdr->e_ident[6] = 1; // Version
    ehdr->e_ident[7] = elf::ELFOSABI_LINUX;
    ehdr->e_type = elf::ET_EXEC;
    ehdr->e_machine = elf::EM_X86_64;
    ehdr->e_version = 1;
    ehdr->e_entry = 0x401000;
    ehdr->e_phoff = sizeof(elf::Ehdr64);
    ehdr->e_shoff = 512; // After program headers
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(elf::Ehdr64);
    ehdr->e_phentsize = sizeof(elf::Phdr64);
    ehdr->e_phnum = 2;
    ehdr->e_shentsize = sizeof(elf::Shdr64);
    ehdr->e_shnum = 4;
    ehdr->e_shstrndx = 3;

    // Program Headers
    auto* phdrs = reinterpret_cast<elf::Phdr64*>(ptr + sizeof(elf::Ehdr64));

    // PHDR 0: Load .text
    phdrs[0].p_type = 1; // PT_LOAD
    phdrs[0].p_flags = 5; // PF_R | PF_X
    phdrs[0].p_offset = 0x1000;
    phdrs[0].p_vaddr = 0x400000;
    phdrs[0].p_paddr = 0x400000;
    phdrs[0].p_filesz = 0x1000;
    phdrs[0].p_memsz = 0x1000;
    phdrs[0].p_align = 0x1000;

    // PHDR 1: Load .data
    phdrs[1].p_type = 1; // PT_LOAD
    phdrs[1].p_flags = 6; // PF_R | PF_W
    phdrs[1].p_offset = 0x2000;
    phdrs[1].p_vaddr = 0x402000;
    phdrs[1].p_paddr = 0x402000;
    phdrs[1].p_filesz = 0x1000;
    phdrs[1].p_memsz = 0x1000;
    phdrs[1].p_align = 0x1000;

    // Section Headers at offset 512
    auto* shdrs = reinterpret_cast<elf::Shdr64*>(ptr + 512);

    // SHDR 0: NULL
    shdrs[0].sh_type = elf::SHT_NULL;

    // SHDR 1: .text
    shdrs[1].sh_name = 1; // Will point to ".text" in shstrtab
    shdrs[1].sh_type = elf::SHT_PROGBITS;
    shdrs[1].sh_flags = elf::SHF_ALLOC | elf::SHF_EXECINSTR;
    shdrs[1].sh_addr = 0x401000;
    shdrs[1].sh_offset = 0x1000;
    shdrs[1].sh_size = 0x1000;
    shdrs[1].sh_addralign = 16;

    // SHDR 2: .data
    shdrs[2].sh_name = 7; // ".data"
    shdrs[2].sh_type = elf::SHT_PROGBITS;
    shdrs[2].sh_flags = elf::SHF_ALLOC | elf::SHF_WRITE;
    shdrs[2].sh_addr = 0x402000;
    shdrs[2].sh_offset = 0x2000;
    shdrs[2].sh_size = 0x1000;
    shdrs[2].sh_addralign = 8;

    // SHDR 3: .shstrtab
    shdrs[3].sh_name = 13; // ".shstrtab"
    shdrs[3].sh_type = elf::SHT_STRTAB;
    shdrs[3].sh_flags = 0;
    shdrs[3].sh_addr = 0;
    shdrs[3].sh_offset = 0x3000;
    shdrs[3].sh_size = 64;
    shdrs[3].sh_addralign = 1;

    // Section header string table
    std::string shstrtab = "\0.text\0.data\0.shstrtab\0";
    std::memcpy(ptr + 0x3000, shstrtab.data(), shstrtab.size());

    // Fill .text with NOPs
    std::memset(ptr + 0x1000, 0x90, 0x1000);
    // Fill .data
    std::memset(ptr + 0x2000, 0x00, 0x1000);

    return data;
}

static std::vector<std::byte> create_minimal_elf32() {
    std::vector<std::byte> data(1024, std::byte{0});
    auto* ptr = data.data();

    // ELF Header
    auto* ehdr = reinterpret_cast<elf::Ehdr32*>(ptr);
    ehdr->e_ident[0] = 0x7F;
    ehdr->e_ident[1] = 'E';
    ehdr->e_ident[2] = 'L';
    ehdr->e_ident[3] = 'F';
    ehdr->e_ident[4] = elf::ELFCLASS32;
    ehdr->e_ident[5] = elf::ELFDATA2LSB;
    ehdr->e_ident[6] = 1;
    ehdr->e_ident[7] = elf::ELFOSABI_LINUX;
    ehdr->e_type = elf::ET_EXEC;
    ehdr->e_machine = elf::EM_386;
    ehdr->e_version = 1;
    ehdr->e_entry = 0x08048000;
    ehdr->e_phoff = sizeof(elf::Ehdr32);
    ehdr->e_shoff = 512;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = sizeof(elf::Ehdr32);
    ehdr->e_phentsize = sizeof(elf::Phdr32);
    ehdr->e_phnum = 2;
    ehdr->e_shentsize = sizeof(elf::Shdr32);
    ehdr->e_shnum = 4;
    ehdr->e_shstrndx = 3;

    // Program Headers
    auto* phdrs = reinterpret_cast<elf::Phdr32*>(ptr + sizeof(elf::Ehdr32));
    phdrs[0].p_type = 1;
    phdrs[0].p_flags = 5;
    phdrs[0].p_offset = 0x1000;
    phdrs[0].p_vaddr = 0x08048000;
    phdrs[0].p_paddr = 0x08048000;
    phdrs[0].p_filesz = 0x1000;
    phdrs[0].p_memsz = 0x1000;
    phdrs[0].p_align = 0x1000;

    phdrs[1].p_type = 1;
    phdrs[1].p_flags = 6;
    phdrs[1].p_offset = 0x2000;
    phdrs[1].p_vaddr = 0x08049000;
    phdrs[1].p_paddr = 0x08049000;
    phdrs[1].p_filesz = 0x1000;
    phdrs[1].p_memsz = 0x1000;
    phdrs[1].p_align = 0x1000;

    // Section Headers
    auto* shdrs = reinterpret_cast<elf::Shdr32*>(ptr + 512);
    shdrs[0].sh_type = elf::SHT_NULL;
    shdrs[1].sh_name = 1;
    shdrs[1].sh_type = elf::SHT_PROGBITS;
    shdrs[1].sh_flags = elf::SHF_ALLOC | elf::SHF_EXECINSTR;
    shdrs[1].sh_addr = 0x08048000;
    shdrs[1].sh_offset = 0x1000;
    shdrs[1].sh_size = 0x1000;
    shdrs[1].sh_addralign = 16;

    shdrs[2].sh_name = 7;
    shdrs[2].sh_type = elf::SHT_PROGBITS;
    shdrs[2].sh_flags = elf::SHF_ALLOC | elf::SHF_WRITE;
    shdrs[2].sh_addr = 0x08049000;
    shdrs[2].sh_offset = 0x2000;
    shdrs[2].sh_size = 0x1000;
    shdrs[2].sh_addralign = 8;

    shdrs[3].sh_name = 13;
    shdrs[3].sh_type = elf::SHT_STRTAB;
    shdrs[3].sh_flags = 0;
    shdrs[3].sh_addr = 0;
    shdrs[3].sh_offset = 0x3000;
    shdrs[3].sh_size = 64;
    shdrs[3].sh_addralign = 1;

    std::string shstrtab = "\0.text\0.data\0.shstrtab\0";
    std::memcpy(ptr + 0x3000, shstrtab.data(), shstrtab.size());

    std::memset(ptr + 0x1000, 0x90, 0x1000);
    std::memset(ptr + 0x2000, 0x00, 0x1000);

    return data;
}

TEST(ELFParser, ParseELF64) {
    auto elf_data = create_minimal_elf64();
    elf::ELFParser parser;
    auto result = parser.parse(elf_data);

    ASSERT_TRUE(result) << "ELF64 parse failed: " << result.error().to_string();

    auto& analysis = result.value();
    EXPECT_EQ(analysis.format, BinaryFormat::ELF);
    EXPECT_EQ(analysis.architecture, Architecture::X64);
    EXPECT_TRUE(analysis.is_64bit);
    EXPECT_EQ(analysis.entry_point, 0x401000);
    EXPECT_EQ(analysis.sections.size(), 4); // NULL + .text + .data + .shstrtab
    EXPECT_EQ(analysis.os_abi, "linux");
}

TEST(ELFParser, ParseELF32) {
    auto elf_data = create_minimal_elf32();
    elf::ELFParser parser;
    auto result = parser.parse(elf_data);

    ASSERT_TRUE(result) << "ELF32 parse failed: " << result.error().to_string();

    auto& analysis = result.value();
    EXPECT_EQ(analysis.format, BinaryFormat::ELF);
    EXPECT_EQ(analysis.architecture, Architecture::X86);
    EXPECT_TRUE(analysis.is_32bit);
    EXPECT_EQ(analysis.entry_point, 0x08048000);
}

TEST(ELFParser, InvalidMagic) {
    std::vector<std::byte> data(64, std::byte{0});
    // No ELF magic

    elf::ELFParser parser;
    auto result = parser.parse(data);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidBinaryFormat);
}

TEST(ELFParser, WrongClass) {
    std::vector<std::byte> data(64, std::byte{0});
    data[0] = std::byte{0x7F};
    data[1] = std::byte{'E'};
    data[2] = std::byte{'L'};
    data[3] = std::byte{'F'};
    data[4] = std::byte{99}; // Invalid class

    elf::ELFParser parser;
    auto result = parser.parse(data);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::UnsupportedArchitecture);
}

TEST(ELFParser, BigEndian) {
    std::vector<std::byte> data(64, std::byte{0});
    data[0] = std::byte{0x7F};
    data[1] = std::byte{'E'};
    data[2] = std::byte{'L'};
    data[3] = std::byte{'F'};
    data[4] = std::byte{elf::ELFCLASS64};
    data[5] = std::byte{elf::ELFDATA2MSB}; // Big endian

    elf::ELFParser parser;
    auto result = parser.parse(data);
    // Should parse but warn about big-endian
    // For now, expect it might fail or warn
    if (result) {
        EXPECT_EQ(result.value().endianness, Endianness::Big);
    }
}

TEST(ELFParser, SectionPermissions) {
    auto elf_data = create_minimal_elf64();
    elf::ELFParser parser;
    auto result = parser.parse(elf_data);
    ASSERT_TRUE(result);

    auto& analysis = result.value();
    // Find .text section
    bool found_text = false, found_data = false;
    for (const auto& sec : analysis.sections) {
        if (sec.name == ".text") {
            found_text = true;
            EXPECT_TRUE(sec.is_executable());
            EXPECT_FALSE(sec.is_writable());
            EXPECT_TRUE(sec.is_code());
        }
        if (sec.name == ".data") {
            found_data = true;
            EXPECT_FALSE(sec.is_executable());
            EXPECT_TRUE(sec.is_writable());
            EXPECT_TRUE(sec.is_data());
        }
    }
    EXPECT_TRUE(found_text);
    EXPECT_TRUE(found_data);
}