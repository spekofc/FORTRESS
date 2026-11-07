// FORTRESS PE Parser Tests

#include <fortress/binary/formats/pe/pe_parser.h>
#include <fortress/core/file_utils.h>
#include <gtest/gtest.h>

using namespace fortress;

static std::vector<std::byte> create_minimal_pe32() {
    std::vector<std::byte> data(512, std::byte{0});
    auto* ptr = data.data();

    // DOS Header
    auto* dos = reinterpret_cast<pe::DOSHeader*>(ptr);
    dos->e_magic = pe::DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    // PE Signature
    ptr[0x80] = std::byte{'P'};
    ptr[0x81] = std::byte{'E'};
    ptr[0x82] = std::byte{0x00};
    ptr[0x83] = std::byte{0x00};

    // COFF Header
    auto* coff = reinterpret_cast<pe::COFFHeader*>(ptr + 0x84);
    coff->machine = pe::MACHINE_I386;
    coff->number_of_sections = 1;
    coff->time_date_stamp = 0x12345678;
    coff->size_of_optional_header = sizeof(pe::OptionalHeader32);
    coff->characteristics = 0x010F; // Executable, 32-bit, no line nums, no symbols

    // Optional Header (PE32)
    auto* opt = reinterpret_cast<pe::OptionalHeader32*>(ptr + 0x84 + sizeof(pe::COFFHeader));
    opt->magic = 0x10B; // PE32
    opt->major_linker_version = 14;
    opt->minor_linker_version = 0;
    opt->size_of_code = 0x1000;
    opt->size_of_initialized_data = 0x1000;
    opt->size_of_uninitialized_data = 0;
    opt->address_of_entry_point = 0x1000;
    opt->base_of_code = 0x1000;
    opt->base_of_data = 0x2000;
    opt->image_base = 0x00400000;
    opt->section_alignment = 0x1000;
    opt->file_alignment = 0x200;
    opt->major_operating_system_version = 6;
    opt->minor_operating_system_version = 0;
    opt->major_image_version = 1;
    opt->minor_image_version = 0;
    opt->major_subsystem_version = 6;
    opt->minor_subsystem_version = 0;
    opt->size_of_image = 0x3000;
    opt->size_of_headers = 0x200;
    opt->subsystem = pe::SUBSYSTEM_WINDOWS_CUI;
    opt->dll_characteristics = pe::DLL_DYNAMIC_BASE | pe::DLL_NX_COMPAT;
    opt->size_of_stack_reserve = 0x100000;
    opt->size_of_stack_commit = 0x1000;
    opt->size_of_heap_reserve = 0x100000;
    opt->size_of_heap_commit = 0x1000;
    opt->number_of_rva_and_sizes = 16;

    // Data directories (16 * 8 bytes = 128 bytes)
    auto* dirs = reinterpret_cast<pe::DataDirectory*>(reinterpret_cast<std::byte*>(opt) + sizeof(pe::OptionalHeader32));
    // Export directory
    dirs[pe::DIRECTORY_EXPORT].virtual_address = 0x2000;
    dirs[pe::DIRECTORY_EXPORT].size = 0x100;
    // Import directory
    dirs[pe::DIRECTORY_IMPORT].virtual_address = 0x2100;
    dirs[pe::DIRECTORY_IMPORT].size = 0x100;

    // Section Header
    auto* sect = reinterpret_cast<pe::SectionHeader*>(reinterpret_cast<std::byte*>(dirs) + 16 * sizeof(pe::DataDirectory));
    std::memcpy(sect->name, ".text", 5);
    sect->virtual_size = 0x1000;
    sect->virtual_address = 0x1000;
    sect->size_of_raw_data = 0x200;
    sect->pointer_to_raw_data = 0x200;
    sect->characteristics = pe::SECTION_MEM_READ | pe::SECTION_MEM_EXECUTE | pe::SECTION_CNT_CODE;

    // Fill section data
    std::memset(ptr + 0x200, 0x90, 0x200); // NOPs

    // Export directory
    auto* exp = reinterpret_cast<pe::ExportDirectory*>(ptr + 0x200 + 0x2000 - 0x1000); // RVA 0x2000
    exp->name_rva = 0x2040;
    exp->ordinal_base = 1;
    exp->number_of_functions = 1;
    exp->number_of_names = 1;
    exp->address_of_functions = 0x2050;
    exp->address_of_names = 0x2060;
    exp->address_of_name_ordinals = 0x2070;

    // Export data
    uint32_t* func_rva = reinterpret_cast<uint32_t*>(ptr + 0x200 + 0x2050 - 0x1000);
    *func_rva = 0x1000; // RVA of function

    uint32_t* name_rva = reinterpret_cast<uint32_t*>(ptr + 0x200 + 0x2060 - 0x1000);
    *name_rva = 0x2080;

    uint16_t* ordinal = reinterpret_cast<uint16_t*>(ptr + 0x200 + 0x2070 - 0x1000);
    *ordinal = 0;

    // Export name
    std::memcpy(ptr + 0x200 + 0x2080 - 0x1000, "TestFunction", 13);

    // DLL name
    std::memcpy(ptr + 0x200 + 0x2040 - 0x1000, "test.dll", 9);

    return data;
}

static std::vector<std::byte> create_minimal_pe64() {
    std::vector<std::byte> data(1024, std::byte{0});
    auto* ptr = data.data();

    // DOS Header
    auto* dos = reinterpret_cast<pe::DOSHeader*>(ptr);
    dos->e_magic = pe::DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    // PE Signature
    ptr[0x80] = std::byte{'P'};
    ptr[0x81] = std::byte{'E'};
    ptr[0x82] = std::byte{0x00};
    ptr[0x83] = std::byte{0x00};

    // COFF Header
    auto* coff = reinterpret_cast<pe::COFFHeader*>(ptr + 0x84);
    coff->machine = pe::MACHINE_AMD64;
    coff->number_of_sections = 1;
    coff->time_date_stamp = 0x12345678;
    coff->size_of_optional_header = sizeof(pe::OptionalHeader64);
    coff->characteristics = 0x010F;

    // Optional Header (PE32+)
    auto* opt = reinterpret_cast<pe::OptionalHeader64*>(ptr + 0x84 + sizeof(pe::COFFHeader));
    opt->magic = 0x20B; // PE32+
    opt->major_linker_version = 14;
    opt->minor_linker_version = 0;
    opt->size_of_code = 0x1000;
    opt->size_of_initialized_data = 0x1000;
    opt->size_of_uninitialized_data = 0;
    opt->address_of_entry_point = 0x1000;
    opt->base_of_code = 0x1000;
    opt->image_base = 0x00007FF600000000;
    opt->section_alignment = 0x1000;
    opt->file_alignment = 0x200;
    opt->major_operating_system_version = 10;
    opt->minor_operating_system_version = 0;
    opt->major_image_version = 1;
    opt->minor_image_version = 0;
    opt->major_subsystem_version = 10;
    opt->minor_subsystem_version = 0;
    opt->size_of_image = 0x3000;
    opt->size_of_headers = 0x400;
    opt->subsystem = pe::SUBSYSTEM_WINDOWS_CUI;
    opt->dll_characteristics = pe::DLL_HIGH_ENTROPY_VA | pe::DLL_DYNAMIC_BASE | pe::DLL_NX_COMPAT;
    opt->size_of_stack_reserve = 0x100000;
    opt->size_of_stack_commit = 0x1000;
    opt->size_of_heap_reserve = 0x100000;
    opt->size_of_heap_commit = 0x1000;
    opt->number_of_rva_and_sizes = 16;

    // Data directories
    auto* dirs = reinterpret_cast<pe::DataDirectory*>(reinterpret_cast<std::byte*>(opt) + sizeof(pe::OptionalHeader64));

    // Section Header
    auto* sect = reinterpret_cast<pe::SectionHeader*>(reinterpret_cast<std::byte*>(dirs) + 16 * sizeof(pe::DataDirectory));
    std::memcpy(sect->name, ".text", 5);
    sect->virtual_size = 0x1000;
    sect->virtual_address = 0x1000;
    sect->size_of_raw_data = 0x200;
    sect->pointer_to_raw_data = 0x400;
    sect->characteristics = pe::SECTION_MEM_READ | pe::SECTION_MEM_EXECUTE | pe::SECTION_CNT_CODE;

    // Fill section data
    std::memset(ptr + 0x400, 0x90, 0x200); // NOPs

    return data;
}

TEST(PEParser, ParsePE32) {
    auto pe_data = create_minimal_pe32();
    pe::PEParser parser;
    auto result = parser.parse(pe_data);

    ASSERT_TRUE(result) << "PE32 parse failed: " << result.error().to_string();

    auto& analysis = result.value();
    EXPECT_EQ(analysis.format, BinaryFormat::PE);
    EXPECT_EQ(analysis.architecture, Architecture::X86);
    EXPECT_TRUE(analysis.is_32bit);
    EXPECT_FALSE(analysis.is_64bit);
    EXPECT_EQ(analysis.entry_point, 0x00401000);
    EXPECT_EQ(analysis.sections.size(), 1);
    EXPECT_EQ(analysis.sections[0].name, ".text");
    EXPECT_TRUE(analysis.sections[0].is_executable());
    EXPECT_FALSE(analysis.sections[0].is_writable());
    EXPECT_EQ(analysis.total_sections, 1);
}

TEST(PEParser, ParsePE64) {
    auto pe_data = create_minimal_pe64();
    pe::PEParser parser;
    auto result = parser.parse(pe_data);

    ASSERT_TRUE(result) << "PE64 parse failed: " << result.error().to_string();

    auto& analysis = result.value();
    EXPECT_EQ(analysis.format, BinaryFormat::PE);
    EXPECT_EQ(analysis.architecture, Architecture::X64);
    EXPECT_TRUE(analysis.is_64bit);
    EXPECT_FALSE(analysis.is_32bit);
    EXPECT_EQ(analysis.entry_point, 0x00007FF600001000);
    EXPECT_EQ(analysis.sections.size(), 1);
}

TEST(PEParser, InvalidSignature) {
    std::vector<std::byte> data(100, std::byte{0});
    data[0] = std::byte{'M'};
    data[1] = std::byte{'Z'};
    // No PE signature

    pe::PEParser parser;
    auto result = parser.parse(data);
    EXPECT_FALSE(result);
    EXPECT_EQ(result.error().code(), ErrorCode::InvalidBinaryFormat);
}

TEST(PEParser, TruncatedHeader) {
    std::vector<std::byte> data(50, std::byte{0});
    data[0] = std::byte{'M'};
    data[1] = std::byte{'Z'};

    pe::PEParser parser;
    auto result = parser.parse(data);
    EXPECT_FALSE(result);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}