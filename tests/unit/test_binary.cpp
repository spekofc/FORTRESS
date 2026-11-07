// FORTRESS Binary Analysis Tests

#include <fortress/binary/analysis/analyzer.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/file_utils.h>
#include <gtest/gtest.h>

using namespace fortress;

TEST(BinaryAnalyzer, DetectPE) {
    // Create a minimal PE-like header
    std::vector<std::byte> data(0x100, std::byte{0});
    // MZ signature
    data[0] = std::byte{'M'};
    data[1] = std::byte{'Z'};
    // e_lfanew at offset 0x3C
    data[0x3C] = std::byte{0x40};
    data[0x3D] = std::byte{0x00};
    data[0x3E] = std::byte{0x00};
    data[0x3F] = std::byte{0x00};
    // PE signature at offset 0x40
    data[0x40] = std::byte{'P'};
    data[0x41] = std::byte{'E'};
    data[0x42] = std::byte{0x00};
    data[0x43] = std::byte{0x00};

    auto fmt = BinaryAnalyzer::detect_format(data);
    ASSERT_TRUE(fmt);
    EXPECT_EQ(fmt.value(), BinaryFormat::PE);
}

TEST(BinaryAnalyzer, DetectELF) {
    std::vector<std::byte> data(64, std::byte{0});
    // ELF magic
    data[0] = std::byte{0x7F};
    data[1] = std::byte{'E'};
    data[2] = std::byte{'L'};
    data[3] = std::byte{'F'};
    data[4] = std::byte{2}; // 64-bit
    data[5] = std::byte{1}; // Little endian

    auto fmt = BinaryAnalyzer::detect_format(data);
    ASSERT_TRUE(fmt);
    EXPECT_EQ(fmt.value(), BinaryFormat::ELF);
}

TEST(BinaryAnalyzer, DetectMachO32) {
    std::vector<std::byte> data(64, std::byte{0});
    // MH_MAGIC (little endian)
    data[0] = std::byte{0xFE};
    data[1] = std::byte{0xED};
    data[2] = std::byte{0xFA};
    data[3] = std::byte{0xCE};

    auto fmt = BinaryAnalyzer::detect_format(data);
    ASSERT_TRUE(fmt);
    EXPECT_EQ(fmt.value(), BinaryFormat::MachO);
}

TEST(BinaryAnalyzer, DetectMachO64) {
    std::vector<std::byte> data(64, std::byte{0});
    // MH_MAGIC_64
    data[0] = std::byte{0xFE};
    data[1] = std::byte{0xED};
    data[2] = std::byte{0xFA};
    data[3] = std::byte{0xCF};

    auto fmt = BinaryAnalyzer::detect_format(data);
    ASSERT_TRUE(fmt);
    EXPECT_EQ(fmt.value(), BinaryFormat::MachO);
}

TEST(BinaryAnalyzer, DetectFatMachO) {
    std::vector<std::byte> data(64, std::byte{0});
    // FAT_MAGIC
    data[0] = std::byte{0xCA};
    data[1] = std::byte{0xFE};
    data[2] = std::byte{0xBA};
    data[3] = std::byte{0xBE};

    auto fmt = BinaryAnalyzer::detect_format(data);
    ASSERT_TRUE(fmt);
    EXPECT_EQ(fmt.value(), BinaryFormat::MachO);
}

TEST(BinaryAnalyzer, SupportedFormats) {
    auto formats = BinaryAnalyzer::supported_formats();
    EXPECT_EQ(formats.size(), 3);
    EXPECT_TRUE(std::find(formats.begin(), formats.end(), BinaryFormat::PE) != formats.end());
    EXPECT_TRUE(std::find(formats.begin(), formats.end(), BinaryFormat::ELF) != formats.end());
    EXPECT_TRUE(std::find(formats.begin(), formats.end(), BinaryFormat::MachO) != formats.end());
}

TEST(BinaryAnalyzer, SupportedArchitectures) {
    auto archs = BinaryAnalyzer::supported_architectures();
    EXPECT_GE(archs.size(), 4);
    EXPECT_TRUE(std::find(archs.begin(), archs.end(), Architecture::X86) != archs.end());
    EXPECT_TRUE(std::find(archs.begin(), archs.end(), Architecture::X64) != archs.end());
    EXPECT_TRUE(std::find(archs.begin(), archs.end(), Architecture::ARM64) != archs.end());
}

TEST(BinaryInfo, SectionPermissions) {
    SectionInfo sec;
    sec.permissions = SectionPermission::Read | SectionPermission::Execute;

    EXPECT_TRUE(sec.is_executable());
    EXPECT_FALSE(sec.is_writable());
    EXPECT_TRUE(sec.is_readable());
    EXPECT_TRUE(sec.is_code());
    EXPECT_FALSE(sec.is_data());
}

TEST(BinaryInfo, FunctionConfidence) {
    FunctionInfo fn;
    fn.confidence = ConfidenceLevel::Confirmed;
    EXPECT_EQ(to_string(fn.confidence), "confirmed");

    fn.confidence = ConfidenceLevel::High;
    EXPECT_EQ(to_string(fn.confidence), "high");

    fn.confidence = ConfidenceLevel::Medium;
    EXPECT_EQ(to_string(fn.confidence), "medium");

    fn.confidence = ConfidenceLevel::Low;
    EXPECT_EQ(to_string(fn.confidence), "low");
}

TEST(BinaryInfo, FunctionSource) {
    FunctionInfo fn;
    fn.source = FunctionSource::ExportTable;
    EXPECT_EQ(to_string(fn.source), "export_table");

    fn.source = FunctionSource::SymbolTable;
    EXPECT_EQ(to_string(fn.source), "symbol_table");

    fn.source = FunctionSource::Disassembly;
    EXPECT_EQ(to_string(fn.source), "disassembly");

    fn.source = FunctionSource::Heuristic;
    EXPECT_EQ(to_string(fn.source), "heuristic");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}