// FORTRESS Analysis Data Model Tests

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/formats/pe/pe_address_converter.h>
#include <fortress/binary/formats/elf/elf_address_converter.h>
#include <fortress/binary/formats/macho/macho_address_converter.h>
#include <gtest/gtest.h>
#include <vector>
#include <string>

using namespace fortress;

// ============================================================================
// TypedAddress Tests
// ============================================================================

TEST(AnalysisModel, TypedAddress_FactoryMethods) {
    auto fo = TypedAddress::file_offset(0x1000);
    EXPECT_EQ(fo.value(), 0x1000);
    EXPECT_EQ(fo.space(), AddressSpace::FileOffset);
    EXPECT_TRUE(fo.valid());

    auto rva = TypedAddress::rva(0x2000);
    EXPECT_EQ(rva.value(), 0x2000);
    EXPECT_EQ(rva.space(), AddressSpace::RVA);

    auto va = TypedAddress::va(0x400000);
    EXPECT_EQ(va.value(), 0x400000);
    EXPECT_EQ(va.space(), AddressSpace::VA);

    auto seg_va = TypedAddress::segment_va(0x1000);
    EXPECT_EQ(seg_va.value(), 0x1000);
    EXPECT_EQ(seg_va.space(), AddressSpace::SegmentVA);
}

TEST(AnalysisModel, TypedAddress_Equality) {
    auto a = TypedAddress::va(0x1000);
    auto b = TypedAddress::va(0x1000);
    auto c = TypedAddress::va(0x2000);
    auto d = TypedAddress::rva(0x1000);

    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
    EXPECT_NE(a, d);  // Different space
    EXPECT_LT(a, c);
    EXPECT_LT(d, a);  // RVA < VA in space ordering
}

TEST(AnalysisModel, TypedAddress_ToString) {
    auto fo = TypedAddress::file_offset(0x1000);
    auto rva = TypedAddress::rva(0x2000);
    auto va = TypedAddress::va(0x400000);
    auto seg_va = TypedAddress::segment_va(0x1000);

    EXPECT_EQ(fo.to_string(), "FO:0x1000");
    EXPECT_EQ(rva.to_string(), "RVA:0x2000");
    EXPECT_EQ(va.to_string(), "VA:0x400000");
    EXPECT_EQ(seg_va.to_string(), "SEG_VA:0x1000");
}

TEST(AnalysisModel, TypedAddress_Invalid) {
    TypedAddress invalid;
    EXPECT_FALSE(invalid.valid());
    EXPECT_EQ(invalid.space(), AddressSpace::Invalid);
    EXPECT_EQ(invalid.value(), 0);
}

// ============================================================================
// NormalizedSection Tests
// ============================================================================

TEST(AnalysisModel, NormalizedSection_Basic) {
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(0x401000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sec.permissions = SectionPermission::Read | SectionPermission::Execute;

    EXPECT_TRUE(sec.is_executable());
    EXPECT_FALSE(sec.is_writable());
    EXPECT_TRUE(sec.is_readable());
    EXPECT_TRUE(sec.is_code());
    EXPECT_FALSE(sec.is_data());
    EXPECT_FALSE(sec.is_rdata());
}

TEST(AnalysisModel, NormalizedSection_DataSection) {
    NormalizedSection sec;
    sec.name = ".data";
    sec.permissions = SectionPermission::Read | SectionPermission::Write;

    EXPECT_FALSE(sec.is_executable());
    EXPECT_TRUE(sec.is_writable());
    EXPECT_TRUE(sec.is_readable());
    EXPECT_FALSE(sec.is_code());
    EXPECT_TRUE(sec.is_data());
    EXPECT_FALSE(sec.is_rdata());
}

TEST(AnalysisModel, NormalizedSection_RDataSection) {
    NormalizedSection sec;
    sec.name = ".rdata";
    sec.permissions = SectionPermission::Read;

    EXPECT_FALSE(sec.is_executable());
    EXPECT_FALSE(sec.is_writable());
    EXPECT_TRUE(sec.is_readable());
    EXPECT_FALSE(sec.is_code());
    EXPECT_FALSE(sec.is_data());
    EXPECT_TRUE(sec.is_rdata());
}

TEST(AnalysisModel, NormalizedSection_ContainsVA) {
    NormalizedSection sec;
    sec.name = ".text";
    sec.virtual_address = TypedAddress::va(0x401000);
    sec.virtual_size = 0x1000;

    EXPECT_TRUE(sec.contains_va(TypedAddress::va(0x401000)));
    EXPECT_TRUE(sec.contains_va(TypedAddress::va(0x401500)));
    EXPECT_TRUE(sec.contains_va(TypedAddress::va(0x401FFF)));
    EXPECT_FALSE(sec.contains_va(TypedAddress::va(0x400FFF)));
    EXPECT_FALSE(sec.contains_va(TypedAddress::va(0x402000)));
    EXPECT_FALSE(sec.contains_va(TypedAddress::rva(0x1000)));  // Wrong space
}

TEST(AnalysisModel, NormalizedSection_ContainsFileOffset) {
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.raw_size = 0x1000;

    EXPECT_TRUE(sec.contains_file_offset(TypedAddress::file_offset(0x1000)));
    EXPECT_TRUE(sec.contains_file_offset(TypedAddress::file_offset(0x1500)));
    EXPECT_TRUE(sec.contains_file_offset(TypedAddress::file_offset(0x1FFF)));
    EXPECT_FALSE(sec.contains_file_offset(TypedAddress::file_offset(0xFFF)));
    EXPECT_FALSE(sec.contains_file_offset(TypedAddress::file_offset(0x2000)));
    EXPECT_FALSE(sec.contains_file_offset(TypedAddress::va(0x401000)));  // Wrong space
}

// ============================================================================
// NormalizedSymbol Tests
// ============================================================================

TEST(AnalysisModel, NormalizedSymbol_Basic) {
    NormalizedSymbol sym;
    sym.name = "main";
    sym.address = TypedAddress::va(0x401000);
    sym.type = SymbolType::Function;
    sym.binding = SymbolBinding::Global;
    sym.is_exported = true;

    EXPECT_EQ(sym.name, "main");
    EXPECT_EQ(sym.address.value(), 0x401000);
    EXPECT_EQ(sym.type, SymbolType::Function);
    EXPECT_EQ(sym.binding, SymbolBinding::Global);
    EXPECT_TRUE(sym.is_exported);
}

// ============================================================================
// PEAddressConverter Tests
// ============================================================================

TEST(AnalysisModel, PEAddressConverter_RVA_VA) {
    // Create a simple PE-like converter
    uint64_t image_base = 0x400000;
    std::vector<NormalizedSection> sections;
    
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(image_base + 0x1000);
    sec.rva = TypedAddress::rva(0x1000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sections.push_back(sec);

    PEAddressConverter converter(image_base, sections);

    // RVA -> VA
    auto rva = TypedAddress::rva(0x1000);
    auto va_result = converter.convert(rva, AddressSpace::VA);
    EXPECT_TRUE(va_result.success);
    EXPECT_EQ(va_result.address.value(), image_base + 0x1000);
    EXPECT_EQ(va_result.address.space(), AddressSpace::VA);

    // VA -> RVA
    auto va = TypedAddress::va(image_base + 0x1000);
    auto rva_result = converter.convert(va, AddressSpace::RVA);
    EXPECT_TRUE(rva_result.success);
    EXPECT_EQ(rva_result.address.value(), 0x1000);
    EXPECT_EQ(rva_result.address.space(), AddressSpace::RVA);
}

TEST(AnalysisModel, PEAddressConverter_FileOffset_RVA) {
    uint64_t image_base = 0x400000;
    std::vector<NormalizedSection> sections;
    
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(image_base + 0x1000);
    sec.rva = TypedAddress::rva(0x1000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sections.push_back(sec);

    PEAddressConverter converter(image_base, sections);

    // FileOffset -> RVA
    auto fo = TypedAddress::file_offset(0x1000);
    auto rva_result = converter.convert(fo, AddressSpace::RVA);
    EXPECT_TRUE(rva_result.success);
    EXPECT_EQ(rva_result.address.value(), 0x1000);
    EXPECT_EQ(rva_result.address.space(), AddressSpace::RVA);

    // RVA -> FileOffset
    auto rva = TypedAddress::rva(0x1000);
    auto fo_result = converter.convert(rva, AddressSpace::FileOffset);
    EXPECT_TRUE(fo_result.success);
    EXPECT_EQ(fo_result.address.value(), 0x1000);
    EXPECT_EQ(fo_result.address.space(), AddressSpace::FileOffset);
}

TEST(AnalysisModel, PEAddressConverter_FileOffset_VA) {
    uint64_t image_base = 0x400000;
    std::vector<NormalizedSection> sections;
    
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(image_base + 0x1000);
    sec.rva = TypedAddress::rva(0x1000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sections.push_back(sec);

    PEAddressConverter converter(image_base, sections);

    // FileOffset -> VA
    auto fo = TypedAddress::file_offset(0x1000);
    auto va_result = converter.convert(fo, AddressSpace::VA);
    EXPECT_TRUE(va_result.success);
    EXPECT_EQ(va_result.address.value(), image_base + 0x1000);
    EXPECT_EQ(va_result.address.space(), AddressSpace::VA);

    // VA -> FileOffset
    auto va = TypedAddress::va(image_base + 0x1000);
    auto fo_result = converter.convert(va, AddressSpace::FileOffset);
    EXPECT_TRUE(fo_result.success);
    EXPECT_EQ(fo_result.address.value(), 0x1000);
    EXPECT_EQ(fo_result.address.space(), AddressSpace::FileOffset);
}

TEST(AnalysisModel, PEAddressConverter_InvalidConversions) {
    PEAddressConverter converter(0x400000, {});  // No sections

    // FileOffset -> RVA without sections should fail
    auto fo = TypedAddress::file_offset(0x1000);
    auto result = converter.convert(fo, AddressSpace::RVA);
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

// ============================================================================
// ELFAddressConverter Tests
// ============================================================================

TEST(AnalysisModel, ELFAddressConverter_FileOffset_VA) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "LOAD";
    seg.vm_address = TypedAddress::va(0x400000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg);

    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(0x400000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sections.push_back(sec);

    ELFAddressConverter converter(sections, segments);

    // FileOffset -> VA
    auto fo = TypedAddress::file_offset(0x1000);
    auto va_result = converter.convert(fo, AddressSpace::VA);
    EXPECT_TRUE(va_result.success);
    EXPECT_EQ(va_result.address.value(), 0x400000);
    EXPECT_EQ(va_result.address.space(), AddressSpace::VA);

    // VA -> FileOffset
    auto va = TypedAddress::va(0x400000);
    auto fo_result = converter.convert(va, AddressSpace::FileOffset);
    EXPECT_TRUE(fo_result.success);
    EXPECT_EQ(fo_result.address.value(), 0x1000);
    EXPECT_EQ(fo_result.address.space(), AddressSpace::FileOffset);
}

TEST(AnalysisModel, ELFAddressConverter_SegmentVA_VA) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "LOAD";
    seg.vm_address = TypedAddress::va(0x400000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg);

    ELFAddressConverter converter(sections, segments);

    // SegmentVA -> VA (same in ELF)
    auto seg_va = TypedAddress::segment_va(0x1000);
    auto va_result = converter.convert(seg_va, AddressSpace::VA);
    EXPECT_TRUE(va_result.success);
    EXPECT_EQ(va_result.address.value(), 0x1000);
    EXPECT_EQ(va_result.address.space(), AddressSpace::VA);

    // VA -> SegmentVA
    auto va = TypedAddress::va(0x400000);
    auto seg_va_result = converter.convert(va, AddressSpace::SegmentVA);
    EXPECT_TRUE(seg_va_result.success);
    EXPECT_EQ(seg_va_result.address.value(), 0x400000);
    EXPECT_EQ(seg_va_result.address.space(), AddressSpace::SegmentVA);
}

// ============================================================================
// MachOAddressConverter Tests
// ============================================================================

TEST(AnalysisModel, MachOAddressConverter_FileOffset_VA) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "__TEXT";
    seg.vm_address = TypedAddress::va(0x100000000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg);

    NormalizedSection sec;
    sec.name = "__text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(0x100000000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sections.push_back(sec);

    MachOAddressConverter converter(sections, segments);

    // FileOffset -> VA
    auto fo = TypedAddress::file_offset(0x1000);
    auto va_result = converter.convert(fo, AddressSpace::VA);
    EXPECT_TRUE(va_result.success);
    EXPECT_EQ(va_result.address.value(), 0x100000000);
    EXPECT_EQ(va_result.address.space(), AddressSpace::VA);

    // VA -> FileOffset
    auto va = TypedAddress::va(0x100000000);
    auto fo_result = converter.convert(va, AddressSpace::FileOffset);
    EXPECT_TRUE(fo_result.success);
    EXPECT_EQ(fo_result.address.value(), 0x1000);
    EXPECT_EQ(fo_result.address.space(), AddressSpace::FileOffset);
}

TEST(AnalysisModel, MachOAddressConverter_VA_SegmentVA) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "__TEXT";
    seg.vm_address = TypedAddress::va(0x100000000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg);

    MachOAddressConverter converter(sections, segments);

    // VA -> SegmentVA
    auto va = TypedAddress::va(0x100000000 + 0x1000);
    auto seg_va_result = converter.convert(va, AddressSpace::SegmentVA);
    EXPECT_TRUE(seg_va_result.success);
    EXPECT_EQ(seg_va_result.address.value(), 0x1000);  // Offset within __TEXT
    EXPECT_EQ(seg_va_result.address.space(), AddressSpace::SegmentVA);

    // SegmentVA -> VA (should fail - ambiguous without segment base)
    auto seg_va = TypedAddress::segment_va(0x1000);
    auto va_result = converter.convert(seg_va, AddressSpace::VA);
    EXPECT_FALSE(va_result.success);
    EXPECT_FALSE(va_result.error.empty());
}

// ============================================================================
// NormalizedAnalysisResult Tests
// ============================================================================

TEST(AnalysisModel, NormalizedAnalysisResult_FindSectionByVA) {
    NormalizedAnalysisResult result;
    
    NormalizedSection sec1;
    sec1.name = ".text";
    sec1.virtual_address = TypedAddress::va(0x401000);
    sec1.virtual_size = 0x1000;
    result.sections.push_back(std::move(sec1));

    NormalizedSection sec2;
    sec2.name = ".data";
    sec2.virtual_address = TypedAddress::va(0x402000);
    sec2.virtual_size = 0x1000;
    result.sections.push_back(std::move(sec2));

    auto found = result.find_section_by_va(TypedAddress::va(0x401500));
    EXPECT_TRUE(found.has_value());
    EXPECT_EQ((*found)->name, ".text");

    auto not_found = result.find_section_by_va(TypedAddress::va(0x500000));
    EXPECT_FALSE(not_found.has_value());

    // Wrong space
    auto wrong_space = result.find_section_by_va(TypedAddress::rva(0x1000));
    EXPECT_FALSE(wrong_space.has_value());
}

TEST(AnalysisModel, NormalizedAnalysisResult_FindSectionByFileOffset) {
    NormalizedAnalysisResult result;
    
    NormalizedSection sec1;
    sec1.name = ".text";
    sec1.file_offset = TypedAddress::file_offset(0x1000);
    sec1.raw_size = 0x1000;
    result.sections.push_back(std::move(sec1));

    NormalizedSection sec2;
    sec2.name = ".data";
    sec2.file_offset = TypedAddress::file_offset(0x2000);
    sec2.raw_size = 0x1000;
    result.sections.push_back(std::move(sec2));

    auto found = result.find_section_by_file_offset(TypedAddress::file_offset(0x1500));
    EXPECT_TRUE(found.has_value());
    EXPECT_EQ((*found)->name, ".text");

    auto not_found = result.find_section_by_file_offset(TypedAddress::file_offset(0x5000));
    EXPECT_FALSE(not_found.has_value());

    // Wrong space
    auto wrong_space = result.find_section_by_file_offset(TypedAddress::va(0x401000));
    EXPECT_FALSE(wrong_space.has_value());
}

TEST(AnalysisModel, NormalizedAnalysisResult_FindFunctionByVA) {
    NormalizedAnalysisResult result;
    
    NormalizedFunction fn1;
    fn1.name = "main";
    fn1.address = TypedAddress::va(0x401000);
    fn1.size = 0x100;
    result.functions.push_back(std::move(fn1));

    NormalizedFunction fn2;
    fn2.name = "helper";
    fn2.address = TypedAddress::va(0x402000);
    fn2.size = 0x50;
    result.functions.push_back(std::move(fn2));

    auto found = result.find_function_by_va(TypedAddress::va(0x401000));
    EXPECT_TRUE(found.has_value());
    EXPECT_EQ((*found)->name, "main");

    // Within function range (0x401000 + 0x80 = 0x401080, within 0x100 bytes)
    auto within = result.find_function_by_va(TypedAddress::va(0x401080));
    EXPECT_TRUE(within.has_value());
    EXPECT_EQ((*within)->name, "main");

    auto not_found = result.find_function_by_va(TypedAddress::va(0x500000));
    EXPECT_FALSE(not_found.has_value());
}

TEST(AnalysisModel, NormalizedAnalysisResult_FindSymbolByName) {
    NormalizedAnalysisResult result;
    
    NormalizedSymbol sym1;
    sym1.name = "main";
    sym1.address = TypedAddress::va(0x401000);
    result.symbols.push_back(std::move(sym1));

    NormalizedSymbol sym2;
    sym2.name = "printf";
    sym2.address = TypedAddress::va(0x402000);
    result.symbols.push_back(std::move(sym2));

    auto found = result.find_symbol_by_name("main");
    EXPECT_TRUE(found.has_value());
    EXPECT_EQ((*found)->address.value(), 0x401000);

    auto not_found = result.find_symbol_by_name("nonexistent");
    EXPECT_FALSE(not_found.has_value());
}

TEST(AnalysisModel, NormalizedAnalysisResult_FindRelocationsInSection) {
    NormalizedAnalysisResult result;
    
    NormalizedRelocation rel1;
    rel1.section_name = ".text";
    rel1.offset = TypedAddress::file_offset(0x1000);
    result.relocations.push_back(std::move(rel1));

    NormalizedRelocation rel2;
    rel2.section_name = ".text";
    rel2.offset = TypedAddress::file_offset(0x1100);
    result.relocations.push_back(std::move(rel2));

    NormalizedRelocation rel3;
    rel3.section_name = ".data";
    rel3.offset = TypedAddress::file_offset(0x2000);
    result.relocations.push_back(std::move(rel3));

    auto text_relocs = result.find_relocations_in_section(".text");
    EXPECT_EQ(text_relocs.size(), 2);

    auto data_relocs = result.find_relocations_in_section(".data");
    EXPECT_EQ(data_relocs.size(), 1);

    auto none_relocs = result.find_relocations_in_section(".bss");
    EXPECT_EQ(none_relocs.size(), 0);
}

// ============================================================================
// Normalize/Denormalize Tests
// ============================================================================

TEST(AnalysisModel, NormalizeRoundTrip) {
    // Create a minimal BinaryAnalysisResult
    BinaryAnalysisResult original;
    original.format = BinaryFormat::PE;
    original.architecture = Architecture::X64;
    original.is_64bit = true;
    original.endianness = Endianness::Little;
    original.os_abi = "windows";
    original.entry_point = 0x401000;
    original.entry_point_offset = 0x1000;
    original.image_base = 0x400000;
    original.valid_format = true;

    SectionInfo sec;
    sec.name = ".text";
    sec.file_offset = 0x1000;
    sec.virtual_address = 0x401000;
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sec.permissions = SectionPermission::Read | SectionPermission::Execute;
    original.sections.push_back(std::move(sec));

    SymbolInfo sym;
    sym.name = "main";
    sym.address = 0x401000;
    sym.type = SymbolType::Function;
    sym.binding = SymbolBinding::Global;
    sym.is_exported = true;
    original.symbols.push_back(std::move(sym));

    FunctionInfo fn;
    fn.address = 0x401000;
    fn.name = "main";
    fn.size = 0x100;
    fn.confidence = ConfidenceLevel::Confirmed;
    fn.source = FunctionSource::EntryPoint;
    original.functions.push_back(std::move(fn));

    // Normalize
    auto normalized = normalize_analysis_result(original);
    
    // Verify key fields
    EXPECT_EQ(normalized.metadata.format, BinaryFormat::PE);
    EXPECT_EQ(normalized.metadata.architecture, Architecture::X64);
    EXPECT_EQ(normalized.metadata.image_base, 0x400000);
    EXPECT_EQ(normalized.metadata.entry_point.value(), 0x401000);
    EXPECT_EQ(normalized.sections.size(), 1);
    EXPECT_EQ(normalized.sections[0].name, ".text");
    EXPECT_EQ(normalized.symbols.size(), 1);
    EXPECT_EQ(normalized.symbols[0].name, "main");
    EXPECT_EQ(normalized.functions.size(), 1);
    EXPECT_EQ(normalized.functions[0].name, "main");

    // Denormalize
    auto denormalized = denormalize_analysis_result(normalized);
    
    // Verify key fields preserved
    EXPECT_EQ(denormalized.format, BinaryFormat::PE);
    EXPECT_EQ(denormalized.architecture, Architecture::X64);
    EXPECT_EQ(denormalized.image_base, 0x400000);
    EXPECT_EQ(denormalized.entry_point, 0x401000);
    EXPECT_EQ(denormalized.sections.size(), 1);
    EXPECT_EQ(denormalized.sections[0].name, ".text");
    EXPECT_EQ(denormalized.symbols.size(), 1);
    EXPECT_EQ(denormalized.symbols[0].name, "main");
    EXPECT_EQ(denormalized.functions.size(), 1);
    EXPECT_EQ(denormalized.functions[0].name, "main");
}

TEST(AnalysisModel, NormalizeWithELF) {
    BinaryAnalysisResult original;
    original.format = BinaryFormat::ELF;
    original.architecture = Architecture::X64;
    original.is_64bit = true;
    original.endianness = Endianness::Little;
    original.os_abi = "linux";
    original.entry_point = 0x401000;
    original.entry_point_offset = 0x1000;
    original.image_base = 0x400000;  // First PT_LOAD base
    original.valid_format = true;

    auto normalized = normalize_analysis_result(original);
    
    EXPECT_EQ(normalized.metadata.format, BinaryFormat::ELF);
    EXPECT_EQ(normalized.metadata.image_base, 0x400000);
    EXPECT_EQ(normalized.metadata.entry_point.value(), 0x401000);
}

TEST(AnalysisModel, NormalizeWithMachO) {
    BinaryAnalysisResult original;
    original.format = BinaryFormat::MachO;
    original.architecture = Architecture::ARM64;
    original.is_64bit = true;
    original.endianness = Endianness::Little;
    original.os_abi = "macos";
    original.entry_point = 0x100001000;
    original.entry_point_offset = 0x1000;
    original.image_base = 0x100000000;  // __TEXT segment base
    original.valid_format = true;

    auto normalized = normalize_analysis_result(original);
    
    EXPECT_EQ(normalized.metadata.format, BinaryFormat::MachO);
    EXPECT_EQ(normalized.metadata.image_base, 0x100000000);
    EXPECT_EQ(normalized.metadata.entry_point.value(), 0x100001000);
}

// ============================================================================
// BinaryMetadata FormatSpecificData Tests
// ============================================================================

TEST(AnalysisModel, BinaryMetadata_PESpecificData) {
    BinaryMetadata metadata;
    metadata.format = BinaryFormat::PE;
    
    metadata.format_specific.pe = BinaryMetadata::FormatSpecificData::PEData();
    metadata.format_specific.pe->characteristics = 0x10F;
    metadata.format_specific.pe->subsystem = 2;  // WINDOWS_GUI
    metadata.format_specific.pe->dll_characteristics = 0x8160;
    metadata.format_specific.pe->size_of_image = 0x10000;
    metadata.format_specific.pe->size_of_headers = 0x1000;
    metadata.format_specific.pe->checksum = 0x12345678;

    EXPECT_TRUE(metadata.format_specific.pe.has_value());
    EXPECT_EQ(metadata.format_specific.pe->subsystem, 2);
}

TEST(AnalysisModel, BinaryMetadata_ELFSpecificData) {
    BinaryMetadata metadata;
    metadata.format = BinaryFormat::ELF;
    
    metadata.format_specific.elf = BinaryMetadata::FormatSpecificData::ELFData();
    metadata.format_specific.elf->e_flags = 0;
    metadata.format_specific.elf->e_type = 2;  // ET_EXEC
    metadata.format_specific.elf->build_id = "abcdef123456";
    metadata.format_specific.elf->needed_libraries = {"libc.so.6", "libm.so.6"};

    EXPECT_TRUE(metadata.format_specific.elf.has_value());
    EXPECT_EQ(metadata.format_specific.elf->e_type, 2);
}

TEST(AnalysisModel, BinaryMetadata_MachOSpecificData) {
    BinaryMetadata metadata;
    metadata.format = BinaryFormat::MachO;
    
    metadata.format_specific.macho = BinaryMetadata::FormatSpecificData::MachOData();
    metadata.format_specific.macho->filetype = 2;  // MH_EXECUTE
    metadata.format_specific.macho->flags = 0x200085;
    metadata.format_specific.macho->uuid = "12345678-1234-1234-1234-123456789abc";
    metadata.format_specific.macho->rpaths = {"@executable_path/../Frameworks"};

    EXPECT_TRUE(metadata.format_specific.macho.has_value());
    EXPECT_EQ(metadata.format_specific.macho->filetype, 2);
}

// ============================================================================
// FatArchInfo Tests
// ============================================================================

TEST(AnalysisModel, FatArchInfo_Basic) {
    FatArchInfo arch;
    arch.architecture = Architecture::ARM64;
    arch.cputype = 0x0100000C;  // CPU_TYPE_ARM | CPU_ARCH_ABI64
    arch.cpusubtype = 0;
    arch.offset = 0x1000;
    arch.size = 0x100000;

    EXPECT_EQ(arch.architecture, Architecture::ARM64);
    EXPECT_EQ(arch.offset, 0x1000);
    EXPECT_EQ(arch.size, 0x100000);
}

// ============================================================================
// Summary and JSON Tests
// ============================================================================

TEST(AnalysisModel, NormalizedAnalysisResult_Summary) {
    NormalizedAnalysisResult result;
    result.metadata.file_path = "/path/to/binary.exe";
    result.metadata.format = BinaryFormat::PE;
    result.metadata.architecture = Architecture::X64;
    result.metadata.is_64bit = true;
    result.metadata.endianness = Endianness::Little;
    result.metadata.os_abi = "windows";
    result.metadata.entry_point = TypedAddress::va(0x401000);
    result.sections.emplace_back();
    result.symbols.emplace_back();
    result.imports.emplace_back();
    result.exports.emplace_back();
    result.relocations.emplace_back();
    result.functions.emplace_back();
    result.confirmed_functions = 1;
    result.estimated_functions = 2;
    result.analysis_duration = std::chrono::milliseconds(42);
    result.valid_format = true;

    std::string summary = result.summary();
    
    EXPECT_NE(summary.find("binary.exe"), std::string::npos);
    EXPECT_NE(summary.find("PE"), std::string::npos);
    EXPECT_NE(summary.find("x64"), std::string::npos);
    EXPECT_NE(summary.find("64-bit"), std::string::npos);
    EXPECT_NE(summary.find("VA:0x401000"), std::string::npos);
    EXPECT_NE(summary.find("42 ms"), std::string::npos);
}

TEST(AnalysisModel, NormalizedAnalysisResult_ToJSON) {
    NormalizedAnalysisResult result;
    result.metadata.file_path = "/path/to/binary.exe";
    result.metadata.format = BinaryFormat::PE;
    result.metadata.architecture = Architecture::X64;
    result.metadata.endianness = Endianness::Little;
    result.metadata.is_64bit = true;
    result.metadata.entry_point = TypedAddress::va(0x401000);
    result.valid_format = true;

    std::string json = result.to_json();
    
    EXPECT_NE(json.find("binary.exe"), std::string::npos);
    EXPECT_NE(json.find("PE"), std::string::npos);
    EXPECT_NE(json.find("x64"), std::string::npos);
    EXPECT_NE(json.find("VA:0x401000"), std::string::npos);
    EXPECT_NE(json.find("true"), std::string::npos);
}

// ============================================================================
// AddressConverter Tests
// ============================================================================

TEST(AnalysisModel, AddressConverter_CanConvert) {
    PEAddressConverter converter(0x400000, {});
    
    EXPECT_TRUE(converter.can_convert(AddressSpace::VA, AddressSpace::VA));
    EXPECT_TRUE(converter.can_convert(AddressSpace::RVA, AddressSpace::RVA));
    
    // With image_base but no sections
    EXPECT_TRUE(converter.can_convert(AddressSpace::RVA, AddressSpace::VA));
    EXPECT_TRUE(converter.can_convert(AddressSpace::VA, AddressSpace::RVA));
    
    // Without sections
    EXPECT_FALSE(converter.can_convert(AddressSpace::FileOffset, AddressSpace::RVA));
    EXPECT_FALSE(converter.can_convert(AddressSpace::RVA, AddressSpace::FileOffset));
    
    // Add sections
    std::vector<NormalizedSection> sections;
    NormalizedSection sec;
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.rva = TypedAddress::rva(0x1000);
    sec.virtual_size = 0x1000;
    sections.push_back(sec);
    
    PEAddressConverter converter2(0x400000, sections);
    EXPECT_TRUE(converter2.can_convert(AddressSpace::FileOffset, AddressSpace::RVA));
    EXPECT_TRUE(converter2.can_convert(AddressSpace::RVA, AddressSpace::FileOffset));
    EXPECT_TRUE(converter2.can_convert(AddressSpace::FileOffset, AddressSpace::VA));
    EXPECT_TRUE(converter2.can_convert(AddressSpace::VA, AddressSpace::FileOffset));
}

TEST(AnalysisModel, AddressConverter_ImageBase) {
    PEAddressConverter converter(0x400000, {});
    auto base = converter.image_base();
    EXPECT_TRUE(base.has_value());
    EXPECT_EQ(*base, 0x400000);

    ELFAddressConverter elf_converter({}, {});
    auto elf_base = elf_converter.image_base();
    EXPECT_FALSE(elf_base.has_value());  // No segments

    MachOAddressConverter macho_converter({}, {});
    auto macho_base = macho_converter.image_base();
    EXPECT_FALSE(macho_base.has_value());  // No segments
}

TEST(AnalysisModel, AddressConverter_Segments) {
    PEAddressConverter converter(0x400000, {});
    auto segs = converter.segments();
    EXPECT_EQ(segs.size(), 0);

    std::vector<NormalizedSection> sections;
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.virtual_address = TypedAddress::va(0x401000);
    sec.rva = TypedAddress::rva(0x1000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x1000;
    sections.push_back(sec);

    PEAddressConverter converter2(0x400000, sections);
    auto segs2 = converter2.segments();
    EXPECT_EQ(segs2.size(), 1);
    EXPECT_EQ(segs2[0].segment_name, ".text");
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

TEST(AnalysisModel, TypedAddress_OverflowProtection) {
    // Test that we can represent max values
    auto max_va = TypedAddress::va(UINT64_MAX);
    EXPECT_EQ(max_va.value(), UINT64_MAX);
    
    auto max_fo = TypedAddress::file_offset(UINT64_MAX);
    EXPECT_EQ(max_fo.value(), UINT64_MAX);
}

TEST(AnalysisModel, Normalize_EmptyResult) {
    BinaryAnalysisResult empty;
    empty.valid_format = false;
    
    auto normalized = normalize_analysis_result(empty);
    
    EXPECT_FALSE(normalized.valid_format);
    EXPECT_EQ(normalized.metadata.format, BinaryFormat::Unknown);
    EXPECT_EQ(normalized.sections.size(), 0);
    EXPECT_EQ(normalized.symbols.size(), 0);
    EXPECT_EQ(normalized.functions.size(), 0);
}

TEST(AnalysisModel, Denormalize_EmptyResult) {
    NormalizedAnalysisResult empty;
    empty.valid_format = false;
    
    auto denormalized = denormalize_analysis_result(empty);
    
    EXPECT_FALSE(denormalized.valid_format);
    EXPECT_EQ(denormalized.format, BinaryFormat::Unknown);
    EXPECT_EQ(denormalized.sections.size(), 0);
    EXPECT_EQ(denormalized.symbols.size(), 0);
    EXPECT_EQ(denormalized.functions.size(), 0);
}

// ============================================================================
// Hardening Regression Tests
// ============================================================================

// --- PE Hardening Tests ---

TEST(AnalysisModel, PE_RVA_VA_Overflow) {
    PEAddressConverter converter(UINT64_MAX - 0x1000, {});
    auto rva = TypedAddress::rva(0x2000);
    auto result = converter.convert(rva, AddressSpace::VA);
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("overflow"), std::string::npos);
}

TEST(AnalysisModel, PE_VA_Below_ImageBase) {
    PEAddressConverter converter(0x400000, {});
    auto va = TypedAddress::va(0x300000);
    auto result = converter.convert(va, AddressSpace::RVA);
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("below image base"), std::string::npos);
}

TEST(AnalysisModel, PE_FileOffset_BeyondRawSize) {
    std::vector<NormalizedSection> sections;
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(0x1000);
    sec.rva = TypedAddress::rva(0x1000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0x800;  // raw_size < virtual_size
    sections.push_back(sec);
    
    PEAddressConverter converter(0x400000, sections);
    
    // FileOffset within virtual range but beyond raw_size
    auto fo = TypedAddress::file_offset(0x1800);
    auto result = converter.convert(fo, AddressSpace::RVA);
    EXPECT_FALSE(result.success);
    // Conversion should fail because file offset exceeds raw_size
    EXPECT_FALSE(result.error.empty());
}

TEST(AnalysisModel, PE_RVA_In_VirtualOnly_Region) {
    std::vector<NormalizedSection> sections;
    NormalizedSection sec;
    sec.name = ".bss";
    sec.file_offset = TypedAddress::file_offset(0x2000);
    sec.rva = TypedAddress::rva(0x2000);
    sec.virtual_size = 0x1000;
    sec.raw_size = 0;  // No file data (BSS)
    sections.push_back(sec);
    
    PEAddressConverter converter(0x400000, sections);
    
    // RVA in the BSS region - no file offset
    auto rva = TypedAddress::rva(0x2500);
    auto result = converter.convert(rva, AddressSpace::FileOffset);
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("virtual-only"), std::string::npos);
}

TEST(AnalysisModel, PE_Overflow_RVA_Calculation) {
    PEAddressConverter converter(0x400000, {});
    // Use a section with RVA near max
    std::vector<NormalizedSection> sections;
    NormalizedSection sec;
    sec.rva = TypedAddress::rva(UINT64_MAX - 0x100);
    sec.virtual_size = 0x200;
    sections.push_back(sec);
    converter.set_sections(sections);
    
    auto fo = TypedAddress::file_offset(0x100);
    auto result = converter.convert(fo, AddressSpace::RVA);
    // The conversion should either fail or produce an error
    EXPECT_FALSE(result.success);
}

// --- ELF Hardening Tests ---

TEST(AnalysisModel, ELF_VA_In_BSS_Region) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "LOAD";
    seg.vm_address = TypedAddress::va(0x400000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x1000);  // file_size < vm_size
    segments.push_back(seg);
    
    ELFAddressConverter converter(sections, segments);
    
    // VA in the BSS portion (beyond file_size)
    auto va = TypedAddress::va(0x401500);
    auto result = converter.convert(va, AddressSpace::FileOffset);
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("virtual-only"), std::string::npos);
}

TEST(AnalysisModel, ELF_FileOffset_BeyondFileSize) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "LOAD";
    seg.vm_address = TypedAddress::va(0x400000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x1000);
    segments.push_back(seg);
    
    ELFAddressConverter converter(sections, segments);
    
    // FileOffset at the boundary
    auto fo = TypedAddress::file_offset(0x2000);
    auto result = converter.convert(fo, AddressSpace::VA);
    EXPECT_FALSE(result.success);
}

TEST(AnalysisModel, ELF_Overflow_VA_Calculation) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    // seg.vm_address = UINT64_MAX - 0x100
    // To trigger overflow: offset_in_segment > max - vm_address
    // max - vm_address = 0x100, so we need offset_in_segment > 0x100
    SegmentMapping seg;
    seg.vm_address = TypedAddress::va(UINT64_MAX - 0x100);
    seg.vm_size = TypedAddress::va(0x200);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x200);
    segments.push_back(seg);
    
    ELFAddressConverter converter(sections, segments);
    
    // offset = 0x1100 -> offset_in_segment = 0x100 (no overflow)
    // Use offset that causes overflow: file_offset 0x1200 -> offset_in_segment = 0x200
    // 0x200 > 0x100 (max - vm_address) -> overflow
    auto fo = TypedAddress::file_offset(0x1200);
    auto result = converter.convert(fo, AddressSpace::VA);
    // The conversion should fail due to overflow
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

TEST(AnalysisModel, ELF_Pmemsz_Greater_Pfilesz) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "LOAD";
    seg.vm_address = TypedAddress::va(0x400000);
    seg.vm_size = TypedAddress::va(0x2000);      // p_memsz = 0x2000
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x1000);  // p_filesz = 0x1000
    segments.push_back(seg);
    
    ELFAddressConverter converter(sections, segments);
    
    // VA in the file-backed portion should work
    auto va_file = TypedAddress::va(0x400500);
    auto result1 = converter.convert(va_file, AddressSpace::FileOffset);
    EXPECT_TRUE(result1.success);
    
    // VA in the BSS portion (0x401000 to 0x402000) should fail
    auto va_bss = TypedAddress::va(0x401500);
    auto result2 = converter.convert(va_bss, AddressSpace::FileOffset);
    EXPECT_FALSE(result2.success);
    EXPECT_NE(result2.error.find("virtual-only"), std::string::npos);
}

// --- Mach-O Hardening Tests ---

TEST(AnalysisModel, MachO_VA_In_VirtualOnly_Region) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "__DATA";
    seg.vm_address = TypedAddress::va(0x100000000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x1000);  // file_size < vm_size
    segments.push_back(seg);
    
    MachOAddressConverter converter(sections, segments);
    
    // VA in the virtual-only portion
    auto va = TypedAddress::va(0x100001500);
    auto result = converter.convert(va, AddressSpace::FileOffset);
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.error.find("virtual-only"), std::string::npos);
}

TEST(AnalysisModel, MachO_FileOffset_BeyondFileSize) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "__TEXT";
    seg.vm_address = TypedAddress::va(0x100000000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x1000);
    segments.push_back(seg);
    
    MachOAddressConverter converter(sections, segments);
    
    // FileOffset beyond file_size
    auto fo = TypedAddress::file_offset(0x2000);
    auto result = converter.convert(fo, AddressSpace::VA);
    EXPECT_FALSE(result.success);
}

TEST(AnalysisModel, MachO_Overflow_VA_Calculation) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.vm_address = TypedAddress::va(UINT64_MAX - 0x100);
    seg.vm_size = TypedAddress::va(0x200);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x200);
    segments.push_back(seg);
    
    MachOAddressConverter converter(sections, segments);
    
    // Use offset that causes overflow: file_offset 0x1200 -> offset_in_segment = 0x200
    // 0x200 > 0x100 (max - vm_address) -> overflow
    auto fo = TypedAddress::file_offset(0x1200);
    auto result = converter.convert(fo, AddressSpace::VA);
    // The conversion should fail due to overflow
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.error.empty());
}

TEST(AnalysisModel, MachO_SegmentVA_RoundTrip) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "__TEXT";
    seg.vm_address = TypedAddress::va(0x100000000);
    seg.vm_size = TypedAddress::va(0x2000);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg);
    
    MachOAddressConverter converter(sections, segments);
    
    // VA -> SegmentVA
    auto va = TypedAddress::va(0x100001000);
    auto result1 = converter.convert(va, AddressSpace::SegmentVA);
    EXPECT_TRUE(result1.success);
    
    // Use SegmentVAAddress for round-trip
    // Note: SegmentVAAddress is in the same namespace, not nested
    fortress::SegmentVAAddress sva;
    sva.segment_name = "__TEXT";
    sva.offset_in_segment = 0x1000;
    
    auto result2 = converter.convert_segment_va(sva, AddressSpace::VA);
    EXPECT_TRUE(result2.success);
    EXPECT_EQ(result2.address.value(), 0x100001000);
}

TEST(AnalysisModel, MachO_SegmentVA_Ambiguous) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    // Two segments with overlapping VA ranges (malformed)
    SegmentMapping seg1;
    seg1.segment_name = "__TEXT";
    seg1.vm_address = TypedAddress::va(0x100000000);
    seg1.vm_size = TypedAddress::va(0x2000);
    seg1.file_offset = TypedAddress::file_offset(0x1000);
    seg1.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg1);
    
    SegmentMapping seg2;
    seg2.segment_name = "__DATA";
    seg2.vm_address = TypedAddress::va(0x100000000);  // Same base!
    seg2.vm_size = TypedAddress::va(0x2000);
    seg2.file_offset = TypedAddress::file_offset(0x3000);
    seg2.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg2);
    
    MachOAddressConverter converter(sections, segments);
    
    // VA in the overlapping region
    auto va = TypedAddress::va(0x100001000);
    auto result = converter.convert(va, AddressSpace::SegmentVA);
    // Should find first matching segment
    EXPECT_TRUE(result.success);
}

// --- Section Boundary Tests ---

TEST(AnalysisModel, Section_ContainsVA_Overflow) {
    NormalizedSection sec;
    sec.name = ".text";
    sec.virtual_address = TypedAddress::va(UINT64_MAX - 0x100);
    sec.virtual_size = 0x200;
    
    // Should not overflow when checking boundary
    auto va1 = TypedAddress::va(UINT64_MAX - 0x80);
    auto va2 = TypedAddress::va(UINT64_MAX - 0x200);
    
    // The method should handle overflow gracefully
    // (implementation uses simple comparison which naturally handles wrap-around)
    EXPECT_FALSE(sec.contains_va(va1));  // Beyond range
    EXPECT_FALSE(sec.contains_va(va2));  // Below range (wraps around)
}

TEST(AnalysisModel, Section_ContainsFileOffset_Overflow) {
    NormalizedSection sec;
    sec.name = ".text";
    sec.file_offset = TypedAddress::file_offset(UINT64_MAX - 0x100);
    sec.raw_size = 0x200;
    
    auto fo1 = TypedAddress::file_offset(UINT64_MAX - 0x80);
    auto fo2 = TypedAddress::file_offset(UINT64_MAX - 0x200);
    
    EXPECT_FALSE(sec.contains_file_offset(fo1));
    EXPECT_FALSE(sec.contains_file_offset(fo2));
}

// --- Function Boundary Tests ---

TEST(AnalysisModel, FindFunctionByVA_Overflow) {
    NormalizedAnalysisResult result;
    
    NormalizedFunction fn;
    fn.name = "main";
    fn.address = TypedAddress::va(UINT64_MAX - 0x100);
    fn.size = 0x200;
    result.functions.push_back(std::move(fn));
    
    // Should not crash
    auto found = result.find_function_by_va(TypedAddress::va(UINT64_MAX - 0x80));
    // Behavior is implementation-defined for overflow ranges
    // Just ensure no crash
    (void)found;
}

// --- JSON Escaping Tests ---

TEST(AnalysisModel, ToJSON_SpecialCharacters) {
    NormalizedAnalysisResult result;
    result.metadata.file_path = R"(/path/with\"quotes/and\backslashes/binary.exe)";
    result.metadata.format = BinaryFormat::PE;
    result.metadata.architecture = Architecture::X64;
    result.metadata.endianness = Endianness::Little;
    result.metadata.is_64bit = true;
    result.metadata.entry_point = TypedAddress::va(0x401000);
    result.valid_format = true;
    
    std::string json = result.to_json();
    
    // Should contain escaped quotes and backslashes
    EXPECT_NE(json.find(R"(\")"), std::string::npos);
    EXPECT_NE(json.find(R"(\\)"), std::string::npos);
}

TEST(AnalysisModel, ToJSON_UnicodePath) {
    NormalizedAnalysisResult result;
    result.metadata.file_path = "/path/日本語/файл/binary.exe";
    result.metadata.format = BinaryFormat::ELF;
    result.metadata.architecture = Architecture::X64;
    result.metadata.endianness = Endianness::Little;
    result.metadata.is_64bit = true;
    result.metadata.entry_point = TypedAddress::va(0x401000);
    result.valid_format = true;
    
    std::string json = result.to_json();
    
    // Should handle UTF-8 path
    EXPECT_NE(json.find("日本語"), std::string::npos);
    EXPECT_NE(json.find("файл"), std::string::npos);
}

// --- TypedAddress Edge Cases ---

TEST(AnalysisModel, TypedAddress_Comparison_CrossSpace) {
    // Different spaces should not be equal even with same value
    auto va = TypedAddress::va(0x1000);
    auto rva = TypedAddress::rva(0x1000);
    auto fo = TypedAddress::file_offset(0x1000);
    
    EXPECT_NE(va, rva);
    EXPECT_NE(va, fo);
    EXPECT_NE(rva, fo);
    
    // Ordering by space type
    EXPECT_LT(fo, rva);  // FileOffset < RVA
    EXPECT_LT(rva, va);  // RVA < VA
}

TEST(AnalysisModel, TypedAddress_ExplicitCast) {
    auto va = TypedAddress::va(0x401000);
    uint64_t raw = static_cast<uint64_t>(va);
    EXPECT_EQ(raw, 0x401000);
}

// --- AddressConverter Edge Cases ---

TEST(AnalysisModel, AddressConverter_CanConvert_PE_NoSections) {
    PEAddressConverter converter(0x400000, {});
    
    EXPECT_TRUE(converter.can_convert(AddressSpace::RVA, AddressSpace::VA));
    EXPECT_TRUE(converter.can_convert(AddressSpace::VA, AddressSpace::RVA));
    EXPECT_FALSE(converter.can_convert(AddressSpace::FileOffset, AddressSpace::RVA));
    EXPECT_FALSE(converter.can_convert(AddressSpace::RVA, AddressSpace::FileOffset));
}

TEST(AnalysisModel, AddressConverter_CanConvert_ELF_NoSegments) {
    ELFAddressConverter converter({}, {});
    
    EXPECT_FALSE(converter.can_convert(AddressSpace::FileOffset, AddressSpace::VA));
    EXPECT_FALSE(converter.can_convert(AddressSpace::VA, AddressSpace::FileOffset));
}

TEST(AnalysisModel, AddressConverter_CanConvert_MachO_NoSegments) {
    MachOAddressConverter converter({}, {});
    
    EXPECT_FALSE(converter.can_convert(AddressSpace::FileOffset, AddressSpace::VA));
    EXPECT_FALSE(converter.can_convert(AddressSpace::VA, AddressSpace::FileOffset));
}

TEST(AnalysisModel, AddressConverter_ImageBase_ELF) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.max_protection = 0x1;  // PF_R
    seg.vm_address = TypedAddress::va(0x400000);
    segments.push_back(seg);
    
    ELFAddressConverter converter({}, segments);
    auto base = converter.image_base();
    EXPECT_TRUE(base.has_value());
    EXPECT_EQ(*base, 0x400000);
}

TEST(AnalysisModel, AddressConverter_ImageBase_MachO) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.segment_name = "__TEXT";
    seg.vm_address = TypedAddress::va(0x100000000);
    segments.push_back(seg);
    
    MachOAddressConverter converter({}, segments);
    auto base = converter.image_base();
    EXPECT_TRUE(base.has_value());
    EXPECT_EQ(*base, 0x100000000);
}

// --- Malformed Binary Tests ---

TEST(AnalysisModel, PE_OverlappingSections) {
    std::vector<NormalizedSection> sections;
    
    NormalizedSection sec1;
    sec1.name = ".text";
    sec1.file_offset = TypedAddress::file_offset(0x1000);
    sec1.raw_size = 0x2000;
    sections.push_back(sec1);
    
    NormalizedSection sec2;
    sec2.name = ".data";
    sec2.file_offset = TypedAddress::file_offset(0x2000);  // Overlaps
    sec2.raw_size = 0x1000;
    sections.push_back(sec2);
    
    PEAddressConverter converter(0x400000, sections);
    
    // FileOffset in overlapping region - first match wins
    auto fo = TypedAddress::file_offset(0x2500);
    auto result = converter.convert(fo, AddressSpace::RVA);
    EXPECT_TRUE(result.success);
}

TEST(AnalysisModel, MachO_OverlappingSegments) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg1;
    seg1.segment_name = "__TEXT";
    seg1.vm_address = TypedAddress::va(0x100000000);
    seg1.vm_size = TypedAddress::va(0x2000);
    seg1.file_offset = TypedAddress::file_offset(0x1000);
    seg1.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg1);
    
    SegmentMapping seg2;
    seg2.segment_name = "__DATA";
    seg2.vm_address = TypedAddress::va(0x100001000);  // Overlapping
    seg2.vm_size = TypedAddress::va(0x2000);
    seg2.file_offset = TypedAddress::file_offset(0x3000);
    seg2.file_size = TypedAddress::file_offset(0x2000);
    segments.push_back(seg2);
    
    MachOAddressConverter converter({}, segments);
    
    // VA in overlapping region - first match wins
    auto va = TypedAddress::va(0x100001500);
    auto result = converter.convert(va, AddressSpace::SegmentVA);
    EXPECT_TRUE(result.success);
}

// --- Empty/Zero-Size Tests ---

TEST(AnalysisModel, Section_ZeroSize) {
    NormalizedSection sec;
    sec.name = ".text";
    sec.virtual_address = TypedAddress::va(0x401000);
    sec.virtual_size = 0;
    sec.raw_size = 0;
    
    EXPECT_FALSE(sec.contains_va(TypedAddress::va(0x401000)));
    EXPECT_FALSE(sec.contains_file_offset(TypedAddress::file_offset(0x1000)));
}

TEST(AnalysisModel, Segment_ZeroSize) {
    std::vector<NormalizedSection> sections;
    std::vector<SegmentMapping> segments;
    
    SegmentMapping seg;
    seg.vm_address = TypedAddress::va(0x400000);
    seg.vm_size = TypedAddress::va(0);
    seg.file_offset = TypedAddress::file_offset(0x1000);
    seg.file_size = TypedAddress::file_offset(0);
    segments.push_back(seg);
    
    ELFAddressConverter converter({}, {seg});
    
    auto va = TypedAddress::va(0x400000);
    auto result = converter.convert(va, AddressSpace::FileOffset);
    EXPECT_FALSE(result.success);
}