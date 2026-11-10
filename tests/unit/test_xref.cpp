// FORTRESS XREF Database Tests

#include <fortress/binary/analysis/xref.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/llvm_disassembler.h>
#include <fortress/binary/analysis/analyzer.h>
#include <gtest/gtest.h>
#include <vector>
#include <string>

using namespace fortress;

// ============================================================================
// Test Fixtures
// ============================================================================

inline BinaryAnalysisResult make_test_analysis() {
    BinaryAnalysisResult analysis;
    analysis.format = BinaryFormat::PE;
    analysis.architecture = Architecture::X64;
    analysis.endianness = Endianness::Little;
    analysis.is_64bit = true;
    analysis.entry_point = 0x1000;
    analysis.image_base = 0x1000;

    SectionInfo text_section;
    text_section.name = ".text";
    text_section.virtual_address = 0x1000;
    text_section.virtual_size = 0x1000;
    text_section.raw_size = 0x1000;
    text_section.file_offset = 0x400;
    text_section.permissions = SectionPermission::Read | SectionPermission::Execute;
    analysis.sections.push_back(text_section);

    SectionInfo data_section;
    data_section.name = ".data";
    data_section.virtual_address = 0x3000;
    data_section.virtual_size = 0x1000;
    data_section.raw_size = 0x1000;
    data_section.file_offset = 0x1400;
    data_section.permissions = SectionPermission::Read | SectionPermission::Write;
    analysis.sections.push_back(data_section);

    // Relocations
    RelocationInfo reloc1;
    reloc1.offset = 0x1050;
    reloc1.virtual_address = 0x3010;
    reloc1.kind = RelocationKind::Relative;
    reloc1.symbol_name = "";
    analysis.relocations.push_back(reloc1);

    RelocationInfo reloc2;
    reloc2.offset = 0x1060;
    reloc2.virtual_address = 0x4020;
    reloc2.kind = RelocationKind::PLTRelative;
    reloc2.symbol_name = "printf";
    analysis.relocations.push_back(reloc2);

    // Imports
    ImportInfo import;
    import.library_name = "kernel32.dll";
    SymbolInfo sym1;
    sym1.address = 0x4010;
    sym1.name = "CreateFileW";
    import.functions.push_back(sym1);
    SymbolInfo sym2;
    sym2.address = 0x4020;
    sym2.name = "ReadFile";
    import.functions.push_back(sym2);
    SymbolInfo sym3;
    sym3.address = 0x4030;
    sym3.name = "CloseHandle";
    import.functions.push_back(sym3);
    analysis.imports.push_back(import);

    // Exports
    ExportInfo export1;
    export1.library_name = "test.dll";
    SymbolInfo exp_sym1;
    exp_sym1.address = 0x2000;
    exp_sym1.name = "ExportedFunc1";
    export1.functions.push_back(exp_sym1);
    analysis.exports.push_back(export1);

    // Functions
    FunctionInfo func1;
    func1.name = "main";
    func1.address = 0x1000;
    func1.size = 0x50;
    func1.architecture = Architecture::X64;
    func1.confidence = ConfidenceLevel::High;
    func1.source = FunctionSource::EntryPoint;
    analysis.functions.push_back(func1);

    FunctionInfo func2;
    func2.name = "func_a";
    func2.address = 0x2000;
    func2.size = 0x30;
    func2.architecture = Architecture::X64;
    func2.confidence = ConfidenceLevel::High;
    func2.source = FunctionSource::Disassembly;
    analysis.functions.push_back(func2);

    FunctionInfo func3;
    func3.name = "func_b";
    func3.address = 0x2050;
    func3.size = 0x20;
    func3.architecture = Architecture::X64;
    func3.confidence = ConfidenceLevel::Medium;
    func3.source = FunctionSource::Disassembly;
    analysis.functions.push_back(func3);

    return analysis;
}

// ============================================================================
// XRefDatabase Basic Tests
// ============================================================================

TEST(XRefDatabaseTest, Construction) {
    XRefDatabase db;
    EXPECT_TRUE(db.empty());
    EXPECT_EQ(db.size(), 0);
}

TEST(XRefDatabaseTest, BuildFromAnalysis) {
    BinaryAnalysisResult analysis;
    analysis.format = BinaryFormat::PE;
    analysis.architecture = Architecture::X64;
    analysis.endianness = Endianness::Little;
    analysis.is_64bit = true;
    analysis.entry_point = 0x1000;
    analysis.image_base = 0x1000;

    SectionInfo text_section;
    text_section.name = ".text";
    text_section.virtual_address = 0x1000;
    text_section.virtual_size = 0x1000;
    text_section.raw_size = 0x1000;
    text_section.file_offset = 0x400;
    text_section.permissions = SectionPermission::Read | SectionPermission::Execute;
    analysis.sections.push_back(text_section);

    // Relocations
    RelocationInfo reloc1;
    reloc1.offset = 0x1050;
    reloc1.virtual_address = 0x3010;
    reloc1.kind = RelocationKind::Relative;
    reloc1.symbol_name = "";
    analysis.relocations.push_back(reloc1);

    RelocationInfo reloc2;
    reloc2.offset = 0x1060;
    reloc2.virtual_address = 0x4020;
    reloc2.kind = RelocationKind::PLTRelative;
    reloc2.symbol_name = "printf";
    analysis.relocations.push_back(reloc2);

    // Imports
    ImportInfo import;
    import.library_name = "kernel32.dll";
    SymbolInfo sym1;
    sym1.address = 0x4010;
    sym1.name = "CreateFileW";
    import.functions.push_back(sym1);
    SymbolInfo sym2;
    sym2.address = 0x4020;
    sym2.name = "ReadFile";
    import.functions.push_back(sym2);
    SymbolInfo sym3;
    sym3.address = 0x4030;
    sym3.name = "CloseHandle";
    import.functions.push_back(sym3);
    analysis.imports.push_back(import);

    // Exports
    ExportInfo export1;
    export1.library_name = "test.dll";
    SymbolInfo exp_sym1;
    exp_sym1.address = 0x2000;
    exp_sym1.name = "ExportedFunc1";
    export1.functions.push_back(exp_sym1);
    analysis.exports.push_back(export1);

    // Functions
    FunctionInfo func1;
    func1.name = "main";
    func1.address = 0x1000;
    func1.size = 0x50;
    func1.architecture = Architecture::X64;
    func1.confidence = ConfidenceLevel::High;
    func1.source = FunctionSource::EntryPoint;
    analysis.functions.push_back(func1);

    FunctionInfo func2;
    func2.name = "func_a";
    func2.address = 0x2000;
    func2.size = 0x30;
    func2.architecture = Architecture::X64;
    func2.confidence = ConfidenceLevel::High;
    func2.source = FunctionSource::Disassembly;
    analysis.functions.push_back(func2);

    FunctionInfo func3;
    func3.name = "func_b";
    func3.address = 0x2050;
    func3.size = 0x20;
    func3.architecture = Architecture::X64;
    func3.confidence = ConfidenceLevel::Medium;
    func3.source = FunctionSource::Disassembly;
    analysis.functions.push_back(func3);

    XRefDatabase db;

    auto result = db.build(analysis);
    ASSERT_TRUE(result);

    // Should have function entries, relocations, imports, exports
    EXPECT_GT(db.size(), 0);

    // Check for imports
    auto import_refs = db.get_xrefs_by_type(XRefType::Import);
    EXPECT_GT(import_refs.references.size(), 0);

    // Check for exports
    auto export_refs = db.get_xrefs_by_type(XRefType::Export);
    EXPECT_GT(export_refs.references.size(), 0);

    // Check for relocations
    auto reloc_refs = db.get_xrefs_by_type(XRefType::Relocation);
    EXPECT_GT(reloc_refs.references.size(), 0);
}

TEST(XRefDatabaseTest, BuildFromAnalysisWithConfig) {
    BinaryAnalysisResult analysis;
    analysis.format = BinaryFormat::PE;
    analysis.architecture = Architecture::X64;
    analysis.is_64bit = true;

    SectionInfo text_section;
    text_section.name = ".text";
    text_section.virtual_address = 0x1000;
    text_section.virtual_size = 0x1000;
    text_section.raw_size = 0x1000;
    text_section.file_offset = 0x400;
    text_section.permissions = SectionPermission::Read | SectionPermission::Execute;
    analysis.sections.push_back(text_section);

    // Relocations
    RelocationInfo reloc1;
    reloc1.offset = 0x1050;
    reloc1.virtual_address = 0x3010;
    reloc1.kind = RelocationKind::Relative;
    reloc1.symbol_name = "";
    analysis.relocations.push_back(reloc1);

    // Imports
    ImportInfo import;
    import.library_name = "kernel32.dll";
    SymbolInfo sym1;
    sym1.address = 0x4010;
    sym1.name = "CreateFileW";
    import.functions.push_back(sym1);
    analysis.imports.push_back(import);

    // Functions
    FunctionInfo func1;
    func1.name = "main";
    func1.address = 0x1000;
    func1.size = 0x50;
    func1.architecture = Architecture::X64;
    func1.confidence = ConfidenceLevel::High;
    func1.source = FunctionSource::EntryPoint;
    analysis.functions.push_back(func1);

    XRefConfig config;
    config.include_imports = false;
    config.include_exports = false;
    config.include_relocations = false;

    XRefDatabase db(config);
    auto result = db.build(analysis);
    ASSERT_TRUE(result);

    // Should only have function entries
    EXPECT_EQ(db.get_xrefs_by_type(XRefType::Import).references.size(), 0);
    EXPECT_EQ(db.get_xrefs_by_type(XRefType::Export).references.size(), 0);
    EXPECT_EQ(db.get_xrefs_by_type(XRefType::Relocation).references.size(), 0);
}

// ============================================================================
// CFG Integration Tests (require LLVM MC)
// ============================================================================

TEST(XRefDatabaseTest, BuildFromCFG) {
    // This test uses LLVM MC disassembler to build CFGs
    BinaryAnalysisResult analysis;
    analysis.format = BinaryFormat::PE;
    analysis.architecture = Architecture::X64;
    analysis.is_64bit = true;
    analysis.entry_point = 0x1000;
    analysis.image_base = 0x1000;

    SectionInfo text_section;
    text_section.name = ".text";
    text_section.virtual_address = 0x1000;
    text_section.virtual_size = 0x2000;  // Large enough for both functions
    text_section.raw_size = 0x2000;
    text_section.file_offset = 0x400;
    text_section.permissions = SectionPermission::Read | SectionPermission::Execute;
    analysis.sections.push_back(text_section);

    // Functions
    FunctionInfo func1;
    func1.name = "main";
    func1.address = 0x1000;
    func1.size = 0x50;
    func1.architecture = Architecture::X64;
    func1.confidence = ConfidenceLevel::High;
    func1.source = FunctionSource::EntryPoint;
    analysis.functions.push_back(func1);

    FunctionInfo func2;
    func2.name = "func_a";
    func2.address = 0x2000;
    func2.size = 0x30;
    func2.architecture = Architecture::X64;
    func2.confidence = ConfidenceLevel::High;
    func2.source = FunctionSource::Disassembly;
    analysis.functions.push_back(func2);

    // Create simple code for main: call func_a, ret
    std::vector<uint8_t> code(0x2000, 0x90); // NOP padding - large enough for both functions
    code[0x0000] = 0xE8; code[0x0001] = 0x4B; code[0x0002] = 0x10; code[0x0003] = 0x00; code[0x0004] = 0x00; // CALL 0x2000 at 0x1000 (disp=0x104B)
    code[0x0005] = 0xC3; // RET at 0x1005

    // func_a at 0x2000: ret (offset 0x1000 from section base 0x1000)
    code[0x1000] = 0xC3; // RET at 0x2000

    CFGBuilderConfig cfg_config;
    cfg_config.identify_loops = true;
    cfg_config.compute_dominators = true;
    cfg_config.identify_unreachable = true;

    CFGBuilder cfg_builder(cfg_config);

    FunctionInfo main_func = analysis.functions[0];
    FunctionInfo func_a = analysis.functions[1];

    auto main_cfg = cfg_builder.build_cfg(main_func, analysis, code, 0x1000);
    ASSERT_TRUE(main_cfg.success);

    auto func_a_cfg = cfg_builder.build_cfg(func_a, analysis, code, 0x1000);
    ASSERT_TRUE(func_a_cfg.success);

    XRefDatabase db;
    std::vector<std::unique_ptr<ControlFlowGraph>> cfgs;
    cfgs.push_back(std::move(main_cfg.cfg));
    cfgs.push_back(std::move(func_a_cfg.cfg));

    auto result = db.build(analysis, cfgs, nullptr);
    ASSERT_TRUE(result);

    // Should have CFG edges
    auto c2c = db.get_xrefs_by_type(XRefType::CodeToCode);
    EXPECT_GT(c2c.references.size(), 0);

    // Check that call edge has target_address
    bool found_call = false;
    for (const auto& ref : c2c.references) {
        if (ref.kind == XRefKind::Execute && ref.context == "call") {
            found_call = true;
            EXPECT_TRUE(ref.to_address.valid());
            break;
        }
    }
    EXPECT_TRUE(found_call);
}

TEST(XRefDatabaseTest, QueryLimits) {
    XRefDatabase db;
    for (int i = 0; i < 100; ++i) {
        CrossReference ref(
            TypedAddress::va(0x1000 + i), TypedAddress::va(0x2000 + i),
            XRefType::CodeToCode, XRefKind::Execute
        );
        // Use internal method for testing
        db.add_ref(ref);
    }

    // Default limit
    auto result = db.get_xrefs_to(TypedAddress::va(0x2000));
    EXPECT_LE(result.references.size(), 1000); // default limit

    // Custom limit
    result = db.get_xrefs_to(TypedAddress::va(0x2000), 10);
    EXPECT_LE(result.references.size(), 10);
}

TEST(XRefDatabaseTest, TruncationFlag) {
    XRefDatabase db;
    for (int i = 0; i < 1500; ++i) {
        CrossReference ref(
            TypedAddress::va(0x1000 + i), TypedAddress::va(0x2000),
            XRefType::CodeToCode, XRefKind::Execute
        );
        db.add_ref(ref);
    }

    auto result = db.get_xrefs_to(TypedAddress::va(0x2000), 100);
    EXPECT_EQ(result.references.size(), 100);
    EXPECT_TRUE(result.truncated);
    EXPECT_EQ(result.total_count, 1500);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(XRefDatabaseTest, InvalidAddress) {
    XRefDatabase db;
    db.add_ref(CrossReference(
        TypedAddress::va(0x1000), TypedAddress::va(0x2000),
        XRefType::CodeToCode, XRefKind::Execute
    ));

    // Query with invalid address
    auto result = db.get_xrefs_to(TypedAddress::va(0xFFFFFFFFFFFFFFFF));
    EXPECT_EQ(result.references.size(), 0);
    EXPECT_EQ(result.total_count, 0);

    result = db.get_xrefs_from(TypedAddress::va(0xFFFFFFFFFFFFFFFF));
    EXPECT_EQ(result.references.size(), 0);
}

TEST(XRefDatabaseTest, ZeroLimit) {
    XRefDatabase db;
    db.add_ref(CrossReference(
        TypedAddress::va(0x1000), TypedAddress::va(0x2000),
        XRefType::CodeToCode, XRefKind::Execute
    ));

    // Verify the reference was added
    EXPECT_EQ(db.size(), 1);

    // Query with limit smaller than results
    auto result = db.get_xrefs_to(TypedAddress::va(0x2000), 0);
    EXPECT_EQ(result.references.size(), 0);
    EXPECT_TRUE(result.truncated);
    EXPECT_EQ(result.total_count, 1);
}

// ============================================================================
// XRefConfig Tests
// ============================================================================

TEST(XRefConfigTest, DefaultConfig) {
    XRefConfig config;
    EXPECT_TRUE(config.include_code_to_code);
    EXPECT_TRUE(config.include_code_to_data);
    EXPECT_TRUE(config.include_data_to_code);
    EXPECT_TRUE(config.include_data_to_data);
    EXPECT_TRUE(config.include_relocations);
    EXPECT_TRUE(config.include_imports);
    EXPECT_TRUE(config.include_exports);
    EXPECT_TRUE(config.deduplicate);
    EXPECT_TRUE(config.compute_statistics);
    EXPECT_FALSE(config.use_sqlite_persistence);
}

TEST(XRefConfigTest, CustomConfig) {
    XRefConfig config;
    config.include_imports = false;
    config.include_exports = false;
    config.include_relocations = false;
    config.deduplicate = false;
    config.compute_statistics = false;

    EXPECT_FALSE(config.include_imports);
    EXPECT_FALSE(config.include_exports);
    EXPECT_FALSE(config.include_relocations);
    EXPECT_FALSE(config.deduplicate);
    EXPECT_FALSE(config.compute_statistics);
}

// ============================================================================
// Cross-Reference Kind Tests
// ============================================================================

TEST(XRefKindTest, KindValues) {
    EXPECT_EQ(static_cast<int>(XRefKind::Read), 0);
    EXPECT_EQ(static_cast<int>(XRefKind::Write), 1);
    EXPECT_EQ(static_cast<int>(XRefKind::Execute), 2);
    EXPECT_EQ(static_cast<int>(XRefKind::XRefOffset), 3);
    EXPECT_EQ(static_cast<int>(XRefKind::Unknown), 4);
}

TEST(XRefTypeTest, TypeValues) {
    EXPECT_EQ(static_cast<int>(XRefType::CodeToCode), 0);
    EXPECT_EQ(static_cast<int>(XRefType::CodeToData), 1);
    EXPECT_EQ(static_cast<int>(XRefType::DataToCode), 2);
    EXPECT_EQ(static_cast<int>(XRefType::DataToData), 3);
    EXPECT_EQ(static_cast<int>(XRefType::Relocation), 4);
    EXPECT_EQ(static_cast<int>(XRefType::Import), 5);
    EXPECT_EQ(static_cast<int>(XRefType::Export), 6);
    EXPECT_EQ(static_cast<int>(XRefType::Unknown), 7);
}

TEST(XRefConfidenceTest, ConfidenceValues) {
    EXPECT_EQ(static_cast<int>(XRefConfidence::Confirmed), 0);
    EXPECT_EQ(static_cast<int>(XRefConfidence::High), 1);
    EXPECT_EQ(static_cast<int>(XRefConfidence::Medium), 2);
    EXPECT_EQ(static_cast<int>(XRefConfidence::Low), 3);
    EXPECT_EQ(static_cast<int>(XRefConfidence::Unknown), 4);
}

TEST(XRefTypeTest, RoundTrip) {
    CrossReference ref(
        TypedAddress::va(0x1000), TypedAddress::va(0x2000),
        XRefType::CodeToData, XRefKind::Read, XRefConfidence::High
    );
    ref.symbol_name = "test_symbol";
    ref.context = "mov rax, [addr]";

    EXPECT_EQ(ref.type, XRefType::CodeToData);
    EXPECT_EQ(ref.kind, XRefKind::Read);
    EXPECT_EQ(ref.confidence, XRefConfidence::High);
    EXPECT_EQ(ref.symbol_name, "test_symbol");
    EXPECT_EQ(ref.context, "mov rax, [addr]");
    EXPECT_EQ(ref.from_address.value(), 0x1000);
    EXPECT_EQ(ref.to_address.value(), 0x2000);
}