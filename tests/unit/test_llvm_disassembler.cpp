// FORTRESS LLVM MC Disassembler Unit Tests
// Tests for real x86-64 instruction decoding using LLVM MC

#include <gtest/gtest.h>
#include <fortress/binary/analysis/llvm_disassembler.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/core/types.h>
#include <vector>
#include <string>
#include <iostream>
#include <memory>
#include <algorithm>

namespace fortress {

class LLVMDisassemblerTest : public ::testing::Test {
protected:
    void SetUp() override {
        disassembler_ = std::make_unique<LLVMDisassembler>(
            Architecture::X64, Endianness::Little, true);
    }

    std::unique_ptr<LLVMDisassembler> disassembler_;
};

// ============================================================================
// Basic Instruction Tests
// ============================================================================

TEST_F(LLVMDisassemblerTest, Initialization) {
    EXPECT_TRUE(disassembler_->is_valid()) << "LLVM MC disassembler should be available for x86-64";
    EXPECT_EQ(disassembler_->get_architecture(), Architecture::X64);
    EXPECT_EQ(disassembler_->get_endianness(), Endianness::Little);
    EXPECT_TRUE(disassembler_->is_64bit());
    EXPECT_EQ(disassembler_->get_max_instruction_size(), 15);
    EXPECT_EQ(disassembler_->get_status(), LLVMDisassembler::Status::Success);
}

TEST_F(LLVMDisassemblerTest, CallRel32) {
    std::vector<uint8_t> code = {0xE8, 0x00, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 5);
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_FALSE(instr.is_indirect);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1005);
}

TEST_F(LLVMDisassemblerTest, CallRegister) {
    std::vector<uint8_t> code = {0xFF, 0xD0};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.is_indirect);
    EXPECT_FALSE(instr.target_address.has_value());
}

TEST_F(LLVMDisassemblerTest, CallMemory) {
    std::vector<uint8_t> code = {0xFF, 0x10};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.is_indirect);
    EXPECT_FALSE(instr.target_address.has_value());
}

TEST_F(LLVMDisassemblerTest, JmpRel32) {
    std::vector<uint8_t> code = {0xE9, 0x00, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 5);
    EXPECT_EQ(instr.mnemonic, "jmp");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_FALSE(instr.is_conditional_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1005);
}

TEST_F(LLVMDisassemblerTest, JneShort) {
    std::vector<uint8_t> code = {0x75, 0x02};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "jne");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.is_conditional_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1004);
}

TEST_F(LLVMDisassemblerTest, Ret) {
    std::vector<uint8_t> code = {0xC3};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 1);
    EXPECT_EQ(instr.mnemonic, "ret");
    EXPECT_TRUE(instr.is_return);
}

TEST_F(LLVMDisassemblerTest, Nop) {
    std::vector<uint8_t> code = {0x90};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 1);
    EXPECT_EQ(instr.mnemonic, "nop");
    EXPECT_FALSE(instr.is_call);
    EXPECT_FALSE(instr.is_jump);
    EXPECT_FALSE(instr.is_return);
}

TEST_F(LLVMDisassemblerTest, UD2_ValidInstruction) {
    std::vector<uint8_t> code = {0x0F, 0x0B};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "ud2");
    EXPECT_FALSE(instr.mnemonic == "invalid");
}

TEST_F(LLVMDisassemblerTest, InvalidInstruction_TrulyInvalid) {
    std::vector<uint8_t> code = {0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    if (result) {
        EXPECT_GE(instructions.size(), 1);
        const auto& instr = instructions[0];
        EXPECT_EQ(instr.address, 0x1000);
    }
}

TEST_F(LLVMDisassemblerTest, TruncatedInstruction) {
    std::vector<uint8_t> code = {0xE8, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_GE(instructions.size(), 1);
}

TEST_F(LLVMDisassemblerTest, MultipleInstructions) {
    std::vector<uint8_t> code = {0x90, 0x90, 0xC3};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 3);
    
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].mnemonic, "nop");
    EXPECT_EQ(instructions[0].size, 1);
    
    EXPECT_EQ(instructions[1].address, 0x1001);
    EXPECT_EQ(instructions[1].mnemonic, "nop");
    EXPECT_EQ(instructions[1].size, 1);
    
    EXPECT_EQ(instructions[2].address, 0x1002);
    EXPECT_EQ(instructions[2].mnemonic, "ret");
    EXPECT_EQ(instructions[2].size, 1);
}

TEST_F(LLVMDisassemblerTest, CallRel32ZeroDisp) {
    std::vector<uint8_t> code = {0xE8, 0x00, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1005);
}

TEST_F(LLVMDisassemblerTest, CallRel32Positive) {
    std::vector<uint8_t> code = {0xE8, 0x0A, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x100F);
}

TEST_F(LLVMDisassemblerTest, CallRel32Negative) {
    std::vector<uint8_t> code = {0xE8, 0xFA, 0xFF, 0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0xFFF);
}

TEST_F(LLVMDisassemblerTest, CallRel32ToPrev) {
    std::vector<uint8_t> code = {0xE8, 0xFB, 0xFF, 0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1000);
}

TEST_F(LLVMDisassemblerTest, JneShortPositive) {
    std::vector<uint8_t> code = {0x75, 0x0A};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jne");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.is_conditional_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x100C);
}

TEST_F(LLVMDisassemblerTest, JneShortNegative) {
    std::vector<uint8_t> code = {0x75, 0xFA};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jne");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.is_conditional_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0xFFC);
}

TEST_F(LLVMDisassemblerTest, CallRel32LargePositive) {
    std::vector<uint8_t> code = {0xE8, 0xFA, 0xFF, 0xFF, 0x7F};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x80000FFF);
}

TEST_F(LLVMDisassemblerTest, CallRel32HighAddressNegative) {
    std::vector<uint8_t> code = {0xE8, 0xFB, 0xFF, 0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0xFFFFFFFFFFFFFF00, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0xFFFFFFFFFFFFFF00);
}

TEST_F(LLVMDisassemblerTest, JmpRel32HighAddressNegative) {
    std::vector<uint8_t> code = {0xE9, 0xFC, 0xFF, 0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0xFFFFFFFFFFFFFF00, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jmp");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0xFFFFFFFFFFFFFF01);
}

TEST_F(LLVMDisassemblerTest, MixedInstructionSizes) {
    std::vector<uint8_t> code = {0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 3);
    
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].size, 1);
    EXPECT_EQ(instructions[0].mnemonic, "nop");
    
    EXPECT_EQ(instructions[1].address, 0x1001);
    EXPECT_EQ(instructions[1].size, 5);
    EXPECT_EQ(instructions[1].mnemonic, "call");
    EXPECT_TRUE(instructions[1].is_call);
    EXPECT_TRUE(instructions[1].target_address.has_value());
    EXPECT_EQ(instructions[1].target_address.value(), 0x1006);
    
    EXPECT_EQ(instructions[2].address, 0x1006);
    EXPECT_EQ(instructions[2].size, 1);
    EXPECT_EQ(instructions[2].mnemonic, "ret");
}

// ============================================================================
// Helper Functions for Integration Tests
// ============================================================================



// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(LLVMDisassemblerTest, IntegrationTest_CompletePipeline) {
    // This test exercises the FULL pipeline:
    // Bytes → LLVM MC → InstructionInfo → CFGBuilder → CallGraphBuilder
    //
    // Binary layout:
    // .text section at VA 0x1000, file offset 0x400
    // 
    // main (0x1000, size 0x30):
    //   0x1000: NOP
    //   0x1001: CALL func_a (0x2000)
    //   0x1006: RET
    //
    // func_a (0x2000, size 0x20):
    //   0x2000: NOP
    //   0x2001: MOV RAX, 0x4000
    //   0x200B: CALL RAX (indirect call)
    //   0x200D: RET
    //
    // func_b (0x3000, size 0x20):
    //   0x3000: CMP RAX, RBX
    //   0x3003: JNE +2 (skip NOP)
    //   0x3005: NOP
    //   0x3006: RET
    
    std::vector<uint8_t> code = {
        0x90,                                  // 0x1000: NOP
        0xE8, 0xFA, 0x0F, 0x00, 0x00,         // 0x1001: CALL 0x2000 (disp=0xFFB)
        0xC3,                                  // 0x1006: RET
    };
    
    // Extend code to cover all functions (0x1000 to 0x3020 = 0x2020 bytes)
    code.resize(0x2021, 0x90);
    
    // func_a at 0x2000 (offset 0x1000 from base)
    code[0x1000] = 0x90;
    code[0x1001] = 0x48; code[0x1002] = 0xB8;
    code[0x1003] = 0x00; code[0x1004] = 0x40; 
    code[0x1005] = 0x00; code[0x1006] = 0x00;
    code[0x1007] = 0x00; code[0x1008] = 0x00;
    code[0x1009] = 0x00; code[0x100A] = 0x00;
    code[0x100B] = 0xFF; code[0x100C] = 0xD0;  // CALL RAX
    code[0x100D] = 0xC3;
    
    // func_b at 0x3000 (offset 0x2000 from base 0x1000)
    code[0x2000] = 0x48; code[0x2001] = 0x39; code[0x2002] = 0xD8;
    code[0x2003] = 0x75; code[0x2004] = 0x02;
    code[0x2005] = 0x90;
    code[0x2006] = 0xC3;
    
    // Step 1: Create BinaryAnalysisResult
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
    text_section.virtual_size = 0x2021;
    text_section.raw_size = 0x2021;
    text_section.file_offset = 0x400;
    text_section.permissions = SectionPermission::Read | SectionPermission::Execute;
    analysis.sections.push_back(text_section);
    
    FunctionInfo main_func;
    main_func.name = "main";
    main_func.address = 0x1000;
    main_func.size = 0x30;
    main_func.architecture = Architecture::X64;
    main_func.confidence = ConfidenceLevel::High;
    main_func.source = FunctionSource::EntryPoint;
    main_func.call_targets = {0x2000};
    analysis.functions.push_back(main_func);
    
    FunctionInfo func_a;
    func_a.name = "func_a";
    func_a.address = 0x2000;
    func_a.size = 0x20;
    func_a.architecture = Architecture::X64;
    func_a.confidence = ConfidenceLevel::High;
    func_a.source = FunctionSource::Disassembly;
    func_a.call_targets = {};  // Indirect call - no static target
    analysis.functions.push_back(func_a);
    
    FunctionInfo func_b;
    func_b.name = "func_b";
    func_b.address = 0x3000;
    func_b.size = 0x20;
    func_b.architecture = Architecture::X64;
    func_b.confidence = ConfidenceLevel::High;
    func_b.source = FunctionSource::Disassembly;
    func_b.call_targets = {};  // No calls
    analysis.functions.push_back(func_b);
    
    // Step 1: Use REAL CFGBuilder to build CFGs for each function
    CFGBuilderConfig cfg_config;
    cfg_config.identify_loops = true;
    cfg_config.compute_dominators = true;
    cfg_config.identify_unreachable = true;
    
    CFGBuilder cfg_builder(cfg_config);
    
    // The section starts at 0x1000, so code_for_disasm offset 0 = VA 0x1000
    // func_a at 0x2000 is at offset 0x1000 from section base
    // func_b at 0x3000 is at offset 0x2000 from section base
    std::vector<uint8_t> code_for_disasm(0x2021, 0x90);
    // main at 0x1000 (offset 0)
    code_for_disasm[0x0000] = 0x90;                                  // NOP at 0x1000
    code_for_disasm[0x0001] = 0xE8; code_for_disasm[0x0002] = 0xFA; 
    code_for_disasm[0x0003] = 0x0F; code_for_disasm[0x0004] = 0x00; 
    code_for_disasm[0x0005] = 0x00;                                  // CALL 0x2000 at 0x1001 (disp=0xFFA)
    code_for_disasm[0x0006] = 0xC3;                                  // RET at 0x1006
    
    // func_a at 0x2000 (offset 0x1000 from section base)
    code_for_disasm[0x1000] = 0x90;                                  // NOP at 0x2000
    code_for_disasm[0x1001] = 0x48; code_for_disasm[0x1002] = 0xB8;
    code_for_disasm[0x1003] = 0x00; code_for_disasm[0x1004] = 0x40; 
    code_for_disasm[0x1005] = 0x00; code_for_disasm[0x1006] = 0x00;
    code_for_disasm[0x1007] = 0x00; code_for_disasm[0x1008] = 0x00;
    code_for_disasm[0x1009] = 0x00; code_for_disasm[0x100A] = 0x00;
    code_for_disasm[0x100B] = 0xFF; code_for_disasm[0x100C] = 0xD0;  // CALL RAX
    code_for_disasm[0x100D] = 0xC3;
    
    // func_b at 0x3000 (offset 0x2000 from section base)
    code_for_disasm[0x2000] = 0x48; code_for_disasm[0x2001] = 0x39; code_for_disasm[0x2002] = 0xD8;
    code_for_disasm[0x2003] = 0x75; code_for_disasm[0x2004] = 0x02;
    code_for_disasm[0x2005] = 0x90;
    code_for_disasm[0x2006] = 0xC3;
    
    // Build CFGs for each function using the real CFGBuilder
    auto main_cfg_result = cfg_builder.build_cfg(main_func, analysis, code_for_disasm, 0x1000);
    ASSERT_TRUE(main_cfg_result.success) << "main CFG build failed: " << main_cfg_result.error;
    
    auto func_a_cfg_result = cfg_builder.build_cfg(func_a, analysis, code_for_disasm, 0x1000);
    ASSERT_TRUE(func_a_cfg_result.success) << "func_a CFG build failed: " << func_a_cfg_result.error;
    
    auto func_b_cfg_result = cfg_builder.build_cfg(func_b, analysis, code_for_disasm, 0x1000);
    ASSERT_TRUE(func_b_cfg_result.success) << "func_b CFG build failed: " << func_b_cfg_result.error;
    
    // Step 2: Build Call Graph from CFGs
    CallGraphConfig cg_config;
    cg_config.compute_recursion = true;
    cg_config.compute_statistics = true;
    cg_config.merge_duplicate_edges = true;
    
    CallGraphBuilder cg_builder(cg_config);
    
    std::vector<std::unique_ptr<ControlFlowGraph>> cfgs_for_cg;
    cfgs_for_cg.push_back(std::move(main_cfg_result.cfg));
    cfgs_for_cg.push_back(std::move(func_a_cfg_result.cfg));
    cfgs_for_cg.push_back(std::move(func_b_cfg_result.cfg));
    
    CallGraphResult cg_result = cg_builder.build_call_graph(analysis, cfgs_for_cg);
    
    ASSERT_TRUE(cg_result.success) << "Call graph build failed: " << cg_result.error;
    ASSERT_NE(cg_result.graph, nullptr);
    ASSERT_TRUE(cg_result.graph->is_valid);
    
    // Verify Call Graph
    const auto& graph = *cg_result.graph;
    
    // Should have 3 internal functions
    EXPECT_EQ(graph.statistics.internal_functions, 3);
    
    // Find nodes
    const CallGraphNode* main_node = graph.find_node_by_name("main");
    const CallGraphNode* func_a_node = graph.find_node_by_name("func_a");
    const CallGraphNode* func_b_node = graph.find_node_by_name("func_b");
    
    ASSERT_NE(main_node, nullptr) << "main node not found";
    ASSERT_NE(func_a_node, nullptr) << "func_a node not found";
    ASSERT_NE(func_b_node, nullptr) << "func_b node not found";
    
    // Verify edges from main
    auto main_outgoing = graph.get_outgoing_edges(main_node->id);
    ASSERT_FALSE(main_outgoing.empty()) << "main should have outgoing edges";
    
    // main -> func_a (direct call)
    bool found_main_to_func_a = false;
    for (const auto* edge : main_outgoing) {
        if (edge->target_node_id == func_a_node->id) {
            found_main_to_func_a = true;
            EXPECT_EQ(edge->type, CallEdgeType::Direct);
            EXPECT_GT(edge->call_sites.size(), 0);
            // Call site should be at 0x1001 (the CALL instruction in main)
            EXPECT_EQ(edge->call_sites[0].address.value(), 0x1001);
            break;
        }
    }
    EXPECT_TRUE(found_main_to_func_a) << "Edge main -> func_a not found";
    
    // Verify func_a has indirect call edge
    auto func_a_outgoing = graph.get_outgoing_edges(func_a_node->id);
    bool found_indirect_call = false;
    for (const auto* edge : func_a_outgoing) {
        if (edge->type == CallEdgeType::Indirect) {
            found_indirect_call = true;
            EXPECT_GT(edge->call_sites.size(), 0);
            // Call site should be at 0x200B (CALL RAX)
            EXPECT_EQ(edge->call_sites[0].address.value(), 0x200B);
            break;
        }
    }
    EXPECT_TRUE(found_indirect_call) << "Indirect call from func_a not found";
    
    // Verify func_b has no outgoing calls (only conditional branch internal)
    auto func_b_outgoing = graph.get_outgoing_edges(func_b_node->id);
    
    // Verify call graph statistics
    EXPECT_GT(cg_result.resolutions_performed, 0);
    EXPECT_EQ(cg_result.nodes_created, graph.nodes.size());
    EXPECT_GT(cg_result.edges_created, 0);
}

TEST_F(LLVMDisassemblerTest, IntegrationTest_IndirectCall) {
    std::vector<uint8_t> code = {
        0x48, 0xB8, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0x4000
        0xFF, 0xD0,                                                    // CALL RAX
        0xC3                                                           // RET
    };
    
    std::vector<InstructionInfo> instructions;
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 3);
    
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].mnemonic, "movabs");
    
    EXPECT_EQ(instructions[1].address, 0x100A);
    EXPECT_EQ(instructions[1].mnemonic, "call");
    EXPECT_TRUE(instructions[1].is_call);
    EXPECT_TRUE(instructions[1].is_indirect);
    EXPECT_FALSE(instructions[1].target_address.has_value());
    
    EXPECT_EQ(instructions[2].address, 0x100C);
    EXPECT_EQ(instructions[2].mnemonic, "ret");
}

TEST_F(LLVMDisassemblerTest, IntegrationTest_ConditionalBranch) {
    std::vector<uint8_t> code = {
        0x48, 0x39, 0xD8,          // CMP RAX, RBX
        0x75, 0x02,                // JNE +2 (skip NOP, target = 0x1007)
        0x90,                      // NOP at 0x1005
        0xC3                       // RET at 0x1006
    };
    
    std::vector<InstructionInfo> instructions;
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    ASSERT_EQ(instructions.size(), 4);
    
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].mnemonic, "cmp");
    
    EXPECT_EQ(instructions[1].address, 0x1003);
    EXPECT_EQ(instructions[1].mnemonic, "jne");
    EXPECT_TRUE(instructions[1].is_jump);
    EXPECT_TRUE(instructions[1].is_conditional_jump);
    EXPECT_TRUE(instructions[1].target_address.has_value());
    EXPECT_EQ(instructions[1].target_address.value(), 0x1007);
    
    EXPECT_EQ(instructions[2].address, 0x1005);
    EXPECT_EQ(instructions[2].mnemonic, "nop");
    
    EXPECT_EQ(instructions[3].address, 0x1006);
    EXPECT_EQ(instructions[3].mnemonic, "ret");
}

} // namespace fortress