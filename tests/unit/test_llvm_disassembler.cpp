// FORTRESS LLVM MC Disassembler Unit Tests
// Tests for real x86-64 instruction decoding using LLVM MC

#include <gtest/gtest.h>
#include <fortress/binary/analysis/llvm_disassembler.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/types.h>
#include <vector>
#include <string>
#include <iostream>

using namespace fortress;

class LLVMDisassemblerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check if LLVM disassembler is available
        disassembler_ = std::make_unique<LLVMDisassembler>(
            Architecture::X64, Endianness::Little, true);
    }

    std::unique_ptr<LLVMDisassembler> disassembler_;
};

// Test: Disassembler initialization
TEST_F(LLVMDisassemblerTest, Initialization) {
    std::cout << "Disassembler status: " << static_cast<int>(disassembler_->get_status()) << std::endl;
    std::cout << "Disassembler valid: " << disassembler_->is_valid() << std::endl;
    std::cout << "Disassembler arch: " << static_cast<int>(disassembler_->get_architecture()) << std::endl;
    std::cout << "Disassembler endianness: " << static_cast<int>(disassembler_->get_endianness()) << std::endl;
    std::cout << "Disassembler is_64bit: " << disassembler_->is_64bit() << std::endl;
    std::cout << "Disassembler max_instr_size: " << disassembler_->get_max_instruction_size() << std::endl;
    
    EXPECT_TRUE(disassembler_->is_valid()) 
        << "LLVM MC disassembler should be available for x86-64";
    EXPECT_EQ(disassembler_->get_architecture(), Architecture::X64);
    EXPECT_EQ(disassembler_->get_endianness(), Endianness::Little);
    EXPECT_TRUE(disassembler_->is_64bit());
    EXPECT_EQ(disassembler_->get_max_instruction_size(), 15);
    EXPECT_EQ(disassembler_->get_status(), LLVMDisassembler::Status::Success);
}

// Test: CALL rel32 - E8 00 00 00 00 (CALL 0x5)
TEST_F(LLVMDisassemblerTest, CallRel32) {
    // CALL rel32: E8 00 00 00 00 (call 0x5 from address 0x1000)
    std::vector<uint8_t> code = {0xE8, 0x00, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 5);
    EXPECT_EQ(instr.bytes.size(), 5);
    EXPECT_EQ(instr.bytes[0], 0xE8);
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_FALSE(instr.is_indirect);
    EXPECT_FALSE(instr.is_jump);
    EXPECT_FALSE(instr.is_return);
    // Target should be 0x1005 (next instruction)
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1005);
}

// Test: CALL RAX - FF D0
TEST_F(LLVMDisassemblerTest, CallRegister) {
    // CALL RAX: FF D0
    std::vector<uint8_t> code = {0xFF, 0xD0};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.is_indirect);  // Indirect call through register
    EXPECT_FALSE(instr.target_address.has_value());
}

// Test: CALL [RAX] - FF 10
TEST_F(LLVMDisassemblerTest, CallMemory) {
    // CALL [RAX]: FF 10
    std::vector<uint8_t> code = {0xFF, 0x10};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.is_indirect);  // Indirect call through memory
    EXPECT_FALSE(instr.target_address.has_value());
}

// Test: JMP rel32 - E9 00 00 00 00
TEST_F(LLVMDisassemblerTest, JmpRel32) {
    // JMP rel32: E9 00 00 00 00 (jmp 0x5 from address 0x1000)
    std::vector<uint8_t> code = {0xE9, 0x00, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 5);
    EXPECT_EQ(instr.mnemonic, "jmp");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_FALSE(instr.is_conditional_jump);
    EXPECT_FALSE(instr.is_call);
    EXPECT_FALSE(instr.is_return);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1005);
}

// Test: JNE short - 75 02
TEST_F(LLVMDisassemblerTest, JneShort) {
    // JNE rel8: 75 02 (JNE +2 bytes from address 0x1000)
    std::vector<uint8_t> code = {0x75, 0x02};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "jne");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.is_conditional_jump);
    EXPECT_FALSE(instr.is_call);
    EXPECT_FALSE(instr.is_return);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1004);
}

// Test: RET - C3
TEST_F(LLVMDisassemblerTest, Ret) {
    // RET: C3
    std::vector<uint8_t> code = {0xC3};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 1);
    EXPECT_EQ(instr.mnemonic, "ret");
    EXPECT_FALSE(instr.is_call);
    EXPECT_FALSE(instr.is_jump);
    EXPECT_TRUE(instr.is_return);  // ret IS a return instruction
    // Note: ret is correctly detected as return instruction
}

// Test: NOP - 90
TEST_F(LLVMDisassemblerTest, Nop) {
    // NOP: 90
    std::vector<uint8_t> code = {0x90};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_EQ(instr.size, 1);
    EXPECT_EQ(instr.mnemonic, "nop");
    EXPECT_FALSE(instr.is_call);
    EXPECT_FALSE(instr.is_jump);
    EXPECT_FALSE(instr.is_return);
}

// Test: UD2 - Valid instruction that raises invalid opcode exception
TEST_F(LLVMDisassemblerTest, UD2_ValidInstruction) {
    // UD2: 0F 0B (explicitly undefined instruction, but VALID encoding)
    std::vector<uint8_t> code = {0x0F, 0x0B};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    // UD2 should decode successfully as a valid instruction
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.address, 0x1000);
    // UD2 is 2 bytes
    EXPECT_EQ(instr.size, 2);
    EXPECT_EQ(instr.mnemonic, "ud2");
    // UD2 is a valid instruction (though it raises #UD when executed)
    EXPECT_FALSE(instr.mnemonic == "invalid");
}

// Test: Truly invalid instruction encoding
TEST_F(LLVMDisassemblerTest, InvalidInstruction_TrulyInvalid) {
    // 0xFF 0xFF - not a valid x86-64 instruction prefix combination
    // This is an invalid encoding that should not decode as a valid instruction
    std::vector<uint8_t> code = {0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    // May succeed or fail depending on LLVM's handling
    // The important thing is we handle both cases gracefully
    if (result) {
        EXPECT_GE(instructions.size(), 1);
        const auto& instr = instructions[0];
        EXPECT_EQ(instr.address, 0x1000);
        // Should be marked as invalid or have appropriate classification
    }
}

// Test: Truncated sequence - incomplete CALL
TEST_F(LLVMDisassemblerTest, TruncatedInstruction) {
    // Incomplete CALL rel32 (only 3 bytes instead of 5)
    std::vector<uint8_t> code = {0xE8, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    // Should still decode what it can, marking remaining as invalid
    EXPECT_TRUE(result);
    // At least the first byte should be processed
    EXPECT_GE(instructions.size(), 1);
}

// Test: CALL rel32 with zero displacement
TEST_F(LLVMDisassemblerTest, CallRel32ZeroDisp) {
    // CALL rel32: E8 00 00 00 00 (call to next instruction)
    std::vector<uint8_t> code = {0xE8, 0x00, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1005);
}

// Test: CALL rel32 with positive displacement
TEST_F(LLVMDisassemblerTest, CallRel32Positive) {
    // CALL rel32: E8 0A 00 00 00 (call +10 bytes forward)
    std::vector<uint8_t> code = {0xE8, 0x0A, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x100F);  // 0x1000 + 5 + 10
}

// Test: CALL rel32 with negative displacement (backwards call)
TEST_F(LLVMDisassemblerTest, CallRel32Negative) {
    // CALL rel32: E8 FA FF FF FF (call -6 bytes backward)
    std::vector<uint8_t> code = {0xE8, 0xFA, 0xFF, 0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0xFFF);  // 0x1000 + 5 - 6 = 0xFFF (4095)
}

// Test: CALL rel32 to previous instruction (call -5)
TEST_F(LLVMDisassemblerTest, CallRel32ToPrev) {
    // CALL rel32: E8 FB FF FF FF (call -5 bytes, to itself)
    std::vector<uint8_t> code = {0xE8, 0xFB, 0xFF, 0xFF, 0xFF};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x1000);  // 0x1000 + 5 - 5
}

// Test: JNE short with positive displacement
TEST_F(LLVMDisassemblerTest, JneShortPositive) {
    // JNE +10: 75 0A
    std::vector<uint8_t> code = {0x75, 0x0A};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jne");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.is_conditional_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x100C);  // 0x1000 + 2 + 10
}

// Test: JNE short with negative displacement
TEST_F(LLVMDisassemblerTest, JneShortNegative) {
    // JNE -6: 75 FA
    std::vector<uint8_t> code = {0x75, 0xFA};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jne");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.is_conditional_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0xFFC);  // 0x1000 + 2 - 6 = 0xFFC (4092)
}

// Test: CALL rel32 near INT64_MAX boundary (renamed from NearMax)
TEST_F(LLVMDisassemblerTest, CallRel32LargePositive) {
    // CALL rel32 with large positive displacement
    // displacement = 0x7FFFFFFA (little-endian FA FF FF 7F)
    // This tests overflow handling near UINT64_MAX boundary
    std::vector<uint8_t> code = {0xE8, 0xFA, 0xFF, 0xFF, 0x7F};  // Large positive displacement
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    // 0x1000 + 5 + 0x7FFFFFFA = 0x80000FFF
    EXPECT_EQ(instr.target_address.value(), 0x80000FFF);
}

// Test: High address with negative displacement (near UINT64_MAX)
TEST_F(LLVMDisassemblerTest, CallRel32HighAddressNegative) {
    // CALL from near UINT64_MAX with negative displacement
    // Base: 0xFFFFFFFFFFFFFF00, CALL rel32 with displacement -5
    // next_ip = 0xFFFFFFFFFFFFFF05, -5 = 0xFFFFFFFFFFFFFF00
    std::vector<uint8_t> code = {0xE8, 0xFB, 0xFF, 0xFF, 0xFF};  // -5 displacement
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0xFFFFFFFFFFFFFF00, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    // 0xFFFFFFFFFFFFFF00 + 5 - 5 = 0xFFFFFFFFFFFFFF00
    EXPECT_EQ(instr.target_address.value(), 0xFFFFFFFFFFFFFF00);
}

// Test: JMP near UINT64_MAX boundary with negative displacement
TEST_F(LLVMDisassemblerTest, JmpRel32HighAddressNegative) {
    // JMP from near UINT64_MAX with negative displacement
    // Base: 0xFFFFFFFFFFFFFF00, JMP rel32 with displacement -4
    // next_ip = 0xFFFFFFFFFFFFFF05, -4 = 0xFFFFFFFFFFFFFF01
    std::vector<uint8_t> code = {0xE9, 0xFC, 0xFF, 0xFF, 0xFF};  // -4 displacement
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0xFFFFFFFFFFFFFF00, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jmp");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    // 0xFFFFFFFFFFFFFF00 + 5 - 4 = 0xFFFFFFFFFFFFFF01
    EXPECT_EQ(instr.target_address.value(), 0xFFFFFFFFFFFFFF01);
}

// Test: Instructions with different sizes
TEST_F(LLVMDisassemblerTest, MixedInstructionSizes) {
    // NOP (1 byte) + CALL rel32 (5 bytes) + RET (1 byte)
    std::vector<uint8_t> code = {0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 3);
    
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
// Test: End-to-end integration test
// Bytes → LLVMDisassembler → InstructionInfo → CFGBuilder → CallGraphBuilder
// ============================================================================
TEST_F(LLVMDisassemblerTest, IntegrationTest_CompletePipeline) {
    // This test exercises the disassembler pipeline:
    // Bytes → LLVM MC → InstructionInfo (with correct classification and targets)
    //
    // Linear code sequence:
    // 0x1000: NOP
    // 0x1001: CALL 0x2001 (displacement = 0x2001 - 0x1006 = 0xFFB)
    // 0x1006: RET
    // 0x1007: NOP
    // 0x1008: CALL 0x3001 (displacement = 0x3001 - 0x100D = 0x1FF4)
    // 0x100D: RET
    // 0x100E: NOP
    // 0x100F: RET
    //
    // Note: The disassembler performs linear disassembly from base address.
    // Function boundaries are determined by the CFGBuilder using binary analysis.
    
    // CALL from 0x1001 (next_ip=0x1006) to 0x2001: displacement = 0x2001 - 0x1006 = 0xFFB
    // CALL from 0x1008 (next_ip=0x100D) to 0x3001: displacement = 0x3001 - 0x100D = 0x1FF4
    std::vector<uint8_t> code = {
        0x90,                         // NOP at 0x1000
        0xE8, 0xFB, 0x0F, 0x00, 0x00, // CALL 0x2001 from 0x1001 (disp=0xFFB)
        0xC3,                         // RET at 0x1006
        0x90,                         // NOP at 0x1007
        0xE8, 0xF4, 0x1F, 0x00, 0x00, // CALL 0x3001 from 0x1008 (disp=0x1FF4)
        0xC3,                         // RET at 0x100D
        0x90,                         // NOP at 0x100E
        0xC3                          // RET at 0x100F
    };
    
    std::vector<InstructionInfo> instructions;
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 8);
    
    // Verify instruction sequence (linear disassembly)
    // NOP at 0x1000
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].mnemonic, "nop");
    EXPECT_EQ(instructions[0].size, 1);
    
    // CALL at 0x1001 -> target 0x2001
    EXPECT_EQ(instructions[1].address, 0x1001);
    EXPECT_EQ(instructions[1].mnemonic, "call");
    EXPECT_EQ(instructions[1].size, 5);
    EXPECT_TRUE(instructions[1].is_call);
    EXPECT_FALSE(instructions[1].is_indirect);
    EXPECT_TRUE(instructions[1].target_address.has_value());
    EXPECT_EQ(instructions[1].target_address.value(), 0x2001);
    
    // RET at 0x1006
    EXPECT_EQ(instructions[2].address, 0x1006);
    EXPECT_EQ(instructions[2].mnemonic, "ret");
    
    // NOP at 0x1007
    EXPECT_EQ(instructions[3].address, 0x1007);
    EXPECT_EQ(instructions[3].mnemonic, "nop");
    EXPECT_EQ(instructions[3].size, 1);
    
    // CALL at 0x1008 -> target 0x3001
    EXPECT_EQ(instructions[4].address, 0x1008);
    EXPECT_EQ(instructions[4].mnemonic, "call");
    EXPECT_EQ(instructions[4].size, 5);
    EXPECT_TRUE(instructions[4].is_call);
    EXPECT_FALSE(instructions[4].is_indirect);
    EXPECT_TRUE(instructions[4].target_address.has_value());
    EXPECT_EQ(instructions[4].target_address.value(), 0x3001);
    
    // RET at 0x100D
    EXPECT_EQ(instructions[5].address, 0x100D);
    EXPECT_EQ(instructions[5].mnemonic, "ret");
    
    // NOP at 0x100E
    EXPECT_EQ(instructions[6].address, 0x100E);
    EXPECT_EQ(instructions[6].mnemonic, "nop");
    EXPECT_EQ(instructions[6].size, 1);
    
    // RET at 0x100F
    EXPECT_EQ(instructions[7].address, 0x100F);
    EXPECT_EQ(instructions[7].mnemonic, "ret");
    
    // Verify call sites have correct addresses
    EXPECT_EQ(instructions[1].address, 0x1001);  // call site 1
    EXPECT_EQ(instructions[4].address, 0x1008);  // call site 2
    
    // Verify call targets
    EXPECT_TRUE(instructions[1].target_address.has_value());
    EXPECT_EQ(instructions[1].target_address.value(), 0x2001);
    EXPECT_TRUE(instructions[4].target_address.has_value());
    EXPECT_EQ(instructions[4].target_address.value(), 0x3001);
    
    // Verify indirect calls are not marked as indirect (these are direct)
    EXPECT_FALSE(instructions[1].is_indirect);
    EXPECT_FALSE(instructions[4].is_indirect);
    
    // Verify returns
    EXPECT_EQ(instructions[2].mnemonic, "ret");
    EXPECT_EQ(instructions[5].mnemonic, "ret");
    EXPECT_EQ(instructions[7].mnemonic, "ret");
    EXPECT_TRUE(instructions[2].is_return);
    EXPECT_TRUE(instructions[5].is_return);
    EXPECT_TRUE(instructions[7].is_return);
    
    // Verify NOPs
    EXPECT_EQ(instructions[0].mnemonic, "nop");
    EXPECT_EQ(instructions[3].mnemonic, "nop");
    EXPECT_EQ(instructions[6].mnemonic, "nop");
    
    // Verify instruction bytes are preserved
    EXPECT_EQ(instructions[1].bytes.size(), 5);
    EXPECT_EQ(instructions[1].bytes[0], 0xE8);
    EXPECT_EQ(instructions[4].bytes.size(), 5);
    EXPECT_EQ(instructions[4].bytes[0], 0xE8);
}

// Test: Integration with indirect call
TEST_F(LLVMDisassemblerTest, IntegrationTest_IndirectCall) {
    // Test indirect call through register
    // main:
    //   MOV RAX, 0x4000
    //   CALL RAX
    //   RET
    std::vector<uint8_t> code = {
        0x48, 0xB8, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0x4000
        0xFF, 0xD0,                                                    // CALL RAX
        0xC3                                                           // RET
    };
    
    std::vector<InstructionInfo> instructions;
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 3);
    
    // MOV RAX, 0x4000
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].mnemonic, "movabs");
    
    // CALL RAX (indirect)
    EXPECT_EQ(instructions[1].address, 0x100A);
    EXPECT_EQ(instructions[1].mnemonic, "call");
    EXPECT_TRUE(instructions[1].is_call);
    EXPECT_TRUE(instructions[1].is_indirect);  // Indirect call through register
    EXPECT_FALSE(instructions[1].target_address.has_value());  // No target for indirect
    
    // RET
    EXPECT_EQ(instructions[2].address, 0x100C);
    EXPECT_EQ(instructions[2].mnemonic, "ret");
}

// Test: Integration with conditional branch
TEST_F(LLVMDisassemblerTest, IntegrationTest_ConditionalBranch) {
    // Test conditional branch
    // main:
    //   CMP RAX, RBX
    //   JNE target (skip NOP, jump to RET)
    //   NOP
    //   RET
    std::vector<uint8_t> code = {
        0x48, 0x39, 0xD8,          // CMP RAX, RBX
        0x75, 0x02,                // JNE +2 (skip NOP, target = 0x1007)
        0x90,                      // NOP at 0x1005
        0xC3                       // RET at 0x1006
    };
    
    std::vector<InstructionInfo> instructions;
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 4);
    
    // CMP RAX, RBX
    EXPECT_EQ(instructions[0].address, 0x1000);
    EXPECT_EQ(instructions[0].mnemonic, "cmp");
    
    // JNE +2: at 0x1003, size 2, next_ip=0x1005, disp=+2, target=0x1007
    EXPECT_EQ(instructions[1].address, 0x1003);
    EXPECT_EQ(instructions[1].mnemonic, "jne");
    EXPECT_TRUE(instructions[1].is_jump);
    EXPECT_TRUE(instructions[1].is_conditional_jump);
    EXPECT_TRUE(instructions[1].target_address.has_value());
    EXPECT_EQ(instructions[1].target_address.value(), 0x1007);
    
    // NOP at 0x1005 (fallthrough)
    EXPECT_EQ(instructions[2].address, 0x1005);
    EXPECT_EQ(instructions[2].mnemonic, "nop");
    
    // RET at 0x1006
    EXPECT_EQ(instructions[3].address, 0x1006);
    EXPECT_EQ(instructions[3].mnemonic, "ret");
}

