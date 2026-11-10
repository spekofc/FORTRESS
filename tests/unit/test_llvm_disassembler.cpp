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

// Test: Invalid instruction - 0F 0B (UD2 - undefined instruction)
TEST_F(LLVMDisassemblerTest, InvalidInstruction) {
    // UD2: 0F 0B (explicitly undefined instruction)
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

// Test: Multiple instructions in sequence
TEST_F(LLVMDisassemblerTest, MultipleInstructions) {
    // NOP; NOP; RET
    std::vector<uint8_t> code = {0x90, 0x90, 0xC3};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 3);
    
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

// Test: CALL to external function (rel32 to external)
TEST_F(LLVMDisassemblerTest, CallExternal) {
    // CALL to 0x7FFC0000 (simulated external address)
    // CALL rel32: E8 FB EF FB 7F (call 0x7FFC0000 from 0x1000)
    // 0x7FFC0000 - 0x1005 = 0x7FFBEFFB (displacement)
    // Bytes: E8 FB EF FB 7F
    std::vector<uint8_t> code = {0xE8, 0xFB, 0xEF, 0xFB, 0x7F};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x7FFC0000);
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

// Test: JMP rel32 with various displacements
TEST_F(LLVMDisassemblerTest, JmpRel32Variants) {
    // JMP +10: E9 0A 00 00 00
    std::vector<uint8_t> code = {0xE9, 0x0A, 0x00, 0x00, 0x00};
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "jmp");
    EXPECT_TRUE(instr.is_jump);
    EXPECT_TRUE(instr.target_address.has_value());
    EXPECT_EQ(instr.target_address.value(), 0x100F);
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

// Test: CALL/JMP near INT64_MAX boundary
TEST_F(LLVMDisassemblerTest, CallRel32NearMax) {
    // CALL to near UINT64_MAX
    // displacement = 0x7FFFFFFA (little-endian FA FF FF 7F)
    // This tests overflow handling
    std::vector<uint8_t> code = {0xE8, 0xFA, 0xFF, 0xFF, 0x7F};  // Large positive displacement
    std::vector<InstructionInfo> instructions;
    
    bool result = disassembler_->disassemble(code, 0x1000, instructions);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(instructions.size(), 1);
    
    const auto& instr = instructions[0];
    EXPECT_EQ(instr.mnemonic, "call");
    EXPECT_TRUE(instr.is_call);
    EXPECT_TRUE(instr.target_address.has_value());
    // Verify overflow wraps correctly: 0x1000 + 5 + 0x7FFFFFFA = 0x80000FFF
    EXPECT_EQ(instr.target_address.value(), 0x80000FFF);
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

