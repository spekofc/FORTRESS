// FORTRESS LLVM MC Disassembler Interface
// Real instruction decoder using LLVM MC layer

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/core/types.h>
#include <vector>
#include <optional>

namespace fortress {

class LLVMDisassembler {
public:
    explicit LLVMDisassembler(Architecture arch, Endianness endianness = Endianness::Little, bool is_64bit = true);
    ~LLVMDisassembler() = default;

    // Non-copyable, movable
    LLVMDisassembler(const LLVMDisassembler&) = delete;
    LLVMDisassembler& operator=(const LLVMDisassembler&) = delete;
    LLVMDisassembler(LLVMDisassembler&&) = default;
    LLVMDisassembler& operator=(LLVMDisassembler&&) = default;

    // Check if the disassembler was successfully initialized
    bool is_valid() const;

    // Get disassembler properties
    Architecture get_architecture() const;
    Endianness get_endianness() const;
    bool is_64bit() const;
    size_t get_max_instruction_size() const;

    // Disassemble code bytes
    // Returns true on success (at least one instruction decoded)
    // Fills 'instructions' with decoded instruction information
    bool disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                     std::vector<InstructionInfo>& instructions) const;

private:
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    struct Internal {
        Architecture arch_;
        Endianness endianness_;
        bool is_64bit_;
        bool valid_ = false;
        size_t max_instr_size_ = 15;

        // LLVM MC objects
        std::string triple_;
        const llvm::Target* target_ = nullptr;
        std::unique_ptr<llvm::MCRegisterInfo> mri_;
        std::unique_ptr<llvm::MCAsmInfo> mai_;
        std::unique_ptr<llvm::MCInstrInfo> mii_;
        std::unique_ptr<llvm::MCSubtargetInfo> sti_;
        std::unique_ptr<llvm::MCDisassembler> disassembler_;
        std::unique_ptr<llvm::MCInstPrinter> printer_;
        std::unique_ptr<llvm::MCContext> context_;
        std::unique_ptr<llvm::MCInstrAnalysis> instr_analysis_;

        Internal(Architecture arch, Endianness endianness, bool is_64bit);
        
        std::string get_triple() const;
        llvm::MCDisassembler::DecodeStatus decode_instruction(llvm::MCInst& inst,
                                                               uint64_t& size,
                                                               llvm::ArrayRef<uint8_t> bytes,
                                                               uint64_t address) const;
        void classify_instruction(const llvm::MCInst& inst, InstructionInfo& info) const;
        std::optional<uint64_t> get_call_target(const llvm::MCInst& inst, uint64_t address) const;
        bool disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                         std::vector<InstructionInfo>& instructions) const;
    };
    std::unique_ptr<Internal> internal_;
#else
    Architecture arch_ = Architecture::Unknown;
    Endianness endianness_ = Endianness::Little;
    bool is_64bit_ = false;
    bool valid_ = false;
    size_t max_instr_size_ = 15;
#endif
};

} // namespace fortress