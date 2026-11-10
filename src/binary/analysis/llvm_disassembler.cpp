// FORTRESS LLVM MC Disassembler
// Real instruction decoder using LLVM MC layer

#include <fortress/binary/analysis/llvm_disassembler.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <vector>
#include <string>
#include <memory>
#include <optional>

#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/MemoryBuffer.h>
#endif

namespace fortress {

#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER

LLVMDisassembler::Internal::Internal(Architecture arch, Endianness endianness, bool is_64bit)
    : arch_(arch), endianness_(endianness), is_64bit_(is_64bit) {
    
    // Ensure LLVM targets are initialized
    static bool initialized = false;
    if (!initialized) {
        llvm::InitializeAllTargetInfos();
        llvm::InitializeAllTargets();
        llvm::InitializeAllTargetMCs();
        llvm::InitializeAllDisassemblers();
        initialized = true;
    }

    triple_ = get_triple();
    if (triple_.empty()) {
        return;
    }

    std::string error;
    target_ = llvm::TargetRegistry::lookupTarget(triple_, error);
    if (!target_) {
        return;
    }

    // Create register info
    mri_ = std::unique_ptr<llvm::MCRegisterInfo>(target_->createMCRegInfo(triple_));
    if (!mri_) {
        return;
    }

    // Create asm info
    mai_ = std::unique_ptr<llvm::MCAsmInfo>(target_->createMCAsmInfo(*mri_, triple_, llvm::MCTargetOptions()));
    if (!mai_) {
        return;
    }

    // Create instruction info
    mii_ = std::unique_ptr<llvm::MCInstrInfo>(target_->createMCInstrInfo());
    if (!mii_) {
        return;
    }

    // Create subtarget info
    std::string cpu = "generic";
    std::string features = "";
    sti_ = std::unique_ptr<llvm::MCSubtargetInfo>(target_->createMCSubtargetInfo(triple_, cpu, features));
    if (!sti_) {
        return;
    }

    // Create MCContext
    context_ = std::make_unique<llvm::MCContext>(mai_.get(), mri_.get(), nullptr);

    // Create disassembler
    disassembler_ = std::unique_ptr<llvm::MCDisassembler>(target_->createMCDisassembler(*sti_, *context_));
    if (!disassembler_) {
        return;
    }

    // Create instruction printer
    printer_ = std::unique_ptr<llvm::MCInstPrinter>(target_->createMCInstPrinter(
        llvm::Triple(triple_), 
        llvm::MCInstPrinter::getSyntaxFromString("intel"),
        *mai_, *mii_, *mri_));
    if (!printer_) {
        return;
    }

    // Create instruction analysis
    instr_analysis_ = std::unique_ptr<llvm::MCInstrAnalysis>(target_->createMCInstrAnalysis(mii_.get()));

    valid_ = true;

    // Determine max instruction size based on architecture
    switch (arch_) {
        case Architecture::X64:
        case Architecture::X86:
            max_instr_size_ = 15;
            break;
        case Architecture::ARM64:
            max_instr_size_ = 4;
            break;
        case Architecture::ARM:
            max_instr_size_ = 4;
            break;
        default:
            max_instr_size_ = 16;
            break;
    }
}

std::string LLVMDisassembler::Internal::get_triple() const {
    switch (arch_) {
        case Architecture::X64:
            return is_64bit_ ? "x86_64-pc-windows-msvc" : "i686-pc-windows-msvc";
        case Architecture::X86:
            return is_64bit_ ? "x86_64-pc-windows-msvc" : "i686-pc-windows-msvc";
        case Architecture::ARM64:
            return "aarch64-pc-windows-msvc";
        case Architecture::ARM:
            return "arm-pc-windows-msvc";
        default:
            return "";
    }
}

llvm::MCDisassembler::DecodeStatus LLVMDisassembler::Internal::decode_instruction(
    llvm::MCInst& inst, uint64_t& size, llvm::ArrayRef<uint8_t> bytes, uint64_t address) const {
    if (!disassembler_) {
        return llvm::MCDisassembler::Fail;
    }
    return disassembler_->getInstruction(inst, size, bytes, address, llvm::nulls());
}

void LLVMDisassembler::Internal::classify_instruction(const llvm::MCInst& inst, InstructionInfo& info) const {
    if (!instr_analysis_) {
        return;
    }

    // Check if it's a call
    if (instr_analysis_->isCall(inst)) {
        info.is_call = true;
        auto target = get_call_target(inst, info.address);
        if (target) {
            info.target_address = target.value();
        } else {
            info.is_indirect = true;
        }
    }

    // Check if it's a branch
    if (instr_analysis_->isBranch(inst)) {
        info.is_jump = true;
        if (instr_analysis_->isConditionalBranch(inst)) {
            info.is_conditional_jump = true;
        }
        auto target = instr_analysis_->evaluateBranch(inst, info.address, 
            [](const llvm::MCInst&, uint64_t, uint64_t&) -> bool { return false; });
        if (target.hasValue()) {
            info.target_address = target.getValue();
        } else {
            info.is_indirect = true;
        }
    }

    // Check if it's a return
    if (instr_analysis_->isReturn(inst)) {
        info.is_return = true;
    }
}

std::optional<uint64_t> LLVMDisassembler::Internal::get_call_target(const llvm::MCInst& inst, uint64_t address) const {
    if (!instr_analysis_) {
        return std::nullopt;
    }

    // Try to evaluate the call target
    uint64_t target = 0;
    bool result = instr_analysis_->evaluateCall(inst, address, target);
    if (result) {
        return target;
    }
    return std::nullopt;
}

bool LLVMDisassembler::Internal::disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                                             std::vector<InstructionInfo>& instructions) const {
    if (!valid_ || code.empty()) {
        return false;
    }

    instructions.clear();
    instructions.reserve(code.size() / 2);

    size_t offset = 0;
    while (offset < code.size()) {
        llvm::ArrayRef<uint8_t> bytes(code.data() + offset, code.size() - offset);
        llvm::MCInst inst;
        uint64_t size = 0;

        auto status = decode_instruction(inst, size, bytes, base_address + offset);
        
        if (status != llvm::MCDisassembler::Success || size == 0) {
            // Failed to decode - record as invalid/unknown and advance by 1 byte
            InstructionInfo invalid_instr;
            invalid_instr.offset = offset;
            invalid_instr.address = base_address + offset;
            invalid_instr.size = 1;
            invalid_instr.mnemonic = ".byte";
            invalid_instr.operands = "0x" + std::to_string(code[offset] & 0xFF);
            invalid_instr.bytes = {code[offset]};
            invalid_instr.is_call = false;
            invalid_instr.is_jump = false;
            invalid_instr.is_conditional_jump = false;
            invalid_instr.is_return = false;
            invalid_instr.is_indirect = false;
            invalid_instr.format = "intel";
            instructions.push_back(std::move(invalid_instr));
            offset += 1;
            continue;
        }

        // Successfully decoded
        InstructionInfo info;
        info.offset = offset;
        info.address = base_address + offset;
        info.size = size;
        info.bytes.assign(code.data() + offset, code.data() + offset + size);
        
        // Get mnemonic and operands
        std::string asm_string;
        llvm::raw_string_ostream os(asm_string);
        printer_->printInst(&inst, os, "", *sti_);
        os.flush();

        // Parse the output: "mnemonic operands"
        size_t space_pos = asm_string.find(' ');
        if (space_pos != std::string::npos) {
            info.mnemonic = asm_string.substr(0, space_pos);
            info.operands = asm_string.substr(space_pos + 1);
        } else {
            info.mnemonic = asm_string;
            info.operands = "";
        }
        info.format = "intel";

        // Classify the instruction
        classify_instruction(inst, info);

        instructions.push_back(std::move(info));
        offset += size;
    }

    return !instructions.empty();
}

#endif // FORTRESS_USE_LLVM_DISASSEMBLER

// ============================================================================
// LLVMDisassembler Public Interface
// ============================================================================

LLVMDisassembler::LLVMDisassembler(Architecture arch, Endianness endianness, bool is_64bit) {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    internal_ = std::make_unique<Internal>(arch, endianness, is_64bit);
#else
    (void)arch;
    (void)endianness;
    (void)is_64bit;
    arch_ = arch;
    endianness_ = endianness;
    is_64bit_ = is_64bit;
    valid_ = false;
    max_instr_size_ = 15;
#endif
}

bool LLVMDisassembler::is_valid() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ && internal_->valid_;
#else
    return valid_;
#endif
}

Architecture LLVMDisassembler::get_architecture() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->arch_ : Architecture::Unknown;
#else
    return arch_;
#endif
}

Endianness LLVMDisassembler::get_endianness() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->endianness_ : Endianness::Little;
#else
    return endianness_;
#endif
}

bool LLVMDisassembler::is_64bit() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->is_64bit_ : false;
#else
    return is_64bit_;
#endif
}

size_t LLVMDisassembler::get_max_instruction_size() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->max_instr_size_ : 15;
#else
    return max_instr_size_;
#endif
}

bool LLVMDisassembler::disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                                   std::vector<InstructionInfo>& instructions) const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    if (!internal_ || !internal_->valid_) {
        return false;
    }
    return internal_->disassemble(code, base_address, instructions);
#else
    (void)code;
    (void)base_address;
    (void)instructions;
    return false;
#endif
}

} // namespace fortress