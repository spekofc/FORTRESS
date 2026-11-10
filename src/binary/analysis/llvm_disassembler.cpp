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
#include <mutex>

#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCTargetOptions.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/TargetParser/Triple.h>
#endif

namespace fortress {

// ============================================================================
// LLVMDisassembler Implementation (Internal defined here for PIMPL)
// ============================================================================

#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER

struct LLVMDisassembler::Internal {
    Architecture arch_;
    Endianness endianness_;
    bool is_64bit_;
    bool valid_ = false;
    size_t max_instr_size_ = 15;
    Status status_ = Status::Success;

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

    Internal(Architecture arch, Endianness endianness, bool is_64bit)
        : arch_(arch), endianness_(endianness), is_64bit_(is_64bit) {
        
        // Thread-safe one-time LLVM target initialization
        static std::once_flag init_flag;
        std::call_once(init_flag, []() {
            llvm::InitializeAllTargetInfos();
            llvm::InitializeAllTargets();
            llvm::InitializeAllTargetMCs();
            llvm::InitializeAllDisassemblers();
        });

        if (!validate_architecture_config()) {
            return;
        }

        triple_ = get_triple();
        if (triple_.empty()) {
            status_ = Status::UnsupportedArchitecture;
            return;
        }

        llvm::Triple llvm_triple(triple_);
        std::string error;
        target_ = llvm::TargetRegistry::lookupTarget(llvm_triple, error);
        if (!target_) {
            status_ = Status::InitializationFailed;
            return;
        }

        // Create register info
        mri_ = std::unique_ptr<llvm::MCRegisterInfo>(target_->createMCRegInfo(llvm_triple));
        if (!mri_) {
            status_ = Status::InitializationFailed;
            return;
        }

        // Create asm info
        mai_ = std::unique_ptr<llvm::MCAsmInfo>(target_->createMCAsmInfo(*mri_, llvm_triple, llvm::MCTargetOptions()));
        if (!mai_) {
            status_ = Status::InitializationFailed;
            return;
        }

        // Create instruction info
        mii_ = std::unique_ptr<llvm::MCInstrInfo>(target_->createMCInstrInfo());
        if (!mii_) {
            status_ = Status::InitializationFailed;
            return;
        }

        // Create subtarget info
        std::string cpu = "generic";
        std::string features = "";
        sti_ = std::unique_ptr<llvm::MCSubtargetInfo>(target_->createMCSubtargetInfo(llvm_triple, cpu, features));
        if (!sti_) {
            status_ = Status::InitializationFailed;
            return;
        }

        // Create MCContext
        context_ = std::make_unique<llvm::MCContext>(llvm_triple, mai_.get(), mri_.get(), nullptr);

        // Create disassembler
        disassembler_ = std::unique_ptr<llvm::MCDisassembler>(target_->createMCDisassembler(*sti_, *context_));
        if (!disassembler_) {
            status_ = Status::InitializationFailed;
            return;
        }

        // Create instruction printer
        printer_ = std::unique_ptr<llvm::MCInstPrinter>(target_->createMCInstPrinter(
            llvm_triple,
            llvm::MCInstPrinter::Syntax::Intel,
            *mai_, *mii_, *mri_));
        if (!printer_) {
            status_ = Status::InitializationFailed;
            return;
        }

        valid_ = true;
        status_ = Status::Success;

        // Determine max instruction size based on architecture
        switch (arch_) {
            case Architecture::X64:
            case Architecture::X86:
                max_instr_size_ = 15;
                break;
            case Architecture::ARM64:
                max_instr_size_ = 4;
                break;
            default:
                max_instr_size_ = 16;
                break;
        }
    }

    bool validate_architecture_config() {
        // Validate Architecture + is_64bit combinations
        switch (arch_) {
            case Architecture::X64:
                if (!is_64bit_) {
                    status_ = Status::InvalidConfiguration;
                    return false;
                }
                break;
            case Architecture::X86:
                if (is_64bit_) {
                    status_ = Status::InvalidConfiguration;
                    return false;
                }
                break;
            case Architecture::ARM64:
                if (!is_64bit_) {
                    status_ = Status::InvalidConfiguration;
                    return false;
                }
                break;
            default:
                status_ = Status::UnsupportedArchitecture;
                return false;
        }
        return true;
    }

    std::string get_triple() const {
        // Use format-appropriate triples
        switch (arch_) {
            case Architecture::X64:
                return "x86_64-pc-windows-msvc";
            case Architecture::X86:
                return "i686-pc-windows-msvc";
            case Architecture::ARM64:
                return "aarch64-pc-windows-msvc";
            default:
                return "";
        }
    }

    llvm::MCDisassembler::DecodeStatus decode_instruction(llvm::MCInst& inst,
                                                           uint64_t& size,
                                                           llvm::ArrayRef<uint8_t> bytes,
                                                           uint64_t address) const {
        if (!disassembler_) {
            return llvm::MCDisassembler::Fail;
        }
        return disassembler_->getInstruction(inst, size, bytes, address, llvm::nulls());
    }

    bool disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                     std::vector<InstructionInfo>& instructions) const {
        if (!valid_ || code.empty()) {
            return false;
        }

        instructions.clear();
        instructions.reserve(code.size() / 2);

        size_t offset = 0;
        while (offset < code.size()) {
            // Protect against overflow in base_address + offset
            if (base_address > std::numeric_limits<uint64_t>::max() - offset) {
                return false;
            }
            
            llvm::ArrayRef<uint8_t> bytes(code.data() + offset, code.size() - offset);
            llvm::MCInst inst;
            uint64_t size = 0;

            auto decode_status = decode_instruction(inst, size, bytes, base_address + offset);
            
            if (decode_status != llvm::MCDisassembler::Success || size == 0) {
                // Failed to decode - record as invalid instruction with proper metadata
                InstructionInfo invalid_instr;
                invalid_instr.offset = offset;
                invalid_instr.address = base_address + offset;
                invalid_instr.size = 1;
                invalid_instr.mnemonic = "invalid";
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

            // Basic classification based on mnemonic (simplified without MCInstrAnalysis)
            std::string mnemonic_lower = info.mnemonic;
            std::transform(mnemonic_lower.begin(), mnemonic_lower.end(), mnemonic_lower.begin(), ::tolower);
            
            if (mnemonic_lower.rfind("call", 0) == 0 || mnemonic_lower == "bl" || mnemonic_lower == "blx") {
                info.is_call = true;
            } else if (mnemonic_lower.rfind("jmp", 0) == 0 || mnemonic_lower == "b" || mnemonic_lower == "bra") {
                info.is_jump = true;
            } else if (mnemonic_lower.rfind("ret", 0) == 0) {
                info.is_return = true;
            }
            
            // Check for conditional branches (simplified)
            if (mnemonic_lower.length() > 1 && mnemonic_lower[0] == 'j' && mnemonic_lower != "jmp") {
                info.is_conditional_jump = true;
                info.is_jump = true;
            } else if (mnemonic_lower.length() > 1 && mnemonic_lower[0] == 'b' && mnemonic_lower != "b" && mnemonic_lower != "bl" && mnemonic_lower != "blx") {
                info.is_conditional_jump = true;
                info.is_jump = true;
            }

            instructions.push_back(std::move(info));
            offset += size;
        }

        return !instructions.empty();
    }
};

#endif // FORTRESS_USE_LLVM_DISASSEMBLER

// Stub Internal for when LLVM is disabled - provides consistent layout
#if !defined(FORTRESS_USE_LLVM_DISASSEMBLER) || !FORTRESS_USE_LLVM_DISASSEMBLER
struct LLVMDisassembler::Internal {
    Architecture arch_ = Architecture::Unknown;
    Endianness endianness_ = Endianness::Little;
    bool is_64bit_ = false;
    bool valid_ = false;
    size_t max_instr_size_ = 15;
    Status status_ = Status::UnsupportedArchitecture;

    Internal(Architecture arch, Endianness endianness, bool is_64bit)
        : arch_(arch), endianness_(endianness), is_64bit_(is_64bit) {}

    bool disassemble(const std::vector<uint8_t>&, uint64_t,
                     std::vector<InstructionInfo>&) const { return false; }
};
#endif // FORTRESS_USE_LLVM_DISASSEMBLER

// ============================================================================
// LLVMDisassembler Public Interface
// ============================================================================

LLVMDisassembler::LLVMDisassembler(Architecture arch, Endianness endianness, bool is_64bit) {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    internal_ = std::make_unique<Internal>(arch, endianness, is_64bit);
#else
    internal_ = std::make_unique<Internal>(arch, endianness, is_64bit);
#endif
}

LLVMDisassembler::~LLVMDisassembler() = default;

LLVMDisassembler::LLVMDisassembler(LLVMDisassembler&& other) noexcept = default;
LLVMDisassembler& LLVMDisassembler::operator=(LLVMDisassembler&& other) noexcept = default;

bool LLVMDisassembler::is_valid() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ && internal_->valid_;
#else
    return false;
#endif
}

Architecture LLVMDisassembler::get_architecture() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->arch_ : Architecture::Unknown;
#else
    return Architecture::Unknown;
#endif
}

Endianness LLVMDisassembler::get_endianness() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->endianness_ : Endianness::Little;
#else
    return Endianness::Little;
#endif
}

bool LLVMDisassembler::is_64bit() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->is_64bit_ : false;
#else
    return false;
#endif
}

size_t LLVMDisassembler::get_max_instruction_size() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->max_instr_size_ : 15;
#else
    return 15;
#endif
}

LLVMDisassembler::Status LLVMDisassembler::get_status() const {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    return internal_ ? internal_->status_ : Status::InitializationFailed;
#else
    return Status::UnsupportedArchitecture;
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