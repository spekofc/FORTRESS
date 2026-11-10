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
#include <iostream>

#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInst.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/MC/MCSubtargetInfo.h>
#include <llvm/MC/MCAsmInfo.h>
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
        
        // Thread-safe one-time LLVM target initialization - initialize native target
        static std::once_flag init_flag;
        std::call_once(init_flag, []() {
            llvm::InitializeNativeTarget();
            llvm::InitializeNativeTargetAsmPrinter();
            llvm::InitializeNativeTargetAsmParser();
            llvm::InitializeNativeTargetDisassembler();
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

        // Create instruction printer - use integer syntax variant (0 = Intel, 1 = AT&T)
        printer_ = std::unique_ptr<llvm::MCInstPrinter>(target_->createMCInstPrinter(
            llvm_triple, 0, *mai_, *mii_, *mri_));
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
        // Use format-appropriate triples for cross-platform binary analysis
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
                invalid_instr.format = "at&t";
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
            // LLVM 18+ printInst signature: printInst(const MCInst*, uint64_t, StringRef, const MCSubtargetInfo&, raw_ostream&)
            printer_->printInst(&inst, base_address + offset, "", *sti_, os);
            os.flush();

            // Parse the output: "mnemonic operands" - LLVM outputs AT&T syntax with tabs
            // Example: "\tcallq\t0x401000" or "\tretq" or "\tjmp\t0x401000"
            
            // Trim leading whitespace/tabs
            size_t first_non_ws = asm_string.find_first_not_of(" \t");
            if (first_non_ws != std::string::npos) {
                asm_string = asm_string.substr(first_non_ws);
            }
            
            // Parse the output: "mnemonic operands" - split on whitespace (space or tab)
            size_t space_pos = asm_string.find_first_of(" \t");
            if (space_pos != std::string::npos) {
                info.mnemonic = asm_string.substr(0, space_pos);
                // Skip all whitespace to get operands
                size_t operand_start = asm_string.find_first_not_of(" \t", space_pos);
                if (operand_start != std::string::npos) {
                    info.operands = asm_string.substr(operand_start);
                } else {
                    info.operands = "";
                }
            } else {
                info.mnemonic = asm_string;
                info.operands = "";
            }
            
            // Clean mnemonic: remove suffixes like 'q', 'l', 'w', 'b' for x86-64
            // e.g., "callq" -> "call", "retq" -> "ret", "jmpq" -> "jmp"
            std::string clean_mnemonic = info.mnemonic;
            if (!clean_mnemonic.empty()) {
                char last_char = clean_mnemonic.back();
                if ((last_char == 'q' || last_char == 'l' || last_char == 'w' || last_char == 'b') && clean_mnemonic.length() > 1) {
                    clean_mnemonic.pop_back();
                }
            }
            info.mnemonic = clean_mnemonic;
            
            info.format = "at&t";  // LLVM outputs AT&T syntax
            
            // Parse target address for direct calls and jumps
            std::string operands_lower = info.operands;
            std::transform(operands_lower.begin(), operands_lower.end(), operands_lower.begin(), ::tolower);
            
            // Check for indirect calls/jumps (register or memory indirect)
            if (operands_lower.find('*') != std::string::npos || 
                operands_lower.find('(') != std::string::npos ||
                operands_lower.find('%') != std::string::npos) {
                info.is_indirect = true;
            } else {
                info.is_indirect = false;
            }
            
            // Parse target address based on instruction type
            if (!info.is_indirect) {
                // Check if this is a relative call/jump (CALL/JMP rel32, Jcc rel8/rel32)
                bool is_relative = false;
                if (info.mnemonic == "call" || info.mnemonic == "jmp") {
                    if (size == 5) {  // CALL/JMP rel32 are 5 bytes
                        is_relative = true;
                    }
                } else if (size == 2 && info.mnemonic.length() > 1 && info.mnemonic[0] == 'j') {
                    // Short jumps (Jcc rel8) are 2 bytes
                    is_relative = true;
                } else if (size == 6 && info.mnemonic.length() > 1 && info.mnemonic[0] == 'j') {
                    // Jcc rel32 can be 6 bytes (0F 8x)
                    is_relative = true;
                }
                
                if (is_relative) {
                    // For relative calls/jumps, LLVM prints the displacement
                    // Parse the displacement (try decimal first, then hex, since LLVM prints decimal by default)
                    int64_t displacement = 0;
                    bool has_disp = false;
                    
                    // Try decimal first (LLVM prints relative displacements in decimal by default)
                    size_t dec_start = info.operands.find_first_of("0123456789-");
                    if (dec_start != std::string::npos) {
                        size_t dec_end = dec_start;
                        if (info.operands[dec_start] == '-') {
                            dec_end = dec_start + 1;
                        } else {
                            dec_end = dec_start;
                        }
                        dec_end = info.operands.find_first_not_of("0123456789", dec_end);
                        std::string dec_str = info.operands.substr(dec_start, dec_end - dec_start);
                        try {
                            int64_t disp = std::stoll(info.operands.substr(dec_start, dec_end - dec_start), nullptr, 10);
                            displacement = disp;
                            has_disp = true;
                        } catch (...) {
                            // Ignore parse errors
                        }
                    }
                    
                    // If no decimal, check for hex with 0x/0X prefix
                    if (!has_disp) {
                        size_t hex_start = info.operands.find("0x");
                        if (hex_start == std::string::npos) {
                            hex_start = info.operands.find("0X");
                        }
                        if (hex_start != std::string::npos) {
                            // size_t hex_end = info.operands.find_first_not_of("0123456789abcdefABCDEF", hex_start + 2);
                            try {
                                int64_t disp = std::stoll(info.operands.substr(hex_start), nullptr, 16);
                                displacement = disp;
                                has_disp = true;
                            } catch (...) {
                                // Ignore parse errors
                            }
                        }
                    }
                    
                    // If no hex with prefix, check for hex without prefix (all hex digits, optionally with minus)
                    if (!has_disp) {
                        std::string ops_copy = info.operands;
                        bool all_hex = true;
                        size_t start_idx = 0;
                        if (!ops_copy.empty() && ops_copy[0] == '-') {
                            start_idx = 1;
                        }
                        for (size_t i = start_idx; i < ops_copy.size(); ++i) {
                            char c = ops_copy[i];
                            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                                all_hex = false;
                                break;
                            }
                        }
                        if (all_hex && !ops_copy.empty() && ops_copy != "-") {
                            try {
                                int64_t disp = std::stoll(info.operands, nullptr, 16);
                                displacement = disp;
                                has_disp = true;
                            } catch (...) {
                                // Ignore parse errors
                            }
                        }
                    }
                    
                    // If no hex, check for decimal displacement
                    if (!has_disp) {
                        std::string ops_copy2 = info.operands;
                        size_t dec_start2 = ops_copy2.find_first_of("0123456789-");
                        if (dec_start2 != std::string::npos) {
                            size_t dec_end2 = dec_start2;
                            if (ops_copy2[dec_start2] == '-') {
                                dec_end2 = dec_start2 + 1;
                            } else {
                                dec_end2 = dec_start2;
                            }
                            dec_end2 = ops_copy2.find_first_not_of("0123456789", dec_end2);
                            std::string dec_str = ops_copy2.substr(dec_start2, dec_end2 - dec_start2);
                            try {
                                int64_t disp = std::stoll(dec_str, nullptr, 10);
                                displacement = disp;
                                has_disp = true;
                            } catch (...) {
                                // Ignore parse errors
                            }
                        }
                    }
                    
                    if (has_disp) {
                        // For relative instructions, calculate target = next_instruction + displacement
                        // sign-extend based on instruction type
                        int64_t disp_val = displacement;
                        
                        // sign-extend based on instruction type
                        if (size == 5 && (info.mnemonic == "call" || info.mnemonic == "jmp")) {
                            // rel32: sign-extend from 32-bit
                            if (disp_val > 0x7FFFFFFF) {
                                disp_val -= 0x100000000LL;
                            }
                        } else if (size == 2 && info.mnemonic.length() > 1 && info.mnemonic[0] == 'j') {
                            // rel8 (short jump): sign-extend from 8-bit
                            if (disp_val > 0x7F) {
                                disp_val -= 0x100LL;
                            }
                        } else if (size == 6 && info.mnemonic.length() > 1 && info.mnemonic[0] == 'j') {
                            // Jcc rel32 (0F 8x)
                            if (disp_val > 0x7FFFFFFF) {
                                disp_val -= 0x100000000LL;
                            }
                        }
                        
                        int64_t target = static_cast<int64_t>(base_address + offset) + static_cast<int64_t>(size) + disp_val;
                        info.target_address = static_cast<uint64_t>(target);
                    }
                } else {
                    // Direct absolute call/jump - LLVM prints the target address directly
                    // Try to parse as absolute address (hex with or without 0x prefix, or decimal)
                    
                    // Check for hex with 0x/0X prefix
                    size_t abs_hex_start = info.operands.find("0x");
                    if (abs_hex_start == std::string::npos) {
                        abs_hex_start = info.operands.find("0X");
                    }
                    if (abs_hex_start != std::string::npos) {
                        // size_t hex_end = info.operands.find_first_not_of("0123456789abcdefABCDEF", abs_hex_start + 2);
                        try {
                            uint64_t target_addr = std::stoull(info.operands.substr(abs_hex_start), nullptr, 16);
                            info.target_address = target_addr;
                        } catch (...) {
                            // Ignore parse errors
                        }
                    } else {
                        // If no hex with prefix, check for hex without prefix (all hex digits)
                        std::string abs_ops_copy = info.operands;
                        bool all_hex = true;
                        size_t abs_start_idx = 0;
                        if (!abs_ops_copy.empty() && abs_ops_copy[0] == '-') {
                            // Absolute addresses shouldn't be negative, but handle anyway
                        }
                        for (size_t i = abs_start_idx; i < abs_ops_copy.size(); ++i) {
                            char c = abs_ops_copy[i];
                            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                                all_hex = false;
                                break;
                            }
                        }
                        if (all_hex && !abs_ops_copy.empty() && abs_ops_copy != "-") {
                            try {
                                uint64_t target_addr = std::stoull(info.operands, nullptr, 16);
                                info.target_address = target_addr;
                            } catch (...) {
                                // Ignore parse errors
                            }
                        }
                        
                        // If no hex, check for decimal address
                        size_t abs_digit_start = info.operands.find_first_of("0123456789");
                        if (abs_digit_start != std::string::npos) {
                            size_t abs_digit_end = info.operands.find_first_not_of("0123456789", abs_digit_start);
                            try {
                                uint64_t target_addr = std::stoull(info.operands.substr(abs_digit_start, abs_digit_end - abs_digit_start), nullptr, 10);
                                info.target_address = target_addr;
                            } catch (...) {
                                // Ignore parse errors
                            }
                        }
                    }
                }
            }
            
            info.format = "at&t";  // LLVM outputs AT&T syntax
            
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
            
            // Indirect call detection
            if (info.is_call && info.is_indirect) {
                info.is_indirect = true;
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