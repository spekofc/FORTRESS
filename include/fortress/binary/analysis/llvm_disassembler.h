// FORTRESS LLVM MC Disassembler Interface
// Real instruction decoder using LLVM MC layer

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/core/types.h>
#include <memory>
#include <vector>
#include <optional>

namespace fortress {

class LLVMDisassembler {
public:
    explicit LLVMDisassembler(Architecture arch, Endianness endianness = Endianness::Little, bool is_64bit = true);
    ~LLVMDisassembler(); // Defined in .cpp where Internal is complete

    // Non-copyable, movable
    LLVMDisassembler(const LLVMDisassembler&) = delete;
    LLVMDisassembler& operator=(const LLVMDisassembler&) = delete;
    LLVMDisassembler(LLVMDisassembler&&) noexcept;
    LLVMDisassembler& operator=(LLVMDisassembler&&) noexcept;

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

    // Disassembler status enum for production use
    enum class Status {
        Success,
        UnsupportedArchitecture,
        InvalidConfiguration,
        InitializationFailed,
        DecodeError
    };

    // Get last status (for production error reporting)
    Status get_status() const;

private:
    struct Internal;
    std::unique_ptr<Internal> internal_;
};

} // namespace fortress