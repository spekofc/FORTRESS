// FORTRESS CFG Builder
// Control Flow Graph construction for binary analysis

#pragma once

#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/core/types.h>
#include <optional>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <memory>

namespace fortress {

// Forward declarations
class Disassembler;

// Disassembler interface for instruction decoding
class Disassembler {
public:
    virtual ~Disassembler() = default;
    virtual bool disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                              std::vector<InstructionInfo>& instructions) const = 0;
    virtual size_t get_max_instruction_size() const = 0;
};

// CFG Edge types
enum class CFGEdgeType : uint8_t {
    Fallthrough = 0,      // Sequential execution (fallthrough)
    ConditionalBranch,    // Conditional jump (jcc)
    UnconditionalBranch,  // Unconditional jump (jmp)
    Call,                 // Function call
    Return,               // Function return (ret)
    IndirectBranch,       // Indirect jump (jmp reg/mem)
    IndirectCall,         // Indirect call (call reg/mem)
    ExceptionEdge,        // Exception handling edge
    InterruptEdge,        // Interrupt/syscall edge
    Unknown               // Unknown edge type
};

// CFG Edge
struct CFGEdge {
    uint32_t source_block_id = 0;
    uint32_t target_block_id = 0;
    CFGEdgeType type = CFGEdgeType::Unknown;
    bool is_resolved = true;
    std::optional<uint64_t> target_address; // For indirect edges
    std::string condition; // For conditional branches (e.g., "ZF=1")

    CFGEdge() = default;
    CFGEdge(uint32_t src, uint32_t dst, CFGEdgeType t, bool resolved = true)
        : source_block_id(src), target_block_id(dst), type(t), is_resolved(resolved) {}
};

// Basic Block
struct BasicBlock {
    uint32_t id = 0;
    uint64_t start_address = 0;  // VA
    uint64_t start_offset = 0;   // File offset
    size_t size = 0;
    std::vector<uint8_t> bytes;
    std::vector<InstructionInfo> instructions;
    
    // CFG edges
    std::vector<CFGEdge> successors;
    std::vector<uint32_t> predecessors;
    
    // Block properties
    bool is_entry = false;
    bool is_exit = false;
    bool is_entry_block = false;  // Function entry block
    bool has_return = false;
    bool has_call = false;
    bool has_indirect_branch = false;
    
    // Loop analysis
    uint32_t loop_depth = 0;
    uint32_t loop_header_id = 0;
    
    // Dominance
    uint32_t immediate_dominator = UINT32_MAX;
    std::vector<uint32_t> dominance_frontier;
    
    // Statistics
    size_t instruction_count = 0;
    size_t max_instruction_length = 0;
    
    BasicBlock() = default;
    BasicBlock(uint32_t id_, uint64_t addr_, size_t size_)
        : id(id_), start_address(addr_), size(size_) {}
};

// Control Flow Graph
struct ControlFlowGraph {
    FunctionInfo function;
    std::vector<BasicBlock> blocks;
    std::unordered_map<uint64_t, uint32_t> address_to_block; // VA -> block id
    std::unordered_map<uint64_t, uint32_t> offset_to_block;  // File offset -> block id
    
    // Graph properties
    uint32_t entry_block = 0;
    std::vector<uint32_t> exit_blocks;
    std::vector<uint32_t> unreachable_blocks;
    
    // Loop information
    struct LoopInfo {
        uint32_t header_id = 0;
        std::vector<uint32_t> body_blocks;
        uint32_t depth = 0;
        bool is_reducible = true;
    };
    std::vector<LoopInfo> loops;
    
    // Dominator tree
    std::vector<uint32_t> dominator_tree; // immediate dominator for each block
    
    // Statistics
    size_t total_instructions = 0;
    size_t total_edges = 0;
    size_t max_block_size = 0;
    size_t max_successors = 0;
    
    // Metadata
    bool is_valid = false;
    std::string error_message;
    std::vector<std::string> warnings;
    
    ControlFlowGraph() = default;
    
    // Get block by ID
    const BasicBlock* get_block(uint32_t id) const {
        if (id < blocks.size()) return &blocks[id];
        return nullptr;
    }
    
    BasicBlock* get_block(uint32_t id) {
        if (id < blocks.size()) return &blocks[id];
        return nullptr;
    }
    
    // Get block containing address
    const BasicBlock* find_block_containing(uint64_t address) const {
        auto it = address_to_block.find(address);
        if (it != address_to_block.end()) return get_block(it->second);
        return nullptr;
    }
    
    // Get block containing file offset
    const BasicBlock* find_block_by_offset(uint64_t offset) const {
        auto it = offset_to_block.find(offset);
        if (it != offset_to_block.end()) return get_block(it->second);
        return nullptr;
    }
    
    // Validate CFG structure
    bool validate(std::string& error) const;
    
    // Export to JSON
    std::string to_json() const;
    
    // Export to GraphViz DOT
    std::string to_dot(const std::string& graph_name = "cfg") const;
    
    // Summary
    std::string summary() const;
};

// CFG Builder configuration
struct CFGBuilderConfig {
    // Disassembly options
    size_t max_instructions_per_block = 1000;
    size_t max_blocks = 10000;
    size_t max_total_instructions = 100000;
    
    // Analysis options
    bool resolve_indirect_branches = false;
    bool follow_indirect_calls = false;
    bool follow_returns = true;
    bool identify_loops = true;
    bool compute_dominators = true;
    bool identify_unreachable = true;
    
    // Architecture-specific
    bool treat_call_as_block_end = true;
    bool treat_return_as_block_end = true;
    bool treat_indirect_jump_as_block_end = true;
    
    // Architecture-specific instruction patterns
    std::vector<std::string> call_mnemonics = {"call", "bl", "jal", "blx"};
    std::vector<std::string> return_mnemonics = {"ret", "retn", "retf", "bx lr", "bxlr"};
    std::vector<std::string> conditional_branch_mnemonics = {
        "jcc", "jz", "jnz", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
        "jo", "jno", "js", "jns", "jp", "jnp", "jpe", "jpo",
        "beq", "bne", "bgt", "bge", "blt", "ble", "bgt", "bge",
        "bne", "beq", "blt", "ble", "bgt", "bge"
    };
    std::vector<std::string> unconditional_branch_mnemonics = {"jmp", "b", "bra", "j"};
    std::vector<std::string> indirect_branch_mnemonics = {"jmp", "jmpq", "jmpl", "bx", "br", "jr"};
    
    // Architecture-specific register names for indirect branch detection
    std::unordered_set<std::string> call_registers = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                                       "eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    
    CFGBuilderConfig() = default;
};

// CFG Builder result
struct CFGBuilderResult {
    std::unique_ptr<ControlFlowGraph> cfg;
    bool success = false;
    std::string error;
    std::vector<std::string> warnings;
    size_t blocks_created = 0;
    size_t instructions_processed = 0;
    size_t edges_created = 0;
    
    CFGBuilderResult() = default;
    explicit CFGBuilderResult(std::unique_ptr<ControlFlowGraph> cfg_)
        : cfg(std::move(cfg_)), success(true) {}
    CFGBuilderResult(const std::string& error_)
        : success(false), error(error_) {}
};

// Main CFG Builder class
class CFGBuilder {
public:
    explicit CFGBuilder(const CFGBuilderConfig& config = CFGBuilderConfig());
    ~CFGBuilder();
    
    // Build CFG for a single function
    CFGBuilderResult build_cfg(const FunctionInfo& function,
                                const BinaryAnalysisResult& analysis,
                                const std::vector<uint8_t>& code_bytes,
                                uint64_t code_base_address);
    
    // Build CFGs for all functions in analysis
    std::vector<CFGBuilderResult> build_all_cfgs(const BinaryAnalysisResult& analysis,
                                                  const std::vector<uint8_t>& code_bytes,
                                                  uint64_t code_base_address);
    
    // Set custom disassembler (optional)
    void set_disassembler(std::shared_ptr<Disassembler> disassembler);
    
    // Create disassembler for the given architecture (public for testing)
    static std::shared_ptr<Disassembler> create_disassembler(const BinaryAnalysisResult& analysis);
    
    // Get configuration
    const CFGBuilderConfig& get_config() const { return config_; }
    void set_config(const CFGBuilderConfig& config) { config_ = config; }

private:
    CFGBuilderConfig config_;
    std::shared_ptr<Disassembler> disassembler_;
    
    // Internal context for building
    struct BuildContext;
    
    // Internal implementation
    CFGBuilderResult build_cfg_internal(const FunctionInfo& function,
                                         const BinaryAnalysisResult& analysis,
                                         const std::vector<uint8_t>& code_bytes,
                                         uint64_t code_base_address);
    
    // Instruction classification
    struct InstructionClassification {
        bool is_call = false;
        bool is_return = false;
        bool is_conditional_branch = false;
        bool is_unconditional_branch = false;
        bool is_indirect_branch = false;
        bool is_indirect_call = false;
        std::optional<uint64_t> target_address;
        std::string condition;
    };
    
    InstructionClassification classify_instruction(const InstructionInfo& instr,
                                                    const FunctionInfo& function) const;
    
    // Disassembly
    bool disassemble_function(BuildContext& ctx);
    
    // Block building
    std::vector<uint64_t> identify_leaders(const std::vector<InstructionInfo>& instructions,
                                           const FunctionInfo& function) const;
    std::vector<BasicBlock> build_basic_blocks(const std::vector<InstructionInfo>& instructions,
                                                const std::vector<uint64_t>& leaders,
                                                const FunctionInfo& function,
                                                uint64_t code_base_address);
    
    // CFG structure
    bool build_cfg_structure(BuildContext& ctx);
    
    // Edge construction
    void build_edges(ControlFlowGraph& cfg, const FunctionInfo& function);
    void add_edge(ControlFlowGraph& cfg, uint32_t src_id, uint32_t dst_id,
                  CFGEdgeType type, bool resolved,
                  std::optional<uint64_t> target_addr = std::nullopt);
    void add_edge(ControlFlowGraph& cfg, uint32_t src_id, uint64_t target_addr,
                  CFGEdgeType type, bool resolved);
    
    // Loop detection
    void identify_loops(ControlFlowGraph& cfg);
    bool is_back_edge(uint32_t src_id, uint32_t dst_id) const;
    struct LoopInfo {
        uint32_t header = 0;
        std::vector<uint32_t> body;
        uint32_t depth = 0;
        bool is_reducible = true;
    };
    std::vector<LoopInfo> find_loops(const ControlFlowGraph& cfg);
    
    // Dominator tree construction
    void compute_dominators(ControlFlowGraph& cfg);
    uint32_t intersect_dominators(const ControlFlowGraph& cfg, 
                                   uint32_t b1, uint32_t b2) const;
    
    // Unreachable code detection
    void identify_unreachable_blocks(ControlFlowGraph& cfg);
    
    // Validation
    bool validate_cfg(const ControlFlowGraph& cfg, std::string& error) const;
    
    // JSON/DOT export helpers
    std::string cfg_to_json(const ControlFlowGraph& cfg) const;
    std::string cfg_to_dot(const ControlFlowGraph& cfg, const std::string& graph_name) const;
};

// ============================================================================
// CFG String Conversions
// ============================================================================

inline std::string to_string(CFGEdgeType type) {
    switch (type) {
        case CFGEdgeType::Fallthrough: return "Fallthrough";
        case CFGEdgeType::ConditionalBranch: return "ConditionalBranch";
        case CFGEdgeType::UnconditionalBranch: return "UnconditionalBranch";
        case CFGEdgeType::Call: return "Call";
        case CFGEdgeType::Return: return "Return";
        case CFGEdgeType::IndirectBranch: return "IndirectBranch";
        case CFGEdgeType::IndirectCall: return "IndirectCall";
        case CFGEdgeType::ExceptionEdge: return "ExceptionEdge";
        case CFGEdgeType::InterruptEdge: return "InterruptEdge";
        default: return "Unknown";
    }
}

} // namespace fortress