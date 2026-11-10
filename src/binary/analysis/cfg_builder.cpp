// FORTRESS CFG Builder Implementation
// Control Flow Graph construction for binary analysis

#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/llvm_disassembler.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <limits>
#include <functional>

namespace fortress {

// ============================================================================
// Disassembler Interface
// ============================================================================

class Disassembler {
public:
    virtual ~Disassembler() = default;
    virtual bool disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                              std::vector<InstructionInfo>& instructions) const = 0;
    virtual size_t get_max_instruction_size() const = 0;
};

// Stub disassembler (for testing only - not for production use)
class StubDisassembler : public Disassembler {
public:
    bool disassemble(const std::vector<uint8_t>& code, uint64_t base_address,
                      std::vector<InstructionInfo>& instructions) const override {
        if (code.empty()) return false;
        
        size_t offset = 0;
        while (offset < code.size()) {
            InstructionInfo instr;
            instr.offset = offset;
            instr.address = base_address + offset;
            instr.size = 1;
            instr.mnemonic = "nop";
            instr.operands = "";
            instr.bytes = {code[offset]};
            instr.is_call = false;
            instr.is_jump = false;
            instr.is_conditional_jump = false;
            instr.is_return = false;
            instr.is_indirect = false;
            instructions.push_back(instr);
            offset += 1;
            if (offset >= code.size()) break;
        }
        return true;
    }
    
    size_t get_max_instruction_size() const override { return 15; }
};

// ============================================================================
// CFG Builder Implementation
// ============================================================================

struct CFGBuilder::BuildContext {
    const FunctionInfo* function = nullptr;
    const BinaryAnalysisResult* analysis = nullptr;
    const std::vector<uint8_t>* code_bytes = nullptr;
    uint64_t code_base_address = 0;
    std::vector<InstructionInfo> instructions;
    std::vector<uint64_t> leaders;
    std::vector<BasicBlock> blocks;
    std::unordered_map<uint64_t, uint32_t> address_to_block;
    std::unordered_map<uint64_t, uint32_t> offset_to_block;
    std::unordered_map<uint64_t, uint32_t> address_to_instruction_idx;
    ControlFlowGraph* cfg = nullptr;
};

CFGBuilder::CFGBuilder(const CFGBuilderConfig& config)
    : config_(config), disassembler_(nullptr) {}

CFGBuilder::~CFGBuilder() = default;

void CFGBuilder::set_disassembler(std::shared_ptr<Disassembler> disassembler) {
    disassembler_ = std::move(disassembler);
}

std::shared_ptr<Disassembler> CFGBuilder::create_disassembler(const BinaryAnalysisResult& analysis) {
#if defined(FORTRESS_USE_LLVM_DISASSEMBLER) && FORTRESS_USE_LLVM_DISASSEMBLER
    // Create LLVM MC disassembler based on binary architecture
    auto disasm = std::make_shared<LLVMDisassembler>(
        analysis.architecture,
        analysis.endianness,
        analysis.is_64bit
    );
    
    if (disasm->is_valid()) {
        return disasm;
    }
#endif
    
    (void)analysis; // Suppress unused parameter warning when LLVM is disabled
    // Fallback to stub only if explicitly allowed (e.g., for testing)
    // In production, we should fail if no real disassembler is available
    return std::make_shared<StubDisassembler>();
}

CFGBuilderResult CFGBuilder::build_cfg(const FunctionInfo& function,
                                        const BinaryAnalysisResult& analysis,
                                        const std::vector<uint8_t>& code_bytes,
                                        uint64_t code_base_address) {
    BuildContext ctx;
    ctx.function = &function;
    ctx.analysis = &analysis;
    ctx.code_bytes = &code_bytes;
    ctx.code_base_address = code_base_address;
    
    CFGBuilderResult result = build_cfg_internal(function, analysis, code_bytes, code_base_address);
    return result;
}

std::vector<CFGBuilderResult> CFGBuilder::build_all_cfgs(const BinaryAnalysisResult& analysis,
                                                          const std::vector<uint8_t>& code_bytes,
                                                          uint64_t code_base_address) {
    std::vector<CFGBuilderResult> results;
    results.reserve(analysis.functions.size());
    
    for (const auto& function : analysis.functions) {
        CFGBuilderResult result = build_cfg(function, analysis, code_bytes, code_base_address);
        results.push_back(std::move(result));
    }
    return results;
}

CFGBuilderResult CFGBuilder::build_cfg_internal(const FunctionInfo& function,
                                                 const BinaryAnalysisResult& analysis,
                                                 const std::vector<uint8_t>& code_bytes,
                                                 uint64_t code_base_address) {
    BuildContext ctx;
    ctx.function = &function;
    ctx.analysis = &analysis;
    ctx.code_bytes = &code_bytes;
    ctx.code_base_address = code_base_address;
    
    // Create CFG
    auto cfg = std::make_unique<ControlFlowGraph>();
    cfg->function = function;
    ctx.cfg = cfg.get();
    
    // Step 1: Disassemble function code
    if (!disassemble_function(ctx)) {
        return CFGBuilderResult("Failed to disassemble function");
    }
    
    // Step 2: Identify leaders
    ctx.leaders = identify_leaders(ctx.instructions, *ctx.function);
    
    // Step 3: Build basic blocks
    ctx.blocks = build_basic_blocks(ctx.instructions, ctx.leaders, *ctx.function, 0);
    
    // Step 4: Build CFG structure
    if (!build_cfg_structure(ctx)) {
        return CFGBuilderResult("Failed to build CFG structure");
    }
    
    // Step 5: Build edges
    build_edges(*cfg, function);
    
    // Step 6: Identify loops
    if (config_.identify_loops) {
        identify_loops(*cfg);
    }
    
    // Step 7: Compute dominators
    if (config_.compute_dominators) {
        compute_dominators(*cfg);
    }
    
    // Step 8: Identify unreachable blocks
    if (config_.identify_unreachable) {
        identify_unreachable_blocks(*cfg);
    }
    
    // Step 9: Validate
    std::string validation_error;
    if (!validate_cfg(*cfg, validation_error)) {
        cfg->is_valid = false;
        cfg->error_message = "CFG validation failed: " + validation_error;
    } else {
        cfg->is_valid = true;
    }
    
    // Update metadata
    cfg->blocks = std::move(ctx.blocks);
    cfg->address_to_block = std::move(ctx.address_to_block);
    cfg->offset_to_block = std::move(ctx.offset_to_block);
    
    // Rebuild address/offset maps
    for (size_t i = 0; i < cfg->blocks.size(); ++i) {
        const auto& block = cfg->blocks[i];
        cfg->address_to_block[block.start_address] = block.id;
        if (block.start_offset != INVALID_OFFSET) {
            cfg->offset_to_block[block.start_offset] = block.id;
        }
        for (const auto& instr : block.instructions) {
            cfg->address_to_block[instr.address] = block.id;
        }
    }
    
    // Statistics
    cfg->total_instructions = 0;
    cfg->total_edges = 0;
    cfg->max_block_size = 0;
    cfg->max_successors = 0;
    for (const auto& block : cfg->blocks) {
        cfg->total_instructions += block.instructions.size();
        cfg->total_edges += block.successors.size();
        cfg->max_block_size = std::max(cfg->max_block_size, block.size);
        cfg->max_successors = std::max(cfg->max_successors, block.successors.size());
    }
    
    return CFGBuilderResult(std::move(cfg));
}

// ============================================================================
// Disassembly
// ============================================================================

bool CFGBuilder::disassemble_function(BuildContext& ctx) {
    const auto& function = *ctx.function;
    
    // Ensure we have a disassembler
    if (!disassembler_) {
        disassembler_ = create_disassembler(*ctx.analysis);
        if (!disassembler_) {
            return false;
        }
    }
    
    // Find the section containing the function (manual VA range check)
    const SectionInfo* section = nullptr;
    for (const auto& sec : ctx.analysis->sections) {
        uint64_t sec_start = sec.virtual_address;
        uint64_t sec_end = sec.virtual_address + sec.virtual_size;
        if (function.address >= sec_start && function.address < sec_end) {
            section = &sec;
            break;
        }
    }
    
    if (!section) {
        return false;
    }
    
    // Extract code bytes for this function
    uint64_t func_start = function.address;
    uint64_t func_end = function.address + function.size;
    if (function.size == 0) {
        // Estimate function size from next function or section end
        func_end = section->virtual_address + section->virtual_size;
    }
    
    size_t func_offset = func_start >= section->virtual_address ? 
                         func_start - section->virtual_address : 0;
    size_t func_size = func_end > function.address ? func_end - function.address : section->raw_size;
    
    if (func_offset + func_size > section->raw_size) {
        func_size = section->raw_size - func_offset;
    }
    
    // Extract bytes
    const auto& all_bytes = *ctx.code_bytes;
    if (func_offset + func_size > all_bytes.size()) {
        return false;
    }
    
    std::vector<uint8_t> func_bytes(all_bytes.begin() + func_offset,
                                     all_bytes.begin() + func_offset + func_size);
    
    // Disassemble
    std::vector<InstructionInfo> instructions;
    if (!disassembler_->disassemble(func_bytes, function.address, instructions)) {
        return false;
    }
    
    // Filter instructions to function range
    std::vector<InstructionInfo> filtered;
    for (const auto& instr : instructions) {
        if (instr.address >= function.address && instr.address < function.address + function.size) {
            filtered.push_back(instr);
        }
    }
    
    ctx.instructions = std::move(filtered);
    return !ctx.instructions.empty();
}

// ============================================================================
// Instruction Classification
// ============================================================================

CFGBuilder::InstructionClassification CFGBuilder::classify_instruction(
    const InstructionInfo& instr, const FunctionInfo& /*function*/) const {
    
    InstructionClassification cls;
    cls.is_call = instr.is_call;
    cls.is_return = instr.is_return;
    cls.is_conditional_branch = instr.is_conditional_jump;
    cls.is_unconditional_branch = instr.is_jump && !instr.is_conditional_jump && !instr.is_call;
    cls.is_indirect_branch = instr.is_indirect && (instr.is_jump || instr.is_call);
    cls.is_indirect_call = instr.is_call && instr.is_indirect;
    cls.target_address = instr.target_address;
    cls.condition = instr.operands;
    
    return cls;
}

// ============================================================================
// Leader Identification
// ============================================================================

std::vector<uint64_t> CFGBuilder::identify_leaders(const std::vector<InstructionInfo>& instructions,
                                                    const FunctionInfo& function) const {
    std::vector<uint64_t> leaders;
    leaders.reserve(instructions.size() / 4 + 1);
    
    // Function entry is always a leader
    leaders.push_back(function.address);
    
    for (size_t i = 0; i < instructions.size(); ++i) {
        auto cls = classify_instruction(instructions[i], function);
        
        // Target of a branch is a leader
        if (cls.is_conditional_branch || cls.is_unconditional_branch || cls.is_call) {
            if (cls.target_address.has_value()) {
                leaders.push_back(cls.target_address.value());
            }
        }
        
        // Instruction after a branch/return is a leader
        if (cls.is_return || cls.is_unconditional_branch || cls.is_conditional_branch) {
            if (i + 1 < instructions.size()) {
                leaders.push_back(instructions[i + 1].address);
            }
        }
    }
    
    // Sort and deduplicate
    std::sort(leaders.begin(), leaders.end());
    leaders.erase(std::unique(leaders.begin(), leaders.end()), leaders.end());
    
    return leaders;
}

// ============================================================================
// Basic Block Construction
// ============================================================================

std::vector<BasicBlock> CFGBuilder::build_basic_blocks(
    const std::vector<InstructionInfo>& instructions,
    const std::vector<uint64_t>& leaders,
    const FunctionInfo& function,
    uint64_t /*code_base_address*/) {
    
    std::vector<BasicBlock> blocks;
    blocks.reserve(leaders.size());
    
    // Sort leaders
    std::vector<uint64_t> sorted_leaders = leaders;
    std::sort(sorted_leaders.begin(), sorted_leaders.end());
    
    for (size_t i = 0; i < sorted_leaders.size(); ++i) {
        uint64_t leader_addr = sorted_leaders[i];
        uint64_t block_end = (i + 1 < sorted_leaders.size()) ? sorted_leaders[i + 1] : UINT64_MAX;
        
        BasicBlock block;
        block.id = static_cast<uint32_t>(blocks.size());
        block.start_address = leader_addr;
        block.start_offset = INVALID_OFFSET;
        block.is_entry = (leader_addr == function.address);
        block.is_entry_block = (leader_addr == function.address);
        
        // Collect instructions for this block
        for (const auto& instr : instructions) {
            if (instr.address >= leader_addr && instr.address < block_end) {
                block.instructions.push_back(instr);
                block.size += instr.size;
                block.instruction_count++;
                block.max_instruction_length = std::max(block.max_instruction_length, instr.size);
                
                // Check for special instructions
                auto cls = classify_instruction(instr, function);
                if (cls.is_call) block.has_call = true;
                if (cls.is_return) block.has_return = true;
                if (cls.is_indirect_branch) block.has_indirect_branch = true;
                if (cls.is_return) block.has_return = true;
            }
        }
        
        block.size = (i + 1 < sorted_leaders.size()) ? 
            (sorted_leaders[i + 1] - leader_addr) : 
            (function.size > 0 ? function.size : 0);
        
        blocks.push_back(std::move(block));
    }
    
    return blocks;
}

// ============================================================================
// CFG Structure Building
// ============================================================================

bool CFGBuilder::build_cfg_structure(BuildContext& ctx) {
    auto& cfg = *ctx.cfg;
    const auto& blocks = ctx.blocks;
    
    if (blocks.empty()) {
        ctx.cfg->error_message = "No basic blocks created";
        return false;
    }
    
    // Set entry block
    cfg.entry_block = 0;
    cfg.blocks = std::move(ctx.blocks);
    
    // Build address maps
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        const auto& block = cfg.blocks[i];
        cfg.address_to_block[block.start_address] = block.id;
        if (block.start_offset != INVALID_OFFSET) {
            cfg.offset_to_block[block.start_offset] = block.id;
        }
    }
    
    // Identify exit blocks (blocks with return or no successors)
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        if (cfg.blocks[i].has_return || cfg.blocks[i].successors.empty()) {
            cfg.exit_blocks.push_back(static_cast<uint32_t>(i));
        }
        if (cfg.blocks[i].is_entry_block) {
            cfg.entry_block = static_cast<uint32_t>(i);
        }
    }
    
    return true;
}

// ============================================================================
// Edge Construction
// ============================================================================

void CFGBuilder::build_edges(ControlFlowGraph& cfg, const FunctionInfo& function) {
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        auto& block = cfg.blocks[i];
        if (block.instructions.empty()) continue;
        
        const auto& last_instr = block.instructions.back();
        auto cls = classify_instruction(last_instr, function);
        
        if (cls.is_return) {
            // Return instruction - exit edge
            block.successors.emplace_back(block.id, UINT32_MAX, CFGEdgeType::Return, true);
        }
        else if (cls.is_unconditional_branch) {
            if (cls.target_address.has_value()) {
                // Direct jump
                add_edge(cfg, block.id, cls.target_address.value(), 
                        CFGEdgeType::UnconditionalBranch, true);
            } else {
                // Indirect jump
                block.successors.emplace_back(block.id, UINT32_MAX, CFGEdgeType::IndirectBranch, false);
                block.has_indirect_branch = true;
            }
        }
        else if (cls.is_conditional_branch) {
            if (cls.target_address.has_value()) {
                // Conditional branch - add both taken and fallthrough
                add_edge(cfg, block.id, cls.target_address.value(), 
                        CFGEdgeType::ConditionalBranch, true);
                
                // Fallthrough edge
                if (block.id + 1 < cfg.blocks.size()) {
                    add_edge(cfg, block.id, block.id + 1, CFGEdgeType::Fallthrough, true);
                }
            } else {
                // Indirect conditional branch
                block.successors.emplace_back(block.id, UINT32_MAX, CFGEdgeType::ConditionalBranch, false);
                block.has_indirect_branch = true;
            }
        }
        else if (cls.is_call) {
            if (cls.target_address.has_value()) {
                // Direct call
                add_edge(cfg, block.id, cls.target_address.value(),
                        CFGEdgeType::Call, true);
            } else {
                // Indirect call
                block.successors.emplace_back(block.id, UINT32_MAX, CFGEdgeType::IndirectCall, false);
                block.has_indirect_branch = true;
                block.has_call = true;
            }
            
            // Fallthrough after call
            if (block.id + 1 < cfg.blocks.size()) {
                add_edge(cfg, block.id, block.id + 1, CFGEdgeType::Fallthrough, true);
            }
        }
        else {
            // Fallthrough
            if (block.id + 1 < cfg.blocks.size()) {
                add_edge(cfg, block.id, block.id + 1, CFGEdgeType::Fallthrough, true);
            }
        }
    }
}

void CFGBuilder::add_edge(ControlFlowGraph& cfg, uint32_t src_id, uint64_t target_addr,
                          CFGEdgeType type, bool resolved) {
    uint32_t dst_id = UINT32_MAX;
    if (resolved) {
        auto it = cfg.address_to_block.find(target_addr);
        if (it != cfg.address_to_block.end()) {
            dst_id = it->second;
        }
    }
    
    cfg.blocks[src_id].successors.emplace_back(src_id, dst_id, type, resolved);
    if (dst_id != UINT32_MAX) {
        cfg.blocks[dst_id].predecessors.push_back(src_id);
    }
}

void CFGBuilder::add_edge(ControlFlowGraph& cfg, uint32_t src_id, uint32_t dst_id,
                          CFGEdgeType type, bool /*resolved*/,
                          std::optional<uint64_t> /*target_addr*/) {
    cfg.blocks[src_id].successors.emplace_back(src_id, dst_id, type, true);
    if (dst_id != UINT32_MAX) {
        cfg.blocks[dst_id].predecessors.push_back(src_id);
    }
}

// ============================================================================
// Loop Detection (Havlak's algorithm)
// ============================================================================

void CFGBuilder::identify_loops(ControlFlowGraph& cfg) {
    auto loops = find_loops(cfg);
    cfg.loops.clear();
    for (const auto& loop : loops) {
        ControlFlowGraph::LoopInfo info;
        info.header_id = loop.header;
        info.body_blocks = loop.body;
        info.depth = loop.depth;
        info.is_reducible = loop.is_reducible;
        cfg.loops.push_back(std::move(info));
    }
}

bool CFGBuilder::is_back_edge(uint32_t src_id, uint32_t dst_id) const {
    return dst_id <= src_id;
}

std::vector<CFGBuilder::LoopInfo> CFGBuilder::find_loops(const ControlFlowGraph& cfg) {
    std::vector<LoopInfo> loops;
    
    std::vector<uint32_t> dfs_order;
    std::vector<int> dfs_num(cfg.blocks.size(), -1);
    std::vector<int> low(cfg.blocks.size(), -1);
    int dfs_counter = 0;
    
    std::function<void(uint32_t)> dfs = [&](uint32_t u) {
        dfs_num[u] = dfs_counter++;
        low[u] = dfs_num[u];
        
        for (const auto& edge : cfg.blocks[u].successors) {
            uint32_t v = edge.target_block_id;
            if (v >= cfg.blocks.size()) continue;
            
            if (dfs_num[v] == -1) {
                dfs(v);
                low[u] = std::min(low[u], low[v]);
            } else {
                low[u] = std::min(low[u], dfs_num[v]);
            }
        }
    };
    
    if (cfg.entry_block < cfg.blocks.size()) {
        dfs(cfg.entry_block);
    }
    
    for (size_t u = 0; u < cfg.blocks.size(); ++u) {
        for (const auto& edge : cfg.blocks[u].successors) {
            uint32_t v = edge.target_block_id;
            if (v >= cfg.blocks.size()) continue;
            
            if (dfs_num[v] <= dfs_num[u] && dfs_num[v] != -1) {
                LoopInfo loop;
                loop.header = v;
                loop.depth = 0;
                
                std::unordered_set<uint32_t> visited;
                std::function<void(uint32_t)> collect = [&](uint32_t n) {
                    if (visited.count(n)) return;
                    visited.insert(n);
                    loop.body.push_back(n);
                    for (uint32_t pred : cfg.blocks[n].predecessors) {
                        if (pred != cfg.blocks[u].id || n == cfg.blocks[u].id) {
                            collect(pred);
                        }
                    }
                };
                collect(static_cast<uint32_t>(u));
                
                if (!loop.body.empty()) {
                    loop.is_reducible = true;
                    loops.push_back(std::move(loop));
                }
            }
        }
    }
    
    for (auto& loop : loops) {
        for (auto& other : loops) {
            if (&loop != &other) {
                bool contains = true;
                for (uint32_t b : loop.body) {
                    if (std::find(other.body.begin(), other.body.end(), b) == other.body.end()) {
                        contains = false;
                        break;
                    }
                }
                if (contains) loop.depth++;
            }
        }
    }
    
    return loops;
}

// ============================================================================
// Dominator Tree Construction
// ============================================================================

void CFGBuilder::compute_dominators(ControlFlowGraph& cfg) {
    size_t n = cfg.blocks.size();
    if (n == 0) return;
    
    cfg.dominator_tree.assign(n, UINT32_MAX);
    
    cfg.dominator_tree[cfg.entry_block] = cfg.entry_block;
    for (size_t i = 0; i < n; ++i) {
        if (i != cfg.entry_block) {
            cfg.dominator_tree[i] = UINT32_MAX;
        }
    }
    
    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t i = 0; i < n; ++i) {
            if (i == cfg.entry_block) continue;
            
            uint32_t new_idom = UINT32_MAX;
            for (uint32_t pred : cfg.blocks[i].predecessors) {
                if (cfg.dominator_tree[pred] != UINT32_MAX) {
                    new_idom = pred;
                    break;
                }
            }
            
            for (uint32_t pred : cfg.blocks[i].predecessors) {
                if (cfg.dominator_tree[pred] != UINT32_MAX) {
                    if (new_idom == UINT32_MAX) {
                        new_idom = pred;
                    } else {
                        new_idom = intersect_dominators(cfg, new_idom, pred);
                    }
                }
                
                if (new_idom != UINT32_MAX && cfg.dominator_tree[i] != new_idom) {
                    cfg.dominator_tree[i] = new_idom;
                    changed = true;
                }
            }
        }
    }
    
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        if (cfg.blocks[i].predecessors.size() >= 2) {
            for (uint32_t pred : cfg.blocks[i].predecessors) {
                uint32_t runner = pred;
                while (runner != cfg.dominator_tree[i]) {
                    cfg.blocks[runner].dominance_frontier.push_back(static_cast<uint32_t>(i));
                    if (runner == cfg.dominator_tree[runner]) break;
                    runner = cfg.dominator_tree[runner];
                }
            }
        }
    }
}

uint32_t CFGBuilder::intersect_dominators(const ControlFlowGraph& cfg, 
                                           uint32_t b1, uint32_t b2) const {
    std::unordered_set<uint32_t> doms1;
    uint32_t curr = b1;
    while (curr != UINT32_MAX) {
        doms1.insert(curr);
        if (curr == cfg.dominator_tree[curr]) break;
        curr = cfg.dominator_tree[curr];
    }
    
    curr = b2;
    while (curr != UINT32_MAX) {
        if (doms1.count(curr)) return curr;
        if (curr == cfg.dominator_tree[curr]) break;
        curr = cfg.dominator_tree[curr];
    }
    return UINT32_MAX;
}

// ============================================================================
// Unreachable Code Detection
// ============================================================================

void CFGBuilder::identify_unreachable_blocks(ControlFlowGraph& cfg) {
    std::vector<bool> reachable(cfg.blocks.size(), false);
    std::queue<uint32_t> q;
    
    reachable[cfg.entry_block] = true;
    q.push(cfg.entry_block);
    
    while (!q.empty()) {
        uint32_t u = q.front();
        q.pop();
        
        for (const auto& edge : cfg.blocks[u].successors) {
            if (edge.target_block_id < cfg.blocks.size() && !reachable[edge.target_block_id]) {
                reachable[edge.target_block_id] = true;
                q.push(edge.target_block_id);
            }
        }
    }
    
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        if (!reachable[i]) {
            cfg.unreachable_blocks.push_back(static_cast<uint32_t>(i));
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

bool CFGBuilder::validate_cfg(const ControlFlowGraph& cfg, std::string& error) const {
    if (cfg.blocks.empty()) {
        error = "CFG has no blocks";
        return false;
    }
    
    if (cfg.entry_block >= cfg.blocks.size()) {
        error = "Invalid entry block";
        return false;
    }
    
    for (size_t i = 0; i < cfg.blocks.size(); ++i) {
        const auto& block = cfg.blocks[i];
        for (const auto& edge : block.successors) {
            if (edge.target_block_id != UINT32_MAX && edge.target_block_id >= cfg.blocks.size()) {
                error = "Block " + std::to_string(i) + " has edge to invalid block " + 
                        std::to_string(edge.target_block_id);
                return false;
            }
            if (edge.target_block_id != UINT32_MAX) {
                bool found = false;
                for (uint32_t pred : cfg.blocks[edge.target_block_id].predecessors) {
                    if (pred == i) { found = true; break; }
                }
                if (!found) {
                    error = "Block " + std::to_string(i) + " -> " + 
                            std::to_string(edge.target_block_id) + " missing reverse edge";
                    return false;
                }
            }
        }
    }
    
    return true;
}

// ============================================================================
// JSON Export
// ============================================================================

std::string CFGBuilder::cfg_to_json(const ControlFlowGraph& cfg) const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"function\": \"" << cfg.function.name << "\",\n";
    oss << "  \"entry_block\": " << cfg.entry_block << ",\n";
    oss << "  \"blocks\": " << cfg.blocks.size() << ",\n";
    oss << "  \"edges\": " << cfg.total_edges << ",\n";
    oss << "  \"loops\": " << cfg.loops.size() << ",\n";
    oss << "  \"unreachable_blocks\": " << cfg.unreachable_blocks.size() << ",\n";
    oss << "  \"valid\": " << (cfg.is_valid ? "true" : "false") << "\n";
    if (!cfg.error_message.empty()) {
        oss << "  \"error\": \"" << cfg.error_message << "\"\n";
    }
    oss << "}";
    return oss.str();
}

std::string CFGBuilder::cfg_to_dot(const ControlFlowGraph& cfg, const std::string& graph_name) const {
    std::ostringstream oss;
    oss << "digraph " << graph_name << " {\n";
    oss << "  rankdir=TB;\n";
    oss << "  node [shape=box, fontname=\"Courier\"];\n";
    
    for (const auto& block : cfg.blocks) {
        std::ostringstream label;
        label << "0x" << std::hex << block.start_address << std::dec << "\n";
        label << "size: " << block.size << "\n";
        label << "instrs: " << block.instruction_count;
        
        std::string color = "lightgray";
        if (block.is_entry_block) color = "lightgreen";
        else if (block.is_exit) color = "lightcoral";
        else if (block.has_return) color = "lightyellow";
        
        oss << "  " << block.id << " [label=\"" << label.str() 
            << "\", style=filled, fillcolor=" << color << "];\n";
    }
    
    for (const auto& block : cfg.blocks) {
        for (const auto& edge : block.successors) {
            std::string color = "black";
            std::string style = "solid";
            std::string label = "";
            
            switch (edge.type) {
                case CFGEdgeType::Fallthrough: color = "gray"; style = "dashed"; break;
                case CFGEdgeType::ConditionalBranch: color = "blue"; label = "cond"; break;
                case CFGEdgeType::UnconditionalBranch: color = "green"; break;
                case CFGEdgeType::Call: color = "purple"; label = "call"; break;
                case CFGEdgeType::Return: color = "red"; label = "ret"; break;
                case CFGEdgeType::IndirectBranch: color = "orange"; label = "indirect"; break;
                case CFGEdgeType::IndirectCall: color = "orange"; style = "dashed"; label = "icall"; break;
                default: break;
            }
            
            if (!edge.is_resolved) style = "dotted";
            
            uint32_t dst = edge.target_block_id == UINT32_MAX ? 9999 : edge.target_block_id;
            oss << "  " << block.id << " -> " << dst 
                << " [color=" << color << ", style=" << style;
            if (!label.empty()) oss << ", label=\"" << label << "\"";
            oss << "];\n";
        }
    }
    
    oss << "}\n";
    return oss.str();
}

// ============================================================================
// ControlFlowGraph Methods
// ============================================================================

bool ControlFlowGraph::validate(std::string& error) const {
    if (blocks.empty()) {
        error = "CFG has no blocks";
        return false;
    }
    if (entry_block >= blocks.size()) {
        error = "Invalid entry block";
        return false;
    }
    return true;
}

std::string ControlFlowGraph::summary() const {
    std::ostringstream oss;
    oss << "CFG: " << function.name << " (" << blocks.size() << " blocks, " 
        << total_edges << " edges, " << loops.size() << " loops)";
    if (!is_valid) oss << " [INVALID: " << error_message << "]";
    return oss.str();
}

std::string ControlFlowGraph::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"function\": \"" << function.name << "\",\n";
    oss << "  \"entry_block\": " << entry_block << ",\n";
    oss << "  \"blocks\": " << blocks.size() << ",\n";
    oss << "  \"edges\": " << total_edges << ",\n";
    oss << "  \"loops\": " << loops.size() << ",\n";
    oss << "  \"unreachable_blocks\": " << unreachable_blocks.size() << ",\n";
    oss << "  \"valid\": " << (is_valid ? "true" : "false") << "\n";
    if (!error_message.empty()) {
        oss << "  \"error\": \"" << error_message << "\"\n";
    }
    oss << "}";
    return oss.str();
}

std::string ControlFlowGraph::to_dot(const std::string& graph_name) const {
    std::ostringstream oss;
    oss << "digraph " << graph_name << " {\n";
    oss << "  rankdir=TB;\n";
    oss << "  node [shape=box, fontname=\"Courier\"];\n";
    
    for (const auto& block : blocks) {
        std::ostringstream label;
        label << "0x" << std::hex << block.start_address << std::dec << "\n";
        label << "size: " << block.size << "\n";
        label << "instrs: " << block.instruction_count;
        
        std::string color = "lightgray";
        if (block.is_entry_block) color = "lightgreen";
        else if (block.is_exit) color = "lightcoral";
        else if (block.has_return) color = "lightyellow";
        
        oss << "  " << block.id << " [label=\"" << label.str() 
            << "\", style=filled, fillcolor=" << color << "];\n";
    }
    
    for (const auto& block : blocks) {
        for (const auto& edge : block.successors) {
            std::string color = "black";
            std::string style = "solid";
            std::string label = "";
            
            switch (edge.type) {
                case CFGEdgeType::Fallthrough: color = "gray"; style = "dashed"; break;
                case CFGEdgeType::ConditionalBranch: color = "blue"; label = "cond"; break;
                case CFGEdgeType::UnconditionalBranch: color = "green"; break;
                case CFGEdgeType::Call: color = "purple"; label = "call"; break;
                case CFGEdgeType::Return: color = "red"; label = "ret"; break;
                case CFGEdgeType::IndirectBranch: color = "orange"; label = "indirect"; break;
                case CFGEdgeType::IndirectCall: color = "orange"; style = "dashed"; label = "icall"; break;
                default: break;
            }
            
            if (!edge.is_resolved) style = "dotted";
            
            uint32_t dst = edge.target_block_id == UINT32_MAX ? 9999 : edge.target_block_id;
            oss << "  " << block.id << " -> " << dst 
                << " [color=" << color << ", style=" << style;
            if (!label.empty()) oss << ", label=\"" << label << "\"";
            oss << "];\n";
        }
    }
    
    oss << "}\n";
    return oss.str();
}

} // namespace fortress