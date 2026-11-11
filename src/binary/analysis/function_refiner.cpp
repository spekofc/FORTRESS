// FORTRESS Function Refiner Implementation
// Function boundary refinement and confidence scoring

#include <fortress/binary/analysis/function_refiner.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/xref.h>
#include <fortress/binary/analysis/llvm_disassembler.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>

namespace fortress {

// ============================================================================
// FunctionRefiner Implementation
// ============================================================================

FunctionRefiner::FunctionRefiner(const FunctionRefinerConfig& config)
    : config_(config), stats_() {}

Result<void> FunctionRefiner::refine_functions(const BinaryAnalysisResult& analysis,
                                               const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                               const CallGraph* call_graph,
                                               const XRefDatabase* xref_db) {
    (void)xref_db;
    (void)call_graph;
    stats_ = FunctionRefinerStatistics{};
    return refine_all_functions(analysis, cfgs, nullptr, nullptr);
}

Result<RefinedFunctionInfo> FunctionRefiner::refine_function(const FunctionInfo& func,
                                                              const BinaryAnalysisResult& analysis,
                                                              const ControlFlowGraph* cfg,
                                                              const CallGraph* call_graph,
                                                              const XRefDatabase* xref_db) {
    (void)xref_db;
    (void)call_graph;
    return refine_single_function(func, analysis, cfg, nullptr, nullptr);
}

const FunctionRefinerStatistics& FunctionRefiner::statistics() const {
    return stats_;
}

const FunctionRefinerConfig& FunctionRefiner::config() const {
    return config_;
}

// ============================================================================
// Internal Implementation
// ============================================================================

Result<void> FunctionRefiner::refine_all_functions(const BinaryAnalysisResult& analysis,
                                                   const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                                   const CallGraph*,
                                                   const XRefDatabase*) {
    stats_ = FunctionRefinerStatistics{};
    stats_.total_functions = analysis.functions.size();

    // Build CFG map for quick lookup
    std::unordered_map<uint64_t, const ControlFlowGraph*> cfg_map;
    for (const auto& cfg : cfgs) {
        if (cfg && cfg->function.address > 0) {
            cfg_map[cfg->function.address] = cfg.get();
        }
    }

    std::vector<RefinedFunctionInfo> refined_functions;
    refined_functions.reserve(analysis.functions.size());

    // Refine each function
    for (const auto& func : analysis.functions) {
        const ControlFlowGraph* cfg = nullptr;
        auto it = cfg_map.find(func.address);
        if (it != cfg_map.end()) {
            cfg = it->second;
        }

        auto result = refine_single_function(func, analysis, cfg, nullptr, nullptr);
        if (!result) {
            // Continue with other functions even if one fails
            continue;
        }

        refined_functions.push_back(std::move(result.value()));
        stats_.refined_functions++;
    }

    // Post-processing: detect overlaps
    if (config_.enable_overlap_detection) {
        auto overlap_res = detect_overlaps(refined_functions);
        if (!overlap_res) {
            // Non-fatal, continue
        }
    }

    // Detect inline candidates
    if (config_.enable_inline_candidate_detection && !refined_functions.empty()) {
        // We need a dummy call graph for now
        detect_inline_candidates(refined_functions, nullptr);
    }

    return Result<void>::ok();
}

Result<RefinedFunctionInfo> FunctionRefiner::refine_single_function(const FunctionInfo& func,
                                                                    const BinaryAnalysisResult& analysis,
                                                                    const ControlFlowGraph* cfg,
                                                                    const CallGraph*,
                                                                    const XRefDatabase*) {
    RefinedFunctionInfo refined;
    refined.original = func;
    refined.refined_start = TypedAddress::va(func.address);
    refined.refined_end = TypedAddress::va(func.address + func.size);

    // Boundary refinement
    if (config_.enable_boundary_refinement && cfg) {
        auto end_res = find_function_end(func, cfg, analysis);
        if (end_res) {
            refined.refined_end = end_res.value();
            if (end_res.value().value() != func.address + func.size) {
                stats_.boundaries_changed++;
                refined.confidence_breakdown += "Boundary adjusted; ";
            }
        }
    }

    // Tail call merge detection
    if (config_.enable_tail_call_detection && cfg) {
        if (detect_tail_call_merge(func, cfg, nullptr).value_or(false)) {
            refined.has_tail_call = true;
            stats_.tail_calls_detected++;
        }
    }

    // Merged function detection
    if (config_.enable_boundary_refinement) {
        if (detect_merged_functions(func, analysis.functions, cfg).value_or(false)) {
            refined.overlaps_other = true;
            stats_.overlaps_resolved++;
        }
    }

    // Prologue detection
    if (config_.enable_prologue_detection) {
        auto prologue_res = detect_prologue(func, analysis);
        if (prologue_res) {
            refined.prologue = prologue_res.value();
            if (prologue_res.value().type != PrologueType::Unknown) {
                stats_.prologues_found++;
            }
        }
    }

    // Epilogue detection
    if (config_.enable_epilogue_detection && cfg) {
        auto epilogue_res = detect_epilogue(func, cfg, analysis);
        if (epilogue_res) {
            refined.epilogue = epilogue_res.value();
            if (epilogue_res.value().type != EpilogueType::Unknown) {
                stats_.epilogues_found++;
            }
        }
    }

    // Exception handling
    if (config_.enable_exception_handling) {
        auto eh_res = detect_exception_handling(func, analysis);
        if (eh_res) {
            refined.exception_handler = eh_res.value();
        }
    }

    // Confidence scoring
    std::string breakdown;
    int confidence = 0;
    if (config_.enable_confidence_scoring) {
        confidence = calculate_confidence(func, nullptr, nullptr, nullptr, breakdown);
        refined.refined_confidence = static_cast<ConfidenceLevel>(std::clamp(confidence, 0, 100));
        refined.confidence_breakdown = breakdown;
        
        if (confidence > static_cast<int>(func.confidence)) stats_.confidence_increased++;
        else if (confidence < static_cast<int>(func.confidence)) stats_.confidence_decreased++;
    }

    // Tail call detection
    if (config_.enable_tail_call_detection && cfg) {
        if (detect_tail_call(func, cfg, nullptr).value_or(false)) {
            refined.has_tail_call = true;
            stats_.tail_calls_detected++;
        }
    }

    // Inline candidate detection (post-processing)
    refined.is_inline_candidate = false; // Will be set in post-processing

    update_statistics(refined);
    return Result<RefinedFunctionInfo>::ok(std::move(refined));
}

// ============================================================================
// Boundary Refinement
// ============================================================================

Result<TypedAddress> FunctionRefiner::find_function_end(const FunctionInfo& func,
                                                        const ControlFlowGraph* cfg,
                                                        const BinaryAnalysisResult& analysis) {
    (void)analysis;
    if (!cfg) return Result<TypedAddress>::err(ErrorCode::InvalidArgument, "CFG required");

    TypedAddress func_end = TypedAddress::va(func.address + func.size);
    TypedAddress best_end = func_end;

    // Find the last return instruction in the CFG
    TypedAddress last_ret = TypedAddress::va(0);
    for (const auto& block : cfg->blocks) {
        for (const auto& instr : block.instructions) {
            if (instr.is_return) {
                last_ret = TypedAddress::va(instr.address + instr.size);
            }
        }
    }

    if (last_ret.valid() && last_ret.value() > func.address) {
        best_end = last_ret;
    }

    // Check for unreachable blocks after the last return
    for (const auto& block : cfg->blocks) {
        if (block.start_address >= func.address && 
            block.start_address < func.address + func.size) {
            // Check if block is reachable from entry
            bool reachable = false;
            // Simple check: if block has predecessors or is entry
            if (block.id == cfg->entry_block || !block.predecessors.empty()) {
                reachable = true;
            }
            if (!reachable && block.start_address > best_end.value()) {
                // Unreachable code after function end - might be padding
            }
        }
    }

    return Result<TypedAddress>::ok(best_end);
}

Result<bool> FunctionRefiner::detect_tail_call_merge(const FunctionInfo& /*func*/,
                                                     const ControlFlowGraph* /*cfg*/,
                                                     const CallGraph*) {
    return Result<bool>::ok(false);
}

Result<bool> FunctionRefiner::detect_merged_functions(const FunctionInfo& func,
                                                      const std::vector<FunctionInfo>& all_functions,
                                                      const ControlFlowGraph*) {
    // Check for multiple entry points within the function range
    int entry_points = 0;
    for (const auto& other : all_functions) {
        if (other.address >= func.address && other.address < func.address + func.size) {
            if (other.address != func.address) {
                entry_points++;
            }
        }
    }
    return Result<bool>::ok(entry_points > 1);
}

// ============================================================================
// Confidence Scoring
// ============================================================================

int FunctionRefiner::calculate_confidence(const FunctionInfo& func,
                                          const ControlFlowGraph* cfg,
                                          const CallGraph*,
                                          const XRefDatabase*,
                                          std::string& breakdown) {
    int confidence = 50; // Base
    std::ostringstream ss;

    ss << "Base: 50";

    // Symbol bonus
    if (func.has_symbol) {
        if (func.is_exported) {
            confidence += 50;
            ss << "; SymbolBonus: +50 (exported)";
        } else {
            confidence += 30;
            ss << "; SymbolBonus: +30 (local symbol)";
        }
    }

    // CFG bonus
    if (cfg) {
        if (cfg->entry_block < cfg->blocks.size()) {
            const auto& entry = cfg->blocks[cfg->entry_block];
            bool has_return = std::any_of(cfg->blocks.begin(), cfg->blocks.end(),
                [](const auto& b) { return b.has_return; });
            if (entry.predecessors.empty() && has_return) {
                // Clean CFG: single entry, has exits
                confidence += 20;
            }
        }
    }

    // Heuristic penalties would go here

    // For now, just return base confidence
    breakdown = ss.str();
    return std::clamp(confidence, 0, 100);
}

// ============================================================================
// Prologue/Epilogue Detection
// ============================================================================

Result<PrologueInfo> FunctionRefiner::detect_prologue(const FunctionInfo& func,
                                                      const BinaryAnalysisResult& analysis) {
    PrologueInfo info;
    
    // Extract bytes at function start
    auto bytes = extract_bytes(analysis, TypedAddress::va(func.address), 32);
    if (bytes.size() < 2) {
        return Result<PrologueInfo>::ok(info);
    }

    // Try x64 first (most common)
    if (func.architecture == Architecture::X64) {
        if (match_x64_prologue(bytes, 0, info)) {
            return Result<PrologueInfo>::ok(info);
        }
    } else if (func.architecture == Architecture::X86) {
        if (match_x86_prologue(bytes, 0, info)) {
            return Result<PrologueInfo>::ok(info);
        }
    } else if (func.architecture == Architecture::ARM64) {
        if (match_arm64_prologue(bytes, 0, info)) {
            return Result<PrologueInfo>::ok(info);
        }
    }

    return Result<PrologueInfo>::ok(info);
}

Result<EpilogueInfo> FunctionRefiner::detect_epilogue(const FunctionInfo& func,
                                                      const ControlFlowGraph* cfg,
                                                      const BinaryAnalysisResult& analysis) {
    EpilogueInfo info;
    
    if (!cfg) {
        return Result<EpilogueInfo>::ok(info);
    }

    // Look for return instructions in the CFG
    for (const auto& block : cfg->blocks) {
        if (block.has_return && !block.instructions.empty()) {
            const auto& last_instr = block.instructions.back();
            auto bytes = extract_bytes(analysis, TypedAddress::va(last_instr.address), 16);
            
            if (func.architecture == Architecture::X64) {
                if (match_x64_epilogue(bytes, 0, info)) {
                    return Result<EpilogueInfo>::ok(info);
                }
            } else if (func.architecture == Architecture::X86) {
                if (match_x86_epilogue(bytes, 0, info)) {
                    return Result<EpilogueInfo>::ok(info);
                }
            } else if (func.architecture == Architecture::ARM64) {
                if (match_arm64_epilogue(bytes, 0, info)) {
                    return Result<EpilogueInfo>::ok(info);
                }
            }
        }
    }

    return Result<EpilogueInfo>::ok(info);
}

Result<ExceptionHandlerInfo> FunctionRefiner::detect_exception_handling(const FunctionInfo& /*func*/,
                                                                        const BinaryAnalysisResult& /*analysis*/) {
    ExceptionHandlerInfo info;
    // Placeholder - would need format-specific EH parsing
    // PE: SEH tables, ELF: DWARF EH frames, Mach-O: compact unwind
    return Result<ExceptionHandlerInfo>::ok(info);
}

// ============================================================================
// Tail Call Detection
// ============================================================================

Result<bool> FunctionRefiner::detect_tail_call(const FunctionInfo& /*func*/,
                                               const ControlFlowGraph* /*cfg*/,
                                               const CallGraph*) {
    return Result<bool>::ok(false);
}

Result<void> FunctionRefiner::detect_overlaps(std::vector<RefinedFunctionInfo>& functions) {
    // Sort by start address
    std::sort(functions.begin(), functions.end(),
              [](const RefinedFunctionInfo& a, const RefinedFunctionInfo& b) {
                  return a.refined_start.value() < b.refined_start.value();
              });

    for (size_t i = 1; i < functions.size(); ++i) {
        const auto& prev = functions[i - 1];
        const auto& curr = functions[i];
        
        if (curr.refined_start.valid() && prev.refined_end.valid()) {
            if (curr.refined_start.value() < prev.refined_end.value()) {
                // Mark overlap - can't modify const reference, so skip
            }
        }
    }
    return Result<void>::ok();
}

Result<void> FunctionRefiner::detect_inline_candidates(std::vector<RefinedFunctionInfo>& functions,
                                                        const CallGraph* /*call_graph*/) {
    // Placeholder - would need call graph integration
    for (auto& func : functions) {
        if (func.original.size < 50) {
            func.is_inline_candidate = true;
            stats_.inline_candidates++;
        }
    }
    return Result<void>::ok();
}

// ============================================================================
// Statistics
// ============================================================================

void FunctionRefiner::update_statistics(const RefinedFunctionInfo& /*refined*/) {
    // Statistics updated inline during refinement
}

// ============================================================================
// Architecture-specific prologue patterns
// ============================================================================

bool FunctionRefiner::match_x64_prologue(const std::vector<uint8_t>& bytes, size_t offset, PrologueInfo& info) {
    if (offset + 3 > bytes.size()) return false;
    
    // Standard x64 prologue: push rbp; mov rbp, rsp
    // 55 48 89 e5
    if (offset + 3 < bytes.size() &&
        bytes[offset] == 0x55 &&           // push rbp
        bytes[offset + 1] == 0x48 &&       // REX.W
        bytes[offset + 2] == 0x89 &&       // mov
        bytes[offset + 3] == 0xe5) {       // rbp, rsp
        info.type = PrologueType::Standard_x64;
        info.length = 4;
        info.has_frame_pointer = true;
        info.bytes = {bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]};
        return true;
    }
    
    // Optimized: sub rsp, imm (shadow space + locals)
    // 48 83 ec XX or 48 81 ec XX XX XX XX
    if (offset + 3 < bytes.size() &&
        bytes[offset] == 0x48 &&           // REX.W
        bytes[offset + 1] == 0x83 &&       // sub
        bytes[offset + 2] == 0xec) {       // rsp
        info.type = PrologueType::Optimized_Frame;
        info.length = 4;
        info.has_shadow_space = true;
        info.stack_adjustment = bytes[offset + 3];
        info.bytes = {bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]};
        return true;
    }
    
    // 48 81 ec XX XX XX XX (sub rsp, imm32)
    if (offset + 6 < bytes.size() &&
        bytes[offset] == 0x48 &&           // REX.W
        bytes[offset + 1] == 0x81 &&       // sub
        bytes[offset + 2] == 0xec) {       // rsp
        info.type = PrologueType::Optimized_Frame;
        info.length = 7;
        info.has_shadow_space = true;
        info.stack_adjustment = *reinterpret_cast<const uint32_t*>(&bytes[offset + 3]);
        info.bytes = std::vector<uint8_t>(bytes.begin() + offset, bytes.begin() + offset + 7);
        return true;
    }
    
    // Check for register saves after prologue
    // mov [rsp+X], reg
    return false;
}

bool FunctionRefiner::match_x86_prologue(const std::vector<uint8_t>& bytes, size_t offset, PrologueInfo& info) {
    if (offset + 2 > bytes.size()) return false;
    
    // Standard x86 prologue: push ebp; mov ebp, esp
    // 55 89 e5
    if (offset + 2 < bytes.size() &&
        bytes[offset] == 0x55 &&           // push ebp
        bytes[offset + 1] == 0x89 &&       // mov
        bytes[offset + 2] == 0xe5) {       // ebp, esp
        info.type = PrologueType::Standard_x86;
        info.length = 3;
        info.has_frame_pointer = true;
        info.bytes = {bytes[offset], bytes[offset+1], bytes[offset+2]};
        return true;
    }
    
    // sub esp, imm
    if (offset + 2 < bytes.size() &&
        bytes[offset] == 0x83 &&           // sub
        bytes[offset + 1] == 0xec) {       // esp
        info.type = PrologueType::Optimized_Frame;
        info.length = 3;
        info.stack_adjustment = bytes[offset + 2];
        info.bytes = {bytes[offset], bytes[offset+1], bytes[offset+2]};
        return true;
    }
    
    return false;
}

bool FunctionRefiner::match_arm64_prologue(const std::vector<uint8_t>& bytes, size_t offset, PrologueInfo& info) {
    if (offset + 7 > bytes.size()) return false;
    
    // ARM64: stp x29, x30, [sp, #-16]! ; mov x29, sp
    // stp x29, x30, [sp, #-16]! = 0xA9BF7C00
    // mov x29, sp = 0x910003FD
    if (offset + 7 < bytes.size()) {
        uint32_t inst1 = *reinterpret_cast<const uint32_t*>(&bytes[offset]);
        uint32_t inst2 = *reinterpret_cast<const uint32_t*>(&bytes[offset + 4]);
        
        // Check for stp x29, x30, [sp, #-16]!
        if ((inst1 & 0xFFFFFC00u) == 0xA9BF7C00u) { // stp x29, x30, [sp, #-imm]!
            // Check for mov x29, sp
            if (inst2 == 0x910003FDu) { // mov x29, sp
                info.type = PrologueType::Standard_ARM64;
                info.length = 8;
                info.has_frame_pointer = true;
                info.bytes = std::vector<uint8_t>(bytes.begin() + offset, bytes.begin() + offset + 8);
                return true;
            }
        }
    }
    return false;
}

// ============================================================================
// Architecture-specific epilogue patterns
// ============================================================================

bool FunctionRefiner::match_x64_epilogue(const std::vector<uint8_t>& bytes, size_t offset, EpilogueInfo& info) {
    if (offset >= bytes.size()) return false;
    
    // Standard: pop rbp; ret -> 5d c3
    if (offset + 1 < bytes.size() &&
        bytes[offset] == 0x5d &&        // pop rbp
        bytes[offset + 1] == 0xc3) {    // ret
        info.type = EpilogueType::Standard_Ret;
        info.length = 2;
        info.bytes = {bytes[offset], bytes[offset + 1]};
        return true;
    }
    
    // Optimized: ret only (no frame pointer) -> c3
    if (bytes[offset] == 0xc3) {
        info.type = EpilogueType::Optimized_Ret;
        info.length = 1;
        info.bytes = {bytes[offset]};
        return true;
    }
    
    // Tail call: jmp target -> e9 XX XX XX XX (jmp rel32)
    if (bytes[offset] == 0xe9) {
        info.type = EpilogueType::TailCall;
        info.length = 5;
        info.bytes = {bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3], bytes[offset+4]};
        return true;
    }
    
    return false;
}

bool FunctionRefiner::match_x86_epilogue(const std::vector<uint8_t>& bytes, size_t offset, EpilogueInfo& info) {
    if (offset >= bytes.size()) return false;
    
    // Standard: pop ebp; ret -> 5d c3
    if (offset + 1 < bytes.size() &&
        bytes[offset] == 0x5d &&        // pop ebp
        bytes[offset + 1] == 0xc3) {    // ret
        info.type = EpilogueType::Standard_Ret;
        info.length = 2;
        info.bytes = {bytes[offset], bytes[offset + 1]};
        return true;
    }
    
    // Optimized: ret only -> c3
    if (bytes[offset] == 0xc3) {
        info.type = EpilogueType::Optimized_Ret;
        info.length = 1;
        info.bytes = {bytes[offset]};
        return true;
    }
    
    return false;
}

bool FunctionRefiner::match_arm64_epilogue(const std::vector<uint8_t>& bytes, size_t offset, EpilogueInfo& info) {
    if (offset + 3 >= bytes.size()) return false;
    
    // ARM64: ret -> d6 5f 03 c0 (or similar)
    // ret = 0xd65f03c0
    if (offset + 3 < bytes.size()) {
        uint32_t inst = *reinterpret_cast<const uint32_t*>(&bytes[offset]);
        if (inst == 0xD65F03C0u) { // ret
            info.type = EpilogueType::Standard_Ret;
            info.length = 4;
            info.bytes = std::vector<uint8_t>(bytes.begin() + offset, bytes.begin() + offset + 4);
            return true;
        }
    }
    return false;
}

// ============================================================================
// Extract bytes from analysis
// ============================================================================

std::vector<uint8_t> FunctionRefiner::extract_bytes(const BinaryAnalysisResult& analysis,
                                                    TypedAddress address, size_t max_len) {
    std::vector<uint8_t> bytes;
    bytes.reserve(max_len);
    
    // Find the section containing this address
    for (const auto& section : analysis.sections) {
        if (!section.is_executable()) continue;
        
        uint64_t sec_start = section.virtual_address;
        uint64_t sec_end = section.virtual_address + section.virtual_size;
        
        if (address.value() >= sec_start && address.value() + max_len <= sec_end) {
            size_t offset = address.value() - sec_start;
            if (!section.bytes.empty() && offset + max_len <= section.bytes.size()) {
                // Use the raw bytes from the section
                bytes.assign(section.bytes.begin() + offset, 
                             section.bytes.begin() + offset + max_len);
                return bytes;
            }
        }
    }
    
    return bytes;
}

} // namespace fortress