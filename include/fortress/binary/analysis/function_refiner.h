// FORTRESS Function Refiner
// Function boundary refinement and confidence scoring

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/xref.h>
#include <fortress/core/types.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>

namespace fortress {

// ============================================================================
// Function Refiner Types
// ============================================================================

enum class PrologueType : uint8_t {
    Standard_x64,       // push rbp; mov rbp, rsp
    Standard_x86,       // push ebp; mov ebp, esp
    Standard_ARM64,     // stp x29, x30, [sp, #-16]!; mov x29, sp
    Optimized_Frame,    // Frame pointer omission, shadow space only
    NoPrologue,         // No recognizable prologue
    Unknown
};

enum class EpilogueType : uint8_t {
    Standard_Ret,       // pop rbp; ret / pop ebp; ret
    Optimized_Ret,      // ret only (no frame pointer)
    TailCall,           // jmp instead of ret
    Unknown
};

struct PrologueInfo {
    PrologueType type = PrologueType::Unknown;
    size_t length = 0;
    std::vector<uint8_t> bytes;
    bool has_frame_pointer = false;
    bool has_shadow_space = false;
    uint32_t stack_adjustment = 0;
    uint32_t saved_registers = 0;
};

struct EpilogueInfo {
    EpilogueType type = EpilogueType::Unknown;
    size_t length = 0;
    std::vector<uint8_t> bytes;
};

struct ExceptionHandlerInfo {
    bool has_handler = false;
    bool is_seh = false;           // Windows SEH
    bool is_dwarf = false;         // DWARF EH
    bool is_compact_unwind = false; // Mach-O compact unwind
    TypedAddress handler_address;
    TypedAddress unwind_info_address;
};

struct RefinedFunctionInfo {
    FunctionInfo original;
    TypedAddress refined_start;
    TypedAddress refined_end;
    ConfidenceLevel refined_confidence;
    PrologueInfo prologue;
    EpilogueInfo epilogue;
    ExceptionHandlerInfo exception_handler;
    bool is_inline_candidate = false;
    bool has_tail_call = false;
    bool overlaps_other = false;
    std::string confidence_breakdown;
};

struct FunctionRefinerConfig {
    bool enable_boundary_refinement = true;
    bool enable_confidence_scoring = true;
    bool enable_prologue_detection = true;
    bool enable_epilogue_detection = true;
    bool enable_exception_handling = true;
    bool enable_tail_call_detection = true;
    bool enable_overlap_detection = true;
    bool enable_inline_candidate_detection = true;
    size_t min_function_size = 2;
    size_t max_function_size = 0x100000; // 1MB default
};

struct FunctionRefinerStatistics {
    size_t total_functions = 0;
    size_t refined_functions = 0;
    size_t confidence_increased = 0;
    size_t confidence_decreased = 0;
    size_t boundaries_changed = 0;
    size_t prologues_found = 0;
    size_t epilogues_found = 0;
    size_t tail_calls_detected = 0;
    size_t overlaps_resolved = 0;
    size_t inline_candidates = 0;
};

class FunctionRefiner {
public:
    explicit FunctionRefiner(const FunctionRefinerConfig& config = FunctionRefinerConfig());
    ~FunctionRefiner() = default;

    // Non-copyable, movable
    FunctionRefiner(const FunctionRefiner&) = delete;
    FunctionRefiner& operator=(const FunctionRefiner&) = delete;
    FunctionRefiner(FunctionRefiner&&) noexcept = default;
    FunctionRefiner& operator=(FunctionRefiner&&) noexcept = default;

    // Refine functions using CFG, Call Graph, and XREF data
    Result<void> refine_functions(const BinaryAnalysisResult& analysis,
                                  const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs = {},
                                  const CallGraph* call_graph = nullptr,
                                  const XRefDatabase* xref_db = nullptr);

    // Refine a single function
    Result<RefinedFunctionInfo> refine_function(const FunctionInfo& func,
                                                const BinaryAnalysisResult& analysis,
                                                const ControlFlowGraph* cfg = nullptr,
                                                const CallGraph* call_graph = nullptr,
                                                const XRefDatabase* xref_db = nullptr);

    // Get statistics
    const FunctionRefinerStatistics& statistics() const;
    const FunctionRefinerConfig& config() const;

private:
    FunctionRefinerConfig config_;
    FunctionRefinerStatistics stats_;

    // Internal methods
    Result<void> refine_all_functions(const BinaryAnalysisResult& analysis,
                                      const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                      const CallGraph* call_graph,
                                      const XRefDatabase* xref_db);

    Result<RefinedFunctionInfo> refine_single_function(const FunctionInfo& func,
                                                        const BinaryAnalysisResult& analysis,
                                                        const ControlFlowGraph* cfg,
                                                        const CallGraph* call_graph,
                                                        const XRefDatabase* xref_db);

    // Boundary refinement
    Result<TypedAddress> find_function_end(const FunctionInfo& func,
                                           const ControlFlowGraph* cfg,
                                           const BinaryAnalysisResult& analysis);

    Result<bool> detect_tail_call_merge(const FunctionInfo& func,
                                        const ControlFlowGraph* cfg,
                                        const CallGraph* call_graph);

    Result<bool> detect_merged_functions(const FunctionInfo& func,
                                         const std::vector<FunctionInfo>& all_functions,
                                         const ControlFlowGraph* cfg);

    // Confidence scoring
    int calculate_confidence(const FunctionInfo& func,
                             const ControlFlowGraph* cfg,
                             const CallGraph* call_graph,
                             const XRefDatabase* xref_db,
                             std::string& breakdown);

    // Prologue/Epilogue detection
    Result<PrologueInfo> detect_prologue(const FunctionInfo& func,
                                         const BinaryAnalysisResult& analysis);

    Result<EpilogueInfo> detect_epilogue(const FunctionInfo& func,
                                         const ControlFlowGraph* cfg,
                                         const BinaryAnalysisResult& analysis);

    // Exception handling
    Result<ExceptionHandlerInfo> detect_exception_handling(const FunctionInfo& func,
                                                           const BinaryAnalysisResult& analysis);

    // Tail call detection
    Result<bool> detect_tail_call(const FunctionInfo& func,
                                  const ControlFlowGraph* cfg,
                                  const CallGraph* call_graph);

    // Overlap detection
    Result<void> detect_overlaps(std::vector<RefinedFunctionInfo>& functions);

    // Inline candidate detection
    Result<void> detect_inline_candidates(std::vector<RefinedFunctionInfo>& functions,
                                          const CallGraph* call_graph);

    // Statistics
    void update_statistics(const RefinedFunctionInfo& refined);

    // Architecture-specific prologue patterns
    bool match_x64_prologue(const std::vector<uint8_t>& bytes, size_t offset, PrologueInfo& info);
    bool match_x86_prologue(const std::vector<uint8_t>& bytes, size_t offset, PrologueInfo& info);
    bool match_arm64_prologue(const std::vector<uint8_t>& bytes, size_t offset, PrologueInfo& info);

    // Architecture-specific epilogue patterns
    bool match_x64_epilogue(const std::vector<uint8_t>& bytes, size_t offset, EpilogueInfo& info);
    bool match_x86_epilogue(const std::vector<uint8_t>& bytes, size_t offset, EpilogueInfo& info);
    bool match_arm64_epilogue(const std::vector<uint8_t>& bytes, size_t offset, EpilogueInfo& info);

    // Extract bytes from analysis
    std::vector<uint8_t> extract_bytes(const BinaryAnalysisResult& analysis,
                                       TypedAddress address, size_t max_len);
};

} // namespace fortress