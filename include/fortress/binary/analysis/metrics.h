// FORTRESS Metrics & Reporting
// Aggregated metrics, JSON reporting, and GraphViz export

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/xref.h>
#include <fortress/binary/analysis/function_refiner.h>
#include <fortress/binary/analysis/string_analyzer.h>
#include <fortress/core/types.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>
#include <chrono>

namespace fortress {

// ============================================================================
// Metrics Types
// ============================================================================

struct SectionMetrics {
    std::string name;
    TypedAddress virtual_address = TypedAddress::va(0);
    TypedAddress file_offset = TypedAddress::file_offset(0);
    uint64_t virtual_size = 0;
    uint64_t raw_size = 0;
    SectionPermission permissions = SectionPermission::None;
    size_t function_count = 0;
    size_t string_count = 0;
    size_t xref_count = 0;
    size_t instruction_count = 0;
};

struct FileMetrics {
    std::string file_path;
    BinaryFormat format = BinaryFormat::Unknown;
    Architecture architecture = Architecture::Unknown;
    Endianness endianness = Endianness::Little;
    bool is_64bit = false;
    uint64_t entry_point = 0;
    uint64_t image_base = 0;
    size_t file_size = 0;
    std::vector<SectionMetrics> sections;
};

struct FunctionMetrics {
    size_t total_functions = 0;
    size_t functions_with_symbols = 0;
    size_t exported_functions = 0;
    size_t imported_functions = 0;
    size_t refined_functions = 0;
    size_t high_confidence = 0;
    size_t medium_confidence = 0;
    size_t low_confidence = 0;
    size_t functions_with_prologue = 0;
    size_t functions_with_epilogue = 0;
    size_t functions_with_exception_handler = 0;
    size_t tail_calls_detected = 0;
    size_t overlaps_resolved = 0;
    size_t inline_candidates = 0;
    double avg_function_size = 0.0;
    size_t min_function_size = 0;
    size_t max_function_size = 0;
};

struct InstructionMetrics {
    size_t total_instructions = 0;
    size_t call_instructions = 0;
    size_t jump_instructions = 0;
    size_t conditional_jumps = 0;
    size_t return_instructions = 0;
    size_t memory_access = 0;
    size_t arithmetic = 0;
    size_t logic = 0;
    size_t control_flow = 0;
    size_t other = 0;
    std::unordered_map<std::string, size_t> mnemonic_counts;
};

struct BasicBlockMetrics {
    size_t total_blocks = 0;
    size_t total_edges = 0;
    size_t entry_blocks = 0;
    size_t exit_blocks = 0;
    size_t blocks_with_calls = 0;
    size_t blocks_with_returns = 0;
    double avg_block_size = 0.0;
    size_t min_block_size = 0;
    size_t max_block_size = 0;
    size_t unreachable_blocks = 0;
    size_t loop_headers = 0;
    size_t back_edges = 0;
};

struct CFGMetrics {
    size_t total_cfgs = 0;
    size_t total_nodes = 0;
    size_t total_edges = 0;
    size_t functions_with_cfg = 0;
    size_t cfg_with_loops = 0;
    size_t cfg_with_unreachable = 0;
    size_t total_loops = 0;
    double avg_cfg_complexity = 0.0;
    std::vector<BasicBlockMetrics> block_metrics;
};

struct CallGraphMetrics {
    size_t total_nodes = 0;
    size_t total_edges = 0;
    size_t external_nodes = 0;
    size_t import_nodes = 0;
    size_t thunk_functions = 0;
    size_t recursive_functions = 0;
    size_t mutual_recursion_pairs = 0;
    size_t max_call_depth = 0;
    size_t leaf_functions = 0;
    size_t root_functions = 0;
    size_t cycles = 0;
    size_t strongly_connected_components = 0;
    double avg_fan_in = 0.0;
    double avg_fan_out = 0.0;
    size_t max_fan_in = 0;
    size_t max_fan_out = 0;
};

struct XRefMetrics {
    size_t total_xrefs = 0;
    size_t code_to_code = 0;
    size_t code_to_data = 0;
    size_t data_to_code = 0;
    size_t data_to_data = 0;
    size_t relocations = 0;
    size_t imports = 0;
    size_t exports = 0;
    size_t resolved_xrefs = 0;
    size_t unresolved_xrefs = 0;
    size_t high_confidence = 0;
    size_t medium_confidence = 0;
    size_t low_confidence = 0;
    double resolution_rate = 0.0;
};

struct StringMetrics {
    size_t total_strings = 0;
    size_t ascii_strings = 0;
    size_t utf8_strings = 0;
    size_t utf16_le_strings = 0;
    size_t utf16_be_strings = 0;
    size_t pascal_strings = 0;
    size_t referenced_strings = 0;
    size_t unreferenced_strings = 0;
    size_t duplicated_strings = 0;
    size_t total_bytes = 0;
    size_t avg_string_length = 0;
    size_t max_string_length = 0;
    size_t min_string_length = 0;
    size_t high_confidence = 0;
    size_t medium_confidence = 0;
    size_t low_confidence = 0;
    std::unordered_map<std::string, size_t> strings_by_section;
};

struct AnalysisMetrics {
    FileMetrics file;
    FunctionMetrics functions;
    InstructionMetrics instructions;
    CFGMetrics cfg;
    CallGraphMetrics call_graph;
    XRefMetrics xrefs;
    StringMetrics strings;
    std::chrono::milliseconds analysis_time;
    bool complete = true;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

struct MetricsConfig {
    bool include_file_metrics = true;
    bool include_function_metrics = true;
    bool include_instruction_metrics = true;
    bool include_cfg_metrics = true;
    bool include_call_graph_metrics = true;
    bool include_xref_metrics = true;
    bool include_string_metrics = true;
    bool include_per_section_breakdown = true;
    bool include_mnemonic_breakdown = true;
    bool export_json = true;
    bool export_dot = false;
    std::string json_output_path;
    std::string dot_output_path;
    bool pretty_json = true;
};

// ============================================================================
// Metrics Collector
// ============================================================================

class MetricsCollector {
public:
    explicit MetricsCollector(const MetricsConfig& config = MetricsConfig());
    
    // Main collection method
    Result<AnalysisMetrics> collect(const BinaryAnalysisResult& analysis);
    Result<AnalysisMetrics> collect(const BinaryAnalysisResult& analysis,
                                   const XRefDatabase* xref_db,
                                   const std::vector<FunctionInfo>* functions,
                                   const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs,
                                   const CallGraph* call_graph,
                                   const StringAnalysisResult* string_result);
    
    // Export methods
    Result<std::string> export_json(const AnalysisMetrics& metrics, bool pretty = true) const;
    Result<std::string> export_dot(const AnalysisMetrics& metrics) const;
    Result<void> export_json_file(const AnalysisMetrics& metrics, const std::string& path, bool pretty = true) const;
    Result<void> export_dot_file(const AnalysisMetrics& metrics, const std::string& path) const;
    
    // Configuration
    const MetricsConfig& get_config() const { return config_; }
    void set_config(const MetricsConfig& config) { config_ = config; }
    
private:
    MetricsConfig config_;
    
    // Collection helpers
    FileMetrics collect_file_metrics(const BinaryAnalysisResult& analysis,
                                    const std::vector<FunctionInfo>* functions,
                                    const XRefDatabase* xref_db,
                                    const StringAnalysisResult* string_result) const;
    FunctionMetrics collect_function_metrics(const std::vector<FunctionInfo>* functions,
                                             const std::vector<RefinedFunctionInfo>* refined) const;
    InstructionMetrics collect_instruction_metrics(const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs) const;
    CFGMetrics collect_cfg_metrics(const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs) const;
    CallGraphMetrics collect_call_graph_metrics(const CallGraph* call_graph) const;
    XRefMetrics collect_xref_metrics(const XRefDatabase* xref_db) const;
    StringMetrics collect_string_metrics(const StringAnalysisResult* string_result) const;
    BasicBlockMetrics collect_block_metrics(const ControlFlowGraph& cfg) const;
    
    // JSON helpers
    std::string json_escape(const std::string& str) const;
    
    // DOT helpers
    std::string generate_cfg_dot(const AnalysisMetrics& metrics) const;
    std::string generate_call_graph_dot(const AnalysisMetrics& metrics) const;
    std::string generate_xref_dot(const AnalysisMetrics& metrics) const;
};

} // namespace fortress