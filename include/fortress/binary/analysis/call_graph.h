// FORTRESS Call Graph
// Interprocedural call graph construction for binary analysis

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/core/types.h>
#include <optional>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <memory>

namespace fortress {

// Forward declarations
class CFGBuilder;

// Call resolution confidence
enum class CallResolutionConfidence : uint8_t {
    Unknown = 0,
    Low = 1,        // Heuristic/inferred
    Medium = 2,     // Pattern-based (thunk, import table)
    High = 3,       // Direct call, symbol resolution
    Confirmed = 4   // Verified by multiple sources
};

// Call edge type
enum class CallEdgeType : uint8_t {
    Direct = 0,           // Direct CALL instruction
    Indirect = 1,         // Indirect CALL (register/memory)
    Import = 2,           // Call through import table
    Thunk = 3,            // Call through thunk/trampoline
    TailCall = 4,         // Tail call optimization
    Recursive = 5,        // Recursive call (self)
    MutualRecursive = 6,  // Mutual recursion
    External = 7,         // Call to external/unknown function
    Unknown = 8           // Unknown type
};

// Call site information
struct CallSite {
    TypedAddress address;           // Address of CALL instruction
    FunctionInfo* caller = nullptr; // Caller function
    std::string instruction_bytes;  // Raw bytes of instruction
    std::string mnemonic;           // Instruction mnemonic
    std::string operands;           // Instruction operands
    CallEdgeType edge_type = CallEdgeType::Unknown;
    bool is_resolved = false;
    
    CallSite() = default;
    CallSite(TypedAddress addr, FunctionInfo* call, const std::string& mnem, const std::string& ops, CallEdgeType type)
        : address(addr), caller(call), mnemonic(mnem), operands(ops), edge_type(type) {}
};

// Call target information
struct CallTarget {
    TypedAddress address;                 // Target address
    FunctionInfo* function = nullptr;     // Target function (if known)
    std::string symbol_name;              // Symbol name (if available)
    CallResolutionConfidence confidence = CallResolutionConfidence::Unknown;
    std::string resolution_method;        // How target was resolved
    bool is_external = false;             // External library function
    bool is_import = false;               // Import table entry
    bool is_thunk = false;                // Thunk/trampoline
    
    CallTarget() = default;
    CallTarget(TypedAddress addr, CallResolutionConfidence conf, const std::string& method)
        : address(addr), confidence(conf), resolution_method(method) {}
};

// Call resolution result
struct CallResolution {
    CallSite site;
    std::vector<CallTarget> targets;      // Possible targets (usually 1 for direct)
    bool is_ambiguous = false;
    std::string ambiguity_reason;
    CallEdgeType edge_type = CallEdgeType::Unknown;
    bool is_recursive = false;
    bool is_mutual_recursive = false;
    
    CallResolution() = default;
};

// Call graph edge
struct CallGraphEdge {
    uint32_t source_node_id = 0;
    uint32_t target_node_id = 0;
    CallEdgeType type = CallEdgeType::Unknown;
    std::vector<CallSite> call_sites;     // All call sites for this edge
    CallResolutionConfidence confidence = CallResolutionConfidence::Unknown;
    bool is_recursive = false;
    bool is_tail_call = false;
    
    CallGraphEdge() = default;
    CallGraphEdge(uint32_t src, uint32_t dst, CallEdgeType t, CallResolutionConfidence conf)
        : source_node_id(src), target_node_id(dst), type(t), confidence(conf) {}
};

// Call graph node
struct CallGraphNode {
    uint32_t id = 0;
    FunctionInfo* function = nullptr;                 // Associated function
    TypedAddress address;                             // Function entry address
    std::string name;                                 // Function name
    bool is_external = false;                         // External/imported function
    bool is_import = false;                         // Import table entry
    bool is_entry_point = false;                      // Program entry point
    bool is_thunk = false;                            // Thunk function
    bool is_recursive = false;                        // Has self-recursive calls
    bool is_mutual_recursive = false;                 // Part of mutual recursion
    
    // Graph structure
    std::vector<uint32_t> outgoing_edges;             // Edge IDs
    std::vector<uint32_t> incoming_edges;             // Edge IDs
    std::vector<uint32_t> callees;                    // Direct callees (node IDs)
    std::vector<uint32_t> callers;                    // Direct callers (node IDs)
    
    // Statistics
    size_t call_count = 0;                            // Total outgoing calls
    size_t unique_callees = 0;                        // Unique callees
    size_t unique_callers = 0;                        // Unique callers
    size_t recursive_depth = 0;                       // Recursion depth if applicable
    
    CallGraphNode() = default;
    CallGraphNode(uint32_t id_, FunctionInfo* func, const std::string& name_)
        : id(id_), function(func), name(name_) {}
};

// Call graph statistics
struct CallGraphStatistics {
    size_t total_nodes = 0;
    size_t total_edges = 0;
    size_t internal_functions = 0;
    size_t external_functions = 0;
    size_t import_functions = 0;
    size_t thunk_functions = 0;
    size_t recursive_functions = 0;
    size_t mutual_recursive_pairs = 0;
    size_t direct_calls = 0;
    size_t indirect_calls = 0;
    size_t unresolved_calls = 0;
    size_t tail_calls = 0;
    size_t max_call_depth = 0;
    size_t avg_callees_per_function = 0;
    size_t avg_callers_per_function = 0;
    std::unordered_map<std::string, size_t> edge_type_counts;
    
    CallGraphStatistics() = default;
};

// Call graph configuration
struct CallGraphConfig {
    // Analysis options
    bool resolve_indirect_calls = false;      // Attempt indirect call resolution
    bool follow_imports = true;               // Follow import table entries
    bool identify_thunks = true;              // Identify thunk/trampoline functions
    bool identify_tail_calls = true;          // Identify tail call optimizations
    bool compute_recursion = true;            // Identify recursive/mutual recursive calls
    bool compute_statistics = true;           // Compute graph statistics
    bool merge_duplicate_edges = true;        // Merge multiple call sites to same target
    
    // Resolution options
    bool use_symbol_table = true;             // Use symbol table for resolution
    bool use_import_table = true;             // Use import table for resolution
    bool use_heuristic_patterns = true;       // Use heuristic patterns (thunks, etc.)
    size_t max_indirect_candidates = 10;      // Max candidates for indirect calls
    
    // Filtering
    bool include_external = true;             // Include external functions
    bool include_unresolved = true;           // Include unresolved calls in graph
    std::unordered_set<std::string> exclude_symbols; // Symbols to exclude
    
    CallGraphConfig() = default;
};

// Call graph builder result
struct CallGraphResult {
    std::unique_ptr<class CallGraph> graph;
    bool success = false;
    std::string error;
    std::vector<std::string> warnings;
    size_t nodes_created = 0;
    size_t edges_created = 0;
    size_t resolutions_performed = 0;
    size_t unresolved_calls = 0;
    
    CallGraphResult() = default;
    explicit CallGraphResult(std::unique_ptr<CallGraph> g)
        : graph(std::move(g)), success(true) {}
    CallGraphResult(const std::string& err)
        : success(false), error(err) {}
};

// Main Call Graph class
class CallGraph {
public:
    CallGraph() = default;
    ~CallGraph() = default;
    
    // Graph structure
    std::vector<CallGraphNode> nodes;
    std::vector<CallGraphEdge> edges;
    std::unordered_map<uint64_t, uint32_t> address_to_node;  // Function VA -> node ID
    std::unordered_map<std::string, uint32_t> name_to_node;  // Function name -> node ID
    std::unordered_map<uint32_t, std::vector<uint32_t>> node_to_callees; // Node ID -> callee IDs
    std::unordered_map<uint32_t, std::vector<uint32_t>> node_to_callers; // Node ID -> caller IDs
    
    // Statistics
    CallGraphStatistics statistics;
    
    // Metadata
    bool is_valid = false;
    std::string error_message;
    std::vector<std::string> warnings;
    
    // Get node by ID
    const CallGraphNode* get_node(uint32_t id) const;
    CallGraphNode* get_node(uint32_t id);
    
    // Get node by function address
    const CallGraphNode* find_node_by_address(TypedAddress addr) const;
    const CallGraphNode* find_node_by_name(const std::string& name) const;
    
    // Get edges for node
    std::vector<const CallGraphEdge*> get_outgoing_edges(uint32_t node_id) const;
    std::vector<const CallGraphEdge*> get_incoming_edges(uint32_t node_id) const;
    
    // Cycle detection
    std::vector<std::vector<uint32_t>> find_cycles() const;
    std::vector<uint32_t> find_recursive_functions() const;
    std::vector<std::pair<uint32_t, uint32_t>> find_mutual_recursion() const;
    
    // Path finding
    std::optional<std::vector<uint32_t>> find_path(uint32_t from, uint32_t to) const;
    std::vector<uint32_t> get_transitive_callees(uint32_t node_id) const;
    std::vector<uint32_t> get_transitive_callers(uint32_t node_id) const;
    
    // Validation
    bool validate(std::string& error) const;
    
    // Export
    std::string to_json() const;
    std::string to_dot(const std::string& graph_name = "callgraph") const;
    std::string to_dot_filtered(const std::string& graph_name,
                                 const std::unordered_set<std::string>& include_functions) const;
    
    // Summary
    std::string summary() const;
    
    // Statistics computation
    void compute_statistics();
    
    // Graph algorithms
    void compute_transitive_closure();
    std::vector<uint32_t> topological_sort() const;
};

// Call Graph Builder
class CallGraphBuilder {
public:
    explicit CallGraphBuilder(const CallGraphConfig& config = CallGraphConfig());
    ~CallGraphBuilder();
    
    // Build call graph from analysis results and CFGs
    CallGraphResult build_call_graph(const BinaryAnalysisResult& analysis,
                                      const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs);
    
    // Build call graph from analysis only (no CFGs)
    CallGraphResult build_call_graph(const BinaryAnalysisResult& analysis);
    
    // Build call graph for a specific function (local view)
    CallGraphResult build_local_call_graph(const BinaryAnalysisResult& analysis,
                                            TypedAddress function_address,
                                            size_t depth = 3);
    
    // Set CFG builder for enhanced analysis
    void set_cfg_builder(std::shared_ptr<CFGBuilder> cfg_builder);
    
    // Get configuration
    const CallGraphConfig& get_config() const { return config_; }
    void set_config(const CallGraphConfig& config) { config_ = config; }
    
    // Get all call resolutions
    std::vector<CallResolution> get_all_resolutions() const { return resolutions_; }
    std::vector<CallResolution> get_unresolved_calls() const;
    std::vector<CallResolution> get_recursive_calls() const;

private:
    // Internal context for building
    struct BuildContext {
        const BinaryAnalysisResult* analysis = nullptr;
        const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs = nullptr;
        CallGraph* graph = nullptr;
        std::unordered_map<uint64_t, uint32_t> function_to_node;
    };
    
    CallGraphConfig config_;
    std::shared_ptr<CFGBuilder> cfg_builder_;
    BuildContext ctx_;
    std::vector<CallResolution> resolutions_;
    
    // Build phases
    bool build_call_graph_internal(const BinaryAnalysisResult& analysis,
                                    const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                    BuildContext& ctx,
                                    CallGraph& graph);
    
    // Node creation
    uint32_t create_or_get_node(BuildContext& ctx, FunctionInfo* function, bool is_external = false);
    uint32_t create_external_node(BuildContext& ctx, TypedAddress address, const std::string& name, 
                                   const std::string& symbol_name = "", bool is_import = false);
    
    // Edge creation
    void add_edge(BuildContext& ctx, uint32_t src_id, uint32_t dst_id, const CallResolution& resolution);
    void merge_edges(BuildContext& ctx);
    
    // Call resolution
    void resolve_all_calls(BuildContext& ctx, const BinaryAnalysisResult& analysis,
                            const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs);
    CallResolution resolve_direct_call(BuildContext& ctx, const CallSite& site, const BinaryAnalysisResult& analysis);
    CallResolution resolve_indirect_call(BuildContext& ctx, const CallSite& site, const BinaryAnalysisResult& analysis);
    CallResolution resolve_import_call(BuildContext& ctx, const CallSite& site, const BinaryAnalysisResult& analysis);
    CallResolution resolve_thunk_call(BuildContext& ctx, const CallSite& site, const BinaryAnalysisResult& analysis);
    
    // Call site extraction
    std::vector<CallSite> extract_call_sites(BuildContext& ctx, const BinaryAnalysisResult& analysis,
                                              const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs);
    std::vector<CallSite> extract_call_sites_from_cfg(BuildContext& ctx, const ControlFlowGraph& cfg);
    
    // Thunk detection
    bool is_thunk_function(const FunctionInfo& function) const;
    TypedAddress resolve_thunk_target(const FunctionInfo& function) const;
    TypedAddress resolve_thunk_target(uint64_t address) const;
    
    // Tail call detection
    bool is_tail_call(const CallSite& site, const ControlFlowGraph* cfg) const;
    
    // Recursion detection
    void identify_recursion(BuildContext& ctx);
    void identify_mutual_recursion(BuildContext& ctx);
    
    // Import table resolution
    TypedAddress resolve_import(BuildContext& ctx, const std::string& symbol_name) const;
    
    // Heuristic resolution
    std::vector<CallTarget> heuristic_resolve_indirect(const CallSite& site,
                                                        const BinaryAnalysisResult& analysis) const;
    
    // Validation
    bool validate_graph(CallGraph& graph, std::string& error) const;
    
    // Export helpers
    std::string graph_to_json(const CallGraph& graph) const;
    std::string graph_to_dot(const CallGraph& graph, const std::string& graph_name) const;
    
    // Statistics
    void compute_statistics(CallGraph& graph) const;
};

} // namespace fortress