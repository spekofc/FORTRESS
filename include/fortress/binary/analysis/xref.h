// FORTRESS XREF Database
// Cross-reference database for binary analysis

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/core/types.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <memory>
#include <variant>

namespace fortress {

// ============================================================================
// XREF Types and Enums
// ============================================================================

enum class XRefType : uint8_t {
    CodeToCode,     // Instruction → Function/Block (call, jmp, jcc)
    CodeToData,     // Instruction → Variable/String (mov, lea, etc.)
    DataToCode,     // Pointer/Table → Function (vtable, jump table, EH)
    DataToData,     // Pointer/Table → Variable/String (global ptr, string table)
    Relocation,     // Relocation entry → Symbol/Section
    Import,         // Import table entry → External symbol
    Export,         // Export table entry → Symbol
    Unknown
};

enum class XRefKind : uint8_t {
    Read,       // Read access (mov rax, [addr])
    Write,      // Write access (mov [addr], rax)
    Execute,    // Control flow (call, jmp, jcc)
    XRefOffset,     // Address taken (lea rax, [addr])
    Unknown
};

enum class XRefConfidence : uint8_t {
    Confirmed,  // Direct reference, resolved
    High,       // Strong heuristic, likely correct
    Medium,     // Probable, some ambiguity
    Low,        // Weak heuristic, speculative
    Unknown
};

// ============================================================================
// CrossReference Structure
// ============================================================================

struct CrossReference {
    TypedAddress from_address;      // Source location (VA preferred)
    TypedAddress to_address;        // Target location (VA preferred)
    XRefType type = XRefType::Unknown;
    XRefKind kind = XRefKind::Unknown;
    XRefConfidence confidence = XRefConfidence::Unknown;
    std::optional<uint64_t> instruction_offset; // File offset if from instruction
    std::string context;            // Instruction mnemonic, symbol name, etc.
    std::string symbol_name;        // Symbol name if applicable
    bool is_import = false;
    bool is_export = false;

    CrossReference() = default;
    
    CrossReference(TypedAddress from, TypedAddress to, XRefType t, XRefKind k, 
                   XRefConfidence c = XRefConfidence::Medium)
        : from_address(from), to_address(to), type(t), kind(k), confidence(c) {}
};

// ============================================================================
// XREF Statistics
// ============================================================================

struct XRefStatistics {
    size_t total_references = 0;
    size_t code_to_code = 0;
    size_t code_to_data = 0;
    size_t data_to_code = 0;
    size_t data_to_data = 0;
    size_t relocations = 0;
    size_t imports = 0;
    size_t exports = 0;
    size_t unique_sources = 0;
    size_t unique_targets = 0;
    size_t unresolved = 0;
    std::unordered_map<std::string, size_t> by_context;
    std::unordered_map<std::string, size_t> by_symbol;
};

// ============================================================================
// XREF Database Configuration
// ============================================================================

struct XRefConfig {
    bool include_code_to_code = true;
    bool include_code_to_data = true;
    bool include_data_to_code = true;
    bool include_data_to_data = true;
    bool include_relocations = true;
    bool include_imports = true;
    bool include_exports = true;
    bool deduplicate = true;
    bool compute_statistics = true;
    bool use_sqlite_persistence = false; // If true, persist to SQLite
    std::string sqlite_path = "xrefs.db"; // SQLite database path
};

// ============================================================================
// XREF Query Result
// ============================================================================

struct XRefQueryResult {
    std::vector<CrossReference> references;
    bool truncated = false;
    size_t total_count = 0;
};

// ============================================================================
// XREF Database Interface
// ============================================================================

class XRefDatabase {
public:
    XRefDatabase(const XRefConfig& config = XRefConfig());
    ~XRefDatabase();

    // Non-copyable, movable
    XRefDatabase(const XRefDatabase&) = delete;
    XRefDatabase& operator=(const XRefDatabase&) = delete;
    XRefDatabase(XRefDatabase&&) noexcept = default;
    XRefDatabase& operator=(XRefDatabase&&) noexcept = default;

    // Build XREF database from analysis results
    Result<void> build(const BinaryAnalysisResult& analysis,
                       const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs = {},
                       const CallGraph* call_graph = nullptr);

    // Query API
    XRefQueryResult get_xrefs_to(const TypedAddress& target, size_t limit = 1000) const;
    XRefQueryResult get_xrefs_from(const TypedAddress& source, size_t limit = 1000) const;
    XRefQueryResult get_xrefs_between(const TypedAddress& from, const TypedAddress& to, size_t limit = 1000) const;
    XRefQueryResult get_xrefs_by_type(XRefType type, size_t limit = 1000) const;
    XRefQueryResult get_xrefs_by_symbol(const std::string& symbol, size_t limit = 1000) const;

    // Get all references (use with caution on large binaries)
    const std::vector<CrossReference>& all_references() const { return refs_; }

    // Statistics
    const XRefStatistics& statistics() const { return stats_; }
    void compute_statistics();

    // Persistence
    Result<void> save_to_sqlite(const std::string& path) const;
    Result<void> load_from_sqlite(const std::string& path);

    // Clear database
    void clear();

    // Accessors
    size_t size() const { return refs_.size(); }
    bool empty() const { return refs_.empty(); }
    const XRefConfig& config() const { return config_; }

private:
    XRefConfig config_;
    std::vector<CrossReference> refs_;
    XRefStatistics stats_;

    // Indices for fast queries
    std::unordered_multimap<uint64_t, size_t> refs_to_;     // target VA -> ref index
    std::unordered_multimap<uint64_t, size_t> refs_from_;   // source VA -> ref index
    std::unordered_map<std::string, std::vector<size_t>> refs_by_symbol_;

    // Internal methods
public:
    void add_ref(const CrossReference& ref);
    void build_indices();
    void deduplicate();

    // Build methods
    Result<void> build_from_cfg(const ControlFlowGraph& cfg);
    Result<void> build_from_call_graph(const CallGraph& cg);
    Result<void> build_from_analysis_impl(const BinaryAnalysisResult& analysis);
    Result<void> build_from_relocations(const BinaryAnalysisResult& analysis);
    Result<void> build_from_imports_exports(const BinaryAnalysisResult& analysis);
    Result<void> build_from_strings(const BinaryAnalysisResult& analysis);
    Result<void> build_from_data_references(const BinaryAnalysisResult& analysis);

    // SQLite persistence
    Result<void> save_to_sqlite_impl(const std::string& path) const;
    Result<void> load_from_sqlite_impl(const std::string& path);
};

} // namespace fortress