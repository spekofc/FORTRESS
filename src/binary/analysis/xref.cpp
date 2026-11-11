// FORTRESS XREF Database Implementation
// Cross-reference database for binary analysis

#include <fortress/binary/analysis/xref.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <iostream>
#include <mutex>

#if defined(FORTRESS_USE_SQLITE) && FORTRESS_USE_SQLITE
#include <sqlite3.h>
#endif

namespace fortress {

// ============================================================================
// XRefDatabase Implementation
// ============================================================================

XRefDatabase::XRefDatabase(const XRefConfig& config)
    : config_(config), stats_() {
    refs_.reserve(10000);
}

XRefDatabase::~XRefDatabase() = default;

void XRefDatabase::clear() {
    refs_.clear();
    refs_to_.clear();
    refs_from_.clear();
    refs_by_symbol_.clear();
    stats_ = XRefStatistics{};
}

void XRefDatabase::add_ref(const CrossReference& ref) {
    size_t index = refs_.size();
    refs_.push_back(ref);

    // Index by target
    if (ref.to_address.valid()) {
        refs_to_.emplace(ref.to_address.value(), index);
    }

    // Index by source
    if (ref.from_address.valid()) {
        refs_from_.emplace(ref.from_address.value(), index);
    }

    // Index by symbol
    if (!ref.symbol_name.empty()) {
        refs_by_symbol_[ref.symbol_name].push_back(index);
    }
}

void XRefDatabase::build_indices() {
    refs_to_.clear();
    refs_from_.clear();
    refs_by_symbol_.clear();

    for (size_t i = 0; i < refs_.size(); ++i) {
        const auto& ref = refs_[i];
        if (ref.to_address.valid()) {
            refs_to_.emplace(ref.to_address.value(), i);
        }
        if (ref.from_address.valid()) {
            refs_from_.emplace(ref.from_address.value(), i);
        }
        if (!ref.symbol_name.empty()) {
            refs_by_symbol_[ref.symbol_name].push_back(i);
        }
    }
}

void XRefDatabase::deduplicate() {
    if (!config_.deduplicate) return;

    std::unordered_set<std::string> seen;
    std::vector<CrossReference> unique;
    unique.reserve(refs_.size());

    for (const auto& ref : refs_) {
        std::string key = std::to_string(ref.from_address.value()) + "|" +
                          std::to_string(ref.to_address.value()) + "|" +
                          std::to_string(static_cast<int>(ref.type)) + "|" +
                          std::to_string(static_cast<int>(ref.kind)) + "|" +
                          ref.symbol_name;

        if (seen.insert(key).second) {
            unique.push_back(ref);
        }
    }

    refs_ = std::move(unique);
    build_indices();
}

Result<void> XRefDatabase::build(const BinaryAnalysisResult& analysis,
                                 const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                 const CallGraph* call_graph) {
    clear();

    // Build from CFGs
    if (config_.include_code_to_code || config_.include_code_to_data) {
        for (const auto& cfg : cfgs) {
            auto build_res = build_from_cfg(*cfg);
            if (!build_res) return build_res;
        }
    }

    // Build from Call Graph
    if (call_graph && config_.include_code_to_code) {
        auto build_res = build_from_call_graph(*call_graph);
        if (!build_res) return build_res;
    }

    // Build from binary analysis (relocations, imports, exports, strings, data refs)
    auto build_res = build_from_analysis_impl(analysis);
    if (!build_res) return build_res;

    // Build from relocations
    if (config_.include_relocations) {
        build_res = build_from_relocations(analysis);
        if (!build_res) return build_res;
    }

    // Build from imports/exports
    if (config_.include_imports || config_.include_exports) {
        build_res = build_from_imports_exports(analysis);
        if (!build_res) return build_res;
    }

    // Build from strings
    build_res = build_from_strings(analysis);
    if (!build_res) return build_res;

    // Build from data references
    build_res = build_from_data_references(analysis);
    if (!build_res) return build_res;

    // Deduplicate
    deduplicate();

    // Compute statistics
    if (config_.compute_statistics) {
        compute_statistics();
    }

    // SQLite persistence
    if (config_.use_sqlite_persistence && !config_.sqlite_path.empty()) {
        auto sql_res = save_to_sqlite_impl(config_.sqlite_path);
        if (!sql_res) return sql_res;
    }

    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_cfg(const ControlFlowGraph& cfg) {
    for (const auto& block : cfg.blocks) {
        for (const auto& instr : block.instructions) {
            // Control flow edges (Code -> Code)
            if (config_.include_code_to_code) {
                for (const auto& edge : block.successors) {
                    if (edge.target_block_id != UINT32_MAX && edge.target_block_id < cfg.blocks.size()) {
                        const auto& target_block = cfg.blocks[edge.target_block_id];
                        CrossReference ref(
                            TypedAddress::va(instr.address),
                            TypedAddress::va(target_block.start_address),
                            XRefType::CodeToCode,
                            [&edge]() -> XRefKind {
                                switch (edge.type) {
                                    case CFGEdgeType::Call: return XRefKind::Execute;
                                    case CFGEdgeType::ConditionalBranch: return XRefKind::Execute;
                                    case CFGEdgeType::UnconditionalBranch: return XRefKind::Execute;
                                    case CFGEdgeType::Fallthrough: return XRefKind::Execute;
                                    case CFGEdgeType::Return: return XRefKind::Execute;
                                    default: return XRefKind::Unknown;
                                }
                            }(),
                            edge.is_resolved ? XRefConfidence::Confirmed : XRefConfidence::Medium
                        );
                        ref.context = instr.mnemonic;
                        ref.instruction_offset = instr.offset;
                        add_ref(ref);
                    }
                }
            }
        }
    }

    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_call_graph(const CallGraph& cg) {
    for (const auto& edge : cg.edges) {
        if (edge.source_node_id >= cg.nodes.size() || edge.target_node_id >= cg.nodes.size()) continue;

        const auto& src = cg.nodes[edge.source_node_id];
        const auto& dst = cg.nodes[edge.target_node_id];

        CrossReference ref(
            src.address,
            dst.address,
            XRefType::CodeToCode,
            [&edge]() -> XRefKind {
                switch (edge.type) {
                    case CallEdgeType::Direct: return XRefKind::Execute;
                    case CallEdgeType::Indirect: return XRefKind::Execute;
                    case CallEdgeType::Import: return XRefKind::Execute;
                    case CallEdgeType::TailCall: return XRefKind::Execute;
                    default: return XRefKind::Execute;
                }
            }(),
            [&edge]() -> XRefConfidence {
                switch (edge.confidence) {
                    case CallResolutionConfidence::Confirmed: return XRefConfidence::Confirmed;
                    case CallResolutionConfidence::High: return XRefConfidence::High;
                    case CallResolutionConfidence::Medium: return XRefConfidence::Medium;
                    case CallResolutionConfidence::Low: return XRefConfidence::Low;
                    default: return XRefConfidence::Unknown;
                }
            }()
        );
        ref.symbol_name = dst.name;
        ref.is_import = dst.is_import;
        ref.is_export = false;
        add_ref(ref);
    }

    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_analysis_impl(const BinaryAnalysisResult& analysis) {
    // Build function entry references
    for (const auto& func : analysis.functions) {
        CrossReference ref(
            TypedAddress::va(func.address),
            TypedAddress::va(func.address),
            XRefType::CodeToCode,
            XRefKind::Execute,
            XRefConfidence::High
        );
        ref.symbol_name = func.name;
        ref.context = "function_entry";
        add_ref(ref);
    }

    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_relocations(const BinaryAnalysisResult& analysis) {
    for (const auto& reloc : analysis.relocations) {
        CrossReference ref(
            TypedAddress::va(reloc.offset), // Source is the relocation site
            TypedAddress::va(reloc.virtual_address), // Target is the relocation target
            XRefType::Relocation,
            XRefKind::XRefOffset,
            XRefConfidence::Confirmed
        );
        ref.symbol_name = reloc.symbol_name;
        ref.context = "relocation_" + std::to_string(static_cast<int>(reloc.kind));
        add_ref(ref);
    }
    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_imports_exports(const BinaryAnalysisResult& analysis) {
    // Imports - use normalized imports from analysis
    if (config_.include_imports) {
        for (const auto& import : analysis.imports) {
            for (const auto& func : import.functions) {
                if (!func.address) continue;

                CrossReference ref(
                    TypedAddress::va(0), // Will be filled by call sites
                    TypedAddress::va(func.address),
                    XRefType::Import,
                    XRefKind::Execute,
                    XRefConfidence::Confirmed
                );
                ref.symbol_name = func.name;
                ref.is_import = true;
                ref.context = "import_" + import.library_name;
                add_ref(ref);
            }
        }
    }

    // Exports
    if (config_.include_exports) {
        for (const auto& export_sym : analysis.exports) {
            for (const auto& func : export_sym.functions) {
                if (!func.address) continue;

                CrossReference ref(
                    TypedAddress::va(0), // Will be filled by call sites
                    TypedAddress::va(func.address),
                    XRefType::Export,
                    XRefKind::Execute,
                    XRefConfidence::Confirmed
                );
                ref.symbol_name = func.name;
                ref.is_export = true;
                ref.context = "export_" + export_sym.library_name;
                add_ref(ref);
            }
        }
    }

    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_strings(const BinaryAnalysisResult& /*analysis*/) {
    // This would reference string data from code
    // Implementation depends on string analysis results
    return Result<void>::ok();
}

Result<void> XRefDatabase::build_from_data_references(const BinaryAnalysisResult& /*analysis*/) {
    // Data-to-data and data-to-code references
    // This would analyze global pointers, vtables, jump tables, etc.
    return Result<void>::ok();
}

// ============================================================================
// Query API
// ============================================================================

fortress::XRefQueryResult XRefDatabase::get_xrefs_to(const TypedAddress& target, size_t limit) const {
    XRefQueryResult result;
    if (!target.valid()) return result;

    auto range = refs_to_.equal_range(target.value());
    for (auto it = range.first; it != range.second && result.references.size() < limit; ++it) {
        result.references.push_back(refs_[it->second]);
    }
    result.total_count = std::distance(range.first, range.second);
    result.truncated = result.references.size() < result.total_count;
    return result;
}

fortress::XRefQueryResult XRefDatabase::get_xrefs_from(const TypedAddress& source, size_t limit) const {
    XRefQueryResult result;
    if (!source.valid()) return result;

    auto range = refs_from_.equal_range(source.value());
    for (auto it = range.first; it != range.second && result.references.size() < limit; ++it) {
        result.references.push_back(refs_[it->second]);
    }
    result.total_count = std::distance(range.first, range.second);
    result.truncated = result.references.size() < result.total_count;
    return result;
}

fortress::XRefQueryResult XRefDatabase::get_xrefs_between(const TypedAddress& from, const TypedAddress& to, size_t limit) const {
    XRefQueryResult result;
    if (!from.valid() || !to.valid()) return result;

    // Use the smaller index for iteration
    auto from_range = refs_from_.equal_range(from.value());
    for (auto it = from_range.first; it != from_range.second && result.references.size() < limit; ++it) {
        const auto& ref = refs_[it->second];
        if (ref.to_address == to) {
            result.references.push_back(ref);
        }
    }
    // If from index is large, also check to index
    if (result.references.size() < limit) {
        auto to_range = refs_to_.equal_range(to.value());
        for (auto it = to_range.first; it != to_range.second && result.references.size() < limit; ++it) {
            const auto& ref = refs_[it->second];
            if (ref.from_address == from) {
                // Check if already added
                bool found = false;
                for (const auto& existing : result.references) {
                    if (existing.from_address == ref.from_address && existing.to_address == ref.to_address) {
                        found = true; break;
                    }
                }
                if (!found) result.references.push_back(ref);
            }
        }
    }
    return result;
}

fortress::XRefQueryResult XRefDatabase::get_xrefs_by_type(XRefType type, size_t limit) const {
    XRefQueryResult result;
    for (const auto& ref : refs_) {
        if (ref.type == type) {
            result.references.push_back(ref);
            if (result.references.size() >= limit) break;
        }
    }
    return result;
}

fortress::XRefQueryResult XRefDatabase::get_xrefs_by_symbol(const std::string& symbol, size_t limit) const {
    XRefQueryResult result;
    auto it = refs_by_symbol_.find(symbol);
    if (it != refs_by_symbol_.end()) {
        for (size_t idx : it->second) {
            if (result.references.size() >= limit) break;
            result.references.push_back(refs_[idx]);
        }
    }
    return result;
}

// ============================================================================
// Statistics
// ============================================================================

void XRefDatabase::compute_statistics() {
    stats_ = XRefStatistics{};
    stats_.total_references = refs_.size();

    std::unordered_set<uint64_t> unique_sources;
    std::unordered_set<uint64_t> unique_targets;

    for (const auto& ref : refs_) {
        switch (ref.type) {
            case XRefType::CodeToCode: stats_.code_to_code++; break;
            case XRefType::CodeToData: stats_.code_to_data++; break;
            case XRefType::DataToCode: stats_.data_to_code++; break;
            case XRefType::DataToData: stats_.data_to_data++; break;
            case XRefType::Relocation: stats_.relocations++; break;
            case XRefType::Import: stats_.imports++; break;
            case XRefType::Export: stats_.exports++; break;
            default: break;
        }

        if (ref.confidence == XRefConfidence::Unknown) {
            stats_.unresolved++;
        }

        if (ref.from_address.valid()) unique_sources.insert(ref.from_address.value());
        if (ref.to_address.valid()) unique_targets.insert(ref.to_address.value());

        if (!ref.context.empty()) stats_.by_context[ref.context]++;
        if (!ref.symbol_name.empty()) stats_.by_symbol[ref.symbol_name]++;
    }

    stats_.unique_sources = unique_sources.size();
    stats_.unique_targets = unique_targets.size();
}

// ============================================================================
// SQLite Persistence
// ============================================================================

Result<void> XRefDatabase::save_to_sqlite_impl(const std::string& path) const {
#if defined(FORTRESS_USE_SQLITE) && FORTRESS_USE_SQLITE
    sqlite3* db = nullptr;
    int rc = sqlite3_open(path.c_str(), &db);
    if (rc != SQLITE_OK) {
        return Result<void>::err(ErrorCode::InternalError, "Failed to open SQLite database: " + std::string(sqlite3_errmsg(db)));
    }

    // Create tables
    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS xrefs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_address INTEGER NOT NULL,
            to_address INTEGER NOT NULL,
            type INTEGER NOT NULL,
            kind INTEGER NOT NULL,
            confidence INTEGER NOT NULL,
            instruction_offset INTEGER,
            context TEXT,
            symbol_name TEXT,
            is_import INTEGER DEFAULT 0,
            is_export INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_xrefs_from ON xrefs(from_address);
        CREATE INDEX IF NOT EXISTS idx_xrefs_to ON xrefs(to_address);
        CREATE INDEX IF NOT EXISTS idx_xrefs_symbol ON xrefs(symbol_name);
    )";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "Unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return Result<void>::err(ErrorCode::InternalError, "Failed to create tables: " + err);
    }

    // Insert references
    const char* insert_sql = "INSERT INTO xrefs (from_address, to_address, type, kind, confidence, "
                             "instruction_offset, context, symbol_name, is_import, is_export) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return Result<void>::err(ErrorCode::InternalError, "Failed to prepare insert statement");
    }

    for (const auto& ref : refs_) {
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);

        sqlite3_bind_int64(stmt, 1, ref.from_address.valid() ? static_cast<int64_t>(ref.from_address.value()) : 0);
        sqlite3_bind_int64(stmt, 2, ref.to_address.valid() ? static_cast<int64_t>(ref.to_address.value()) : 0);
        sqlite3_bind_int(stmt, 3, static_cast<int>(ref.type));
        sqlite3_bind_int(stmt, 4, static_cast<int>(ref.kind));
        sqlite3_bind_int(stmt, 5, static_cast<int>(ref.confidence));
        sqlite3_bind_int64(stmt, 6, ref.instruction_offset.value_or(-1));
        sqlite3_bind_text(stmt, 7, ref.context.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, ref.symbol_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 9, ref.is_import ? 1 : 0);
        sqlite3_bind_int(stmt, 10, ref.is_export ? 1 : 0);

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return Result<void>::err(ErrorCode::InternalError, "Failed to insert reference");
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return Result<void>::ok();
#else
    (void)path;
    return Result<void>::err(ErrorCode::UnsupportedOperation, "SQLite support not compiled in (FORTRESS_USE_SQLITE=OFF)");
#endif
}

Result<void> XRefDatabase::load_from_sqlite_impl(const std::string& path) const {
#if defined(FORTRESS_USE_SQLITE) && FORTRESS_USE_SQLITE
    sqlite3* db = nullptr;
    int rc = sqlite3_open(path.c_str(), &db);
    if (rc != SQLITE_OK) {
        return Result<void>::err(ErrorCode::InternalError, "Failed to open SQLite database");
    }

    const char* select_sql = "SELECT from_address, to_address, type, kind, confidence, "
                             "instruction_offset, context, symbol_name, is_import, is_export "
                             "FROM xrefs";

    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return Result<void>::err(ErrorCode::InternalError, "Failed to prepare select statement");
    }

    clear();

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        CrossReference ref;
        ref.from_address = TypedAddress::va(static_cast<uint64_t>(sqlite3_column_int64(stmt, 0)));
        ref.to_address = TypedAddress::va(static_cast<uint64_t>(sqlite3_column_int64(stmt, 1)));
        ref.type = static_cast<XRefType>(sqlite3_column_int(stmt, 2));
        ref.kind = static_cast<XRefKind>(sqlite3_column_int(stmt, 3));
        ref.confidence = static_cast<XRefConfidence>(sqlite3_column_int(stmt, 4));
        
        int64_t offset = sqlite3_column_int64(stmt, 5);
        if (offset >= 0) ref.instruction_offset = static_cast<uint64_t>(offset);
        
        ref.context = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)) ?: "";
        ref.symbol_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7)) ?: "";
        ref.is_import = sqlite3_column_int(stmt, 8) != 0;
        ref.is_export = sqlite3_column_int(stmt, 9) != 0;

        add_ref(ref);
    }

    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return Result<void>::err(ErrorCode::InternalError, "Failed to read references from database");
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (config_.compute_statistics) {
        compute_statistics();
    }

    return Result<void>::ok();
#else
    (void)path;
    return Result<void>::err(ErrorCode::UnsupportedOperation, "SQLite support not compiled in (FORTRESS_USE_SQLITE=OFF)");
#endif
}

// ============================================================================
// Public wrapper methods
// ============================================================================

Result<void> XRefDatabase::save_to_sqlite(const std::string& path) const {
    return save_to_sqlite_impl(path);
}

Result<void> XRefDatabase::load_from_sqlite(const std::string& path) {
    return load_from_sqlite_impl(path);
}

} // namespace fortress