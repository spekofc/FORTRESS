// FORTRESS Metrics & Reporting Implementation
// Aggregated metrics, JSON reporting, and GraphViz export

#include <fortress/binary/analysis/metrics.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/xref.h>
#include <fortress/binary/analysis/function_refiner.h>
#include <fortress/binary/analysis/string_analyzer.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <fstream>
#include <chrono>
#include <iomanip>

namespace fortress {

// ============================================================================
// MetricsCollector Implementation
// ============================================================================

MetricsCollector::MetricsCollector(const MetricsConfig& config)
    : config_(config) {}

Result<AnalysisMetrics> MetricsCollector::collect(const BinaryAnalysisResult& analysis) {
    return collect(analysis, nullptr, nullptr, nullptr, nullptr, nullptr);
}

Result<AnalysisMetrics> MetricsCollector::collect(const BinaryAnalysisResult& analysis,
                                                   const XRefDatabase* xref_db,
                                                   const std::vector<FunctionInfo>* functions,
                                                   const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs,
                                                   const CallGraph* call_graph,
                                                   const StringAnalysisResult* string_result) {
    auto start_time = std::chrono::steady_clock::now();
    
    AnalysisMetrics metrics;
    
    if (config_.include_file_metrics) {
        metrics.file = collect_file_metrics(analysis, functions, xref_db, string_result);
    }
    
    if (config_.include_function_metrics && functions) {
        metrics.functions = collect_function_metrics(functions, nullptr);
    }
    
    if (config_.include_instruction_metrics && cfgs) {
        metrics.instructions = collect_instruction_metrics(cfgs);
    }
    
    if (config_.include_cfg_metrics && cfgs) {
        metrics.cfg = collect_cfg_metrics(cfgs);
    }
    
    if (config_.include_call_graph_metrics && call_graph) {
        metrics.call_graph = collect_call_graph_metrics(call_graph);
    }
    
    if (config_.include_xref_metrics && xref_db) {
        metrics.xrefs = collect_xref_metrics(xref_db);
    }
    
    if (config_.include_string_metrics && string_result) {
        metrics.strings = collect_string_metrics(string_result);
    }
    
    auto end_time = std::chrono::steady_clock::now();
    metrics.analysis_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    metrics.complete = true;
    
    // Calculate resolution rate for XREFs
    if (metrics.xrefs.total_xrefs > 0) {
        metrics.xrefs.resolution_rate = static_cast<double>(metrics.xrefs.resolved_xrefs) / static_cast<double>(metrics.xrefs.total_xrefs);
    }
    
    return Result<AnalysisMetrics>::ok(metrics);
}

// ============================================================================
// Collection Helpers
// ============================================================================

FileMetrics MetricsCollector::collect_file_metrics(const BinaryAnalysisResult& analysis,
                                                    const std::vector<FunctionInfo>* functions,
                                                    const XRefDatabase* xref_db,
                                                    const StringAnalysisResult* string_result) const {
    FileMetrics m;
    m.format = analysis.format;
    m.architecture = analysis.architecture;
    m.endianness = analysis.endianness;
    m.is_64bit = analysis.is_64bit;
    m.entry_point = analysis.entry_point;
    m.image_base = analysis.image_base;
    
    // Compute per-section counts
    std::unordered_map<std::string, size_t> funcs_per_section;
    if (functions) {
        for (const auto& func : *functions) {
            funcs_per_section[func.section_name]++;
        }
    }
    
    std::unordered_map<std::string, size_t> strings_per_section;
    if (string_result) {
        for (const auto& str : string_result->strings) {
            strings_per_section[str.section_name]++;
        }
    }
    
    std::unordered_map<std::string, size_t> xrefs_per_section;
    if (xref_db) {
        for (const auto& sec : analysis.sections) {
            auto xrefs = xref_db->get_xrefs_to(TypedAddress::va(sec.virtual_address));
            xrefs_per_section[sec.name] = xrefs.total_count;
        }
    }
    
    // Build SectionMetrics from SectionInfo
    m.sections.reserve(analysis.sections.size());
    for (const auto& sec : analysis.sections) {
        SectionMetrics sm;
        sm.name = sec.name;
        sm.virtual_address = TypedAddress::va(sec.virtual_address);
        sm.file_offset = TypedAddress::file_offset(sec.file_offset);
        sm.virtual_size = sec.virtual_size;
        sm.raw_size = sec.raw_size;
        sm.permissions = sec.permissions;
        sm.function_count = funcs_per_section[sec.name];
        sm.string_count = strings_per_section[sec.name];
        sm.xref_count = xrefs_per_section[sec.name];
        sm.instruction_count = 0; // Would need CFG to calculate
        m.sections.push_back(sm);
    }
    
    return m;
}

FunctionMetrics MetricsCollector::collect_function_metrics(
    const std::vector<FunctionInfo>* functions,
    const std::vector<RefinedFunctionInfo>* refined) const {
    
    FunctionMetrics m;
    
    if (!functions) return m;
    
    m.total_functions = functions->size();
    m.min_function_size = SIZE_MAX;
    m.max_function_size = 0;
    uint64_t total_size = 0;
    
    std::unordered_set<uint64_t> refined_addresses;
    if (refined) {
        for (const auto& rf : *refined) {
            refined_addresses.insert(rf.original.address);
        }
    }
    
    for (const auto& func : *functions) {
        if (func.has_symbol) m.functions_with_symbols++;
        if (func.is_exported) m.exported_functions++;
        if (func.is_imported) m.imported_functions++;
        
        if (refined_addresses.count(func.address)) {
            m.refined_functions++;
        }
        
        if (func.confidence == ConfidenceLevel::High) m.high_confidence++;
        else if (func.confidence == ConfidenceLevel::Medium) m.medium_confidence++;
        else if (func.confidence == ConfidenceLevel::Low) m.low_confidence++;
        
        total_size += func.size;
        m.min_function_size = std::min(m.min_function_size, func.size);
        m.max_function_size = std::max(m.max_function_size, func.size);
    }
    
    if (m.total_functions > 0) {
        m.avg_function_size = static_cast<double>(total_size) / static_cast<double>(m.total_functions);
    }
    
    if (refined) {
        for (const auto& rf : *refined) {
            if (rf.prologue.type != PrologueType::NoPrologue && rf.prologue.type != PrologueType::Unknown) {
                m.functions_with_prologue++;
            }
            if (rf.epilogue.type != EpilogueType::Unknown) {
                m.functions_with_epilogue++;
            }
            if (rf.exception_handler.has_handler) {
                m.functions_with_exception_handler++;
            }
            if (rf.has_tail_call) m.tail_calls_detected++;
            if (rf.overlaps_other) m.overlaps_resolved++;
            if (rf.is_inline_candidate) m.inline_candidates++;
        }
    }
    
    if (m.min_function_size == SIZE_MAX) m.min_function_size = 0;
    
    return m;
}

InstructionMetrics MetricsCollector::collect_instruction_metrics(
    const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs) const {
    
    InstructionMetrics m;
    
    if (!cfgs) return m;
    
    for (const auto& cfg_ptr : *cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        for (const auto& block : cfg.blocks) {
            for (const auto& instr : block.instructions) {
                m.total_instructions++;
                
                if (instr.is_call) m.call_instructions++;
                else if (instr.is_jump) m.jump_instructions++;
                else if (instr.is_return) m.return_instructions++;
                else if (instr.is_conditional_jump) m.conditional_jumps++;
                else {
                    // Classify by mnemonic if available
                    std::string mnemonic = instr.mnemonic;
                    std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::tolower);
                    
                    if (mnemonic.find("add") == 0 || mnemonic.find("sub") == 0 || 
                        mnemonic.find("mul") == 0 || mnemonic.find("div") == 0 ||
                        mnemonic.find("inc") == 0 || mnemonic.find("dec") == 0 ||
                        mnemonic.find("imul") == 0 || mnemonic.find("idiv") == 0) {
                        m.arithmetic++;
                    } else if (mnemonic.find("and") == 0 || mnemonic.find("or") == 0 || 
                               mnemonic.find("xor") == 0 || mnemonic.find("not") == 0 ||
                               mnemonic.find("shl") == 0 || mnemonic.find("shr") == 0 ||
                               mnemonic.find("rol") == 0 || mnemonic.find("ror") == 0) {
                        m.logic++;
                    } else if (mnemonic.find("cmp") == 0 || mnemonic.find("test") == 0 ||
                               mnemonic.find("j") == 0 || mnemonic.find("call") == 0 ||
                               mnemonic.find("ret") == 0) {
                        m.control_flow++;
                    } else if (mnemonic.find("mov") == 0 || mnemonic.find("load") == 0 || 
                               mnemonic.find("store") == 0 || mnemonic.find("lea") == 0) {
                        m.memory_access++;
                    } else {
                        m.other++;
                    }
                }
                
                if (!instr.mnemonic.empty()) {
                    m.mnemonic_counts[instr.mnemonic]++;
                }
            }
        }
    }
    
    return m;
}

BasicBlockMetrics MetricsCollector::collect_block_metrics(const ControlFlowGraph& cfg) const {
    BasicBlockMetrics m;
    
    m.total_blocks = cfg.blocks.size();
    m.entry_blocks = (cfg.entry_block < cfg.blocks.size() ? 1 : 0);
    m.exit_blocks = cfg.exit_blocks.size();
    
    size_t total_edges = 0;
    size_t total_instructions = 0;
    
    for (const auto& block : cfg.blocks) {
        total_edges += block.successors.size();
        total_instructions += block.instructions.size();
        
        if (block.has_return) m.blocks_with_returns++;
        if (block.has_call) m.blocks_with_calls++;
        
        if (block.instructions.size() < m.min_block_size || m.min_block_size == 0) {
            m.min_block_size = block.instructions.size();
        }
        if (block.instructions.size() > m.max_block_size) {
            m.max_block_size = block.instructions.size();
        }
        
        // Check for loop header (has back edge)
        for (const auto& edge : block.successors) {
            if (edge.target_block_id <= block.id) { // Back edge
                m.back_edges++;
                m.loop_headers++;
            }
        }
    }
    
    m.total_edges = total_edges;
    if (m.total_blocks > 0) {
        m.avg_block_size = static_cast<double>(total_instructions) / static_cast<double>(m.total_blocks);
    }
    
    // Count unreachable blocks
    m.unreachable_blocks = cfg.unreachable_blocks.size();
    
    return m;
}

CFGMetrics MetricsCollector::collect_cfg_metrics(const std::vector<std::unique_ptr<ControlFlowGraph>>* cfgs) const {
    CFGMetrics m;
    
    if (!cfgs) return m;
    
    m.total_cfgs = cfgs->size();
    m.functions_with_cfg = cfgs->size();
    
    size_t total_nodes = 0;
    size_t total_edges = 0;
    size_t total_loops = 0;
        double total_complexity = 0.0;
    
    for (const auto& cfg_ptr : *cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        auto block_metrics = collect_block_metrics(cfg);
        m.block_metrics.push_back(block_metrics);
        
        total_nodes += block_metrics.total_blocks;
        total_edges += block_metrics.total_edges;
        total_loops += block_metrics.loop_headers;
                
        // Cyclomatic complexity = E - N + 2P (where P = connected components = 1 for function)
        double complexity = static_cast<double>(block_metrics.total_edges) - 
                           static_cast<double>(block_metrics.total_blocks) + 2.0;
        total_complexity += complexity;
        
        if (block_metrics.loop_headers > 0) m.cfg_with_loops++;
        if (block_metrics.unreachable_blocks > 0) m.cfg_with_unreachable++;
    }
    
    m.total_nodes = total_nodes;
    m.total_edges = total_edges;
    m.total_loops = total_loops;
    
    if (m.total_cfgs > 0) {
        m.avg_cfg_complexity = total_complexity / static_cast<double>(m.total_cfgs);
    }
    
    return m;
}

CallGraphMetrics MetricsCollector::collect_call_graph_metrics(const CallGraph* call_graph) const {
    CallGraphMetrics m;
    
    if (!call_graph) return m;
    
    // Ensure statistics are computed
    const_cast<CallGraph*>(call_graph)->compute_statistics();
    const auto& stats = call_graph->statistics;
    
    m.total_nodes = stats.total_nodes;
    m.total_edges = stats.total_edges;
    m.external_nodes = stats.external_functions;
    m.import_nodes = stats.import_functions;
    m.thunk_functions = stats.thunk_functions;
    m.recursive_functions = stats.recursive_functions;
    m.mutual_recursion_pairs = stats.mutual_recursive_pairs;
    m.max_call_depth = stats.max_call_depth;
    m.avg_fan_in = stats.avg_callers_per_function;
    m.avg_fan_out = stats.avg_callees_per_function;
    
    size_t max_fan_in = 0;
    size_t max_fan_out = 0;
    size_t leaf_count = 0;
    size_t root_count = 0;
    
    for (const auto& node : call_graph->nodes) {
        size_t fan_out = node.callees.size();
        size_t fan_in = node.callers.size();
        
        max_fan_out = std::max(max_fan_out, fan_out);
        max_fan_in = std::max(max_fan_in, fan_in);
        
        if (fan_out == 0) leaf_count++;
        if (fan_in == 0) root_count++;
    }
    
    m.max_fan_in = max_fan_in;
    m.max_fan_out = max_fan_out;
    m.leaf_functions = leaf_count;
    m.root_functions = root_count;
    m.cycles = stats.recursive_functions;
    
    return m;
}

XRefMetrics MetricsCollector::collect_xref_metrics(const XRefDatabase* xref_db) const {
    XRefMetrics m;
    
    if (!xref_db) return m;
    
    const auto& stats = xref_db->statistics();
    m.total_xrefs = stats.total_references;
    m.code_to_code = stats.code_to_code;
    m.code_to_data = stats.code_to_data;
    m.data_to_code = stats.data_to_code;
    m.data_to_data = stats.data_to_data;
    m.relocations = stats.relocations;
    m.imports = stats.imports;
    m.exports = stats.exports;
    
    // Calculate resolved/unresolved
    for (const auto& xref : xref_db->all_references()) {
        if (xref.confidence == XRefConfidence::Confirmed || xref.confidence == XRefConfidence::High) {
            m.resolved_xrefs++;
        } else {
            m.unresolved_xrefs++;
        }
        
        if (xref.confidence == XRefConfidence::Confirmed) m.high_confidence++;
        else if (xref.confidence == XRefConfidence::High) m.high_confidence++;
        else if (xref.confidence == XRefConfidence::Medium) m.medium_confidence++;
        else if (xref.confidence == XRefConfidence::Low) m.low_confidence++;
    }
    
    if (m.total_xrefs > 0) {
        m.resolution_rate = static_cast<double>(m.resolved_xrefs) / static_cast<double>(m.total_xrefs);
    }
    
    return m;
}

StringMetrics MetricsCollector::collect_string_metrics(const StringAnalysisResult* string_result) const {
    StringMetrics m;
    
    if (!string_result) return m;
    
    m.total_strings = string_result->strings.size();
    m.total_bytes = 0;
    m.min_string_length = SIZE_MAX;
    m.max_string_length = 0;
    
    for (const auto& str : string_result->strings) {
        switch (str.encoding) {
            case StringEncoding::ASCII: m.ascii_strings++; break;
            case StringEncoding::UTF8: m.utf8_strings++; break;
            case StringEncoding::UTF16_LE: m.utf16_le_strings++; break;
            case StringEncoding::UTF16_BE: m.utf16_be_strings++; break;
            default: break;
        }
        
        if (str.type == StringType::Pascal_String) m.pascal_strings++;
        
        if (str.ref_type != StringReferenceType::No_Reference) {
            m.referenced_strings++;
        } else {
            m.unreferenced_strings++;
        }
        
        m.total_bytes += str.byte_length;
        m.min_string_length = std::min(m.min_string_length, str.length);
        m.max_string_length = std::max(m.max_string_length, str.length);
        
        switch (str.confidence) {
            case ConfidenceLevel::High: m.high_confidence++; break;
            case ConfidenceLevel::Medium: m.medium_confidence++; break;
            case ConfidenceLevel::Low: m.low_confidence++; break;
            default: break;
        }
        
        m.strings_by_section[str.section_name]++;
    }
    
    m.duplicated_strings = string_result->stats.duplicated_strings;
    
    if (m.total_strings > 0) {
        m.avg_string_length = m.total_bytes / m.total_strings;
    }
    
    if (m.min_string_length == SIZE_MAX) m.min_string_length = 0;
    
    return m;
}

// ============================================================================
// Export Methods
// ============================================================================

std::string MetricsCollector::json_escape(const std::string& str) const {
    std::string result;
    result.reserve(str.size() * 2);
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                } else {
                    result += c;
                }
        }
    }
    return result;
}

Result<std::string> MetricsCollector::export_json(const AnalysisMetrics& metrics, bool pretty) const {
    std::ostringstream oss;
    std::string indent = pretty ? "  " : "";
    std::string newline = pretty ? "\n" : "";
    
    auto write_indent = [&](int level) {
        for (int i = 0; i < level; ++i) oss << indent;
    };
    
    oss << "{" << newline;
    
    // File metrics
    write_indent(1);
    oss << "\"file\": {" << newline;
    write_indent(2);
    oss << "\"format\": " << static_cast<int>(metrics.file.format) << "," << newline;
    write_indent(2);
    oss << "\"architecture\": " << static_cast<int>(metrics.file.architecture) << "," << newline;
    write_indent(2);
    oss << "\"endianness\": " << static_cast<int>(metrics.file.endianness) << "," << newline;
    write_indent(2);
    oss << "\"is_64bit\": " << (metrics.file.is_64bit ? "true" : "false") << "," << newline;
    write_indent(2);
    oss << "\"entry_point\": \"" << std::hex << metrics.file.entry_point << "\"," << newline;
    write_indent(2);
    oss << "\"image_base\": \"" << std::hex << metrics.file.image_base << "\"," << newline;
    write_indent(2);
    oss << "\"file_size\": " << std::dec << metrics.file.file_size << "," << newline;
    write_indent(2);
    oss << "\"sections\": [" << newline;
    for (size_t i = 0; i < metrics.file.sections.size(); ++i) {
        const auto& s = metrics.file.sections[i];
        write_indent(3);
        oss << "{" << newline;
        write_indent(4);
        oss << "\"name\": \"" << json_escape(s.name) << "\"," << newline;
        write_indent(4);
        oss << "\"virtual_address\": \"" << std::hex << s.virtual_address.value() << "\"," << newline;
        write_indent(4);
        oss << "\"virtual_size\": " << std::dec << s.virtual_size << "," << newline;
        write_indent(4);
        oss << "\"file_offset\": " << s.file_offset.value() << "," << newline;
        write_indent(4);
        oss << "\"file_size\": " << s.raw_size << "," << newline;
        write_indent(4);
        oss << "\"permissions\": " << static_cast<int>(s.permissions) << "," << newline;
        write_indent(4);
        oss << "\"function_count\": " << s.function_count << "," << newline;
        write_indent(4);
        oss << "\"string_count\": " << s.string_count << "," << newline;
        write_indent(4);
        oss << "\"xref_count\": " << s.xref_count << "," << newline;
        write_indent(4);
        oss << "\"instruction_count\": " << s.instruction_count << newline;
        write_indent(3);
        oss << "}" << (i + 1 < metrics.file.sections.size() ? "," : "") << newline;
    }
    write_indent(2);
    oss << "]" << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // Function metrics
    write_indent(1);
    oss << "\"functions\": {" << newline;
    write_indent(2);
    oss << "\"total_functions\": " << metrics.functions.total_functions << "," << newline;
    write_indent(2);
    oss << "\"functions_with_symbols\": " << metrics.functions.functions_with_symbols << "," << newline;
    write_indent(2);
    oss << "\"exported_functions\": " << metrics.functions.exported_functions << "," << newline;
    write_indent(2);
    oss << "\"imported_functions\": " << metrics.functions.imported_functions << "," << newline;
    write_indent(2);
    oss << "\"refined_functions\": " << metrics.functions.refined_functions << "," << newline;
    write_indent(2);
    oss << "\"high_confidence\": " << metrics.functions.high_confidence << "," << newline;
    write_indent(2);
    oss << "\"medium_confidence\": " << metrics.functions.medium_confidence << "," << newline;
    write_indent(2);
    oss << "\"low_confidence\": " << metrics.functions.low_confidence << "," << newline;
    write_indent(2);
    oss << "\"functions_with_prologue\": " << metrics.functions.functions_with_prologue << "," << newline;
    write_indent(2);
    oss << "\"functions_with_epilogue\": " << metrics.functions.functions_with_epilogue << "," << newline;
    write_indent(2);
    oss << "\"functions_with_exception_handler\": " << metrics.functions.functions_with_exception_handler << "," << newline;
    write_indent(2);
    oss << "\"tail_calls_detected\": " << metrics.functions.tail_calls_detected << "," << newline;
    write_indent(2);
    oss << "\"overlaps_resolved\": " << metrics.functions.overlaps_resolved << "," << newline;
    write_indent(2);
    oss << "\"inline_candidates\": " << metrics.functions.inline_candidates << "," << newline;
    write_indent(2);
    oss << "\"avg_function_size\": " << metrics.functions.avg_function_size << "," << newline;
    write_indent(2);
    oss << "\"min_function_size\": " << metrics.functions.min_function_size << "," << newline;
    write_indent(2);
    oss << "\"max_function_size\": " << metrics.functions.max_function_size << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // Instruction metrics
    write_indent(1);
    oss << "\"instructions\": {" << newline;
    write_indent(2);
    oss << "\"total_instructions\": " << metrics.instructions.total_instructions << "," << newline;
    write_indent(2);
    oss << "\"call_instructions\": " << metrics.instructions.call_instructions << "," << newline;
    write_indent(2);
    oss << "\"jump_instructions\": " << metrics.instructions.jump_instructions << "," << newline;
    write_indent(2);
    oss << "\"conditional_jumps\": " << metrics.instructions.conditional_jumps << "," << newline;
    write_indent(2);
    oss << "\"return_instructions\": " << metrics.instructions.return_instructions << "," << newline;
    write_indent(2);
    oss << "\"memory_access\": " << metrics.instructions.memory_access << "," << newline;
    write_indent(2);
    oss << "\"arithmetic\": " << metrics.instructions.arithmetic << "," << newline;
    write_indent(2);
    oss << "\"logic\": " << metrics.instructions.logic << "," << newline;
    write_indent(2);
    oss << "\"control_flow\": " << metrics.instructions.control_flow << "," << newline;
    write_indent(2);
    oss << "\"other\": " << metrics.instructions.other << "," << newline;
    write_indent(2);
    oss << "\"mnemonic_counts\": {" << newline;
    size_t mn = 0;
    for (const auto& [mnemonic, count] : metrics.instructions.mnemonic_counts) {
        write_indent(3);
        oss << "\"" << json_escape(mnemonic) << "\": " << count;
        if (++mn < metrics.instructions.mnemonic_counts.size()) oss << ",";
        oss << newline;
    }
    write_indent(2);
    oss << "}" << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // CFG metrics
    write_indent(1);
    oss << "\"cfg\": {" << newline;
    write_indent(2);
    oss << "\"total_cfgs\": " << metrics.cfg.total_cfgs << "," << newline;
    write_indent(2);
    oss << "\"total_nodes\": " << metrics.cfg.total_nodes << "," << newline;
    write_indent(2);
    oss << "\"total_edges\": " << metrics.cfg.total_edges << "," << newline;
    write_indent(2);
    oss << "\"functions_with_cfg\": " << metrics.cfg.functions_with_cfg << "," << newline;
    write_indent(2);
    oss << "\"cfg_with_loops\": " << metrics.cfg.cfg_with_loops << "," << newline;
    write_indent(2);
    oss << "\"cfg_with_unreachable\": " << metrics.cfg.cfg_with_unreachable << "," << newline;
    write_indent(2);
    oss << "\"total_loops\": " << metrics.cfg.total_loops << "," << newline;
    write_indent(2);
    oss << "\"avg_cfg_complexity\": " << metrics.cfg.avg_cfg_complexity << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // Call graph metrics
    write_indent(1);
    oss << "\"call_graph\": {" << newline;
    write_indent(2);
    oss << "\"total_nodes\": " << metrics.call_graph.total_nodes << "," << newline;
    write_indent(2);
    oss << "\"total_edges\": " << metrics.call_graph.total_edges << "," << newline;
    write_indent(2);
    oss << "\"external_nodes\": " << metrics.call_graph.external_nodes << "," << newline;
    write_indent(2);
    oss << "\"import_nodes\": " << metrics.call_graph.import_nodes << "," << newline;
    write_indent(2);
    oss << "\"thunk_functions\": " << metrics.call_graph.thunk_functions << "," << newline;
    write_indent(2);
    oss << "\"recursive_functions\": " << metrics.call_graph.recursive_functions << "," << newline;
    write_indent(2);
    oss << "\"mutual_recursion_pairs\": " << metrics.call_graph.mutual_recursion_pairs << "," << newline;
    write_indent(2);
    oss << "\"max_call_depth\": " << metrics.call_graph.max_call_depth << "," << newline;
    write_indent(2);
    oss << "\"leaf_functions\": " << metrics.call_graph.leaf_functions << "," << newline;
    write_indent(2);
    oss << "\"root_functions\": " << metrics.call_graph.root_functions << "," << newline;
    write_indent(2);
    oss << "\"cycles\": " << metrics.call_graph.cycles << "," << newline;
    write_indent(2);
    oss << "\"strongly_connected_components\": " << metrics.call_graph.strongly_connected_components << "," << newline;
    write_indent(2);
    oss << "\"avg_fan_in\": " << metrics.call_graph.avg_fan_in << "," << newline;
    write_indent(2);
    oss << "\"avg_fan_out\": " << metrics.call_graph.avg_fan_out << "," << newline;
    write_indent(2);
    oss << "\"max_fan_in\": " << metrics.call_graph.max_fan_in << "," << newline;
    write_indent(2);
    oss << "\"max_fan_out\": " << metrics.call_graph.max_fan_out << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // XREF metrics
    write_indent(1);
    oss << "\"xrefs\": {" << newline;
    write_indent(2);
    oss << "\"total_xrefs\": " << metrics.xrefs.total_xrefs << "," << newline;
    write_indent(2);
    oss << "\"code_to_code\": " << metrics.xrefs.code_to_code << "," << newline;
    write_indent(2);
    oss << "\"code_to_data\": " << metrics.xrefs.code_to_data << "," << newline;
    write_indent(2);
    oss << "\"data_to_code\": " << metrics.xrefs.data_to_code << "," << newline;
    write_indent(2);
    oss << "\"data_to_data\": " << metrics.xrefs.data_to_data << "," << newline;
    write_indent(2);
    oss << "\"relocations\": " << metrics.xrefs.relocations << "," << newline;
    write_indent(2);
    oss << "\"imports\": " << metrics.xrefs.imports << "," << newline;
    write_indent(2);
    oss << "\"exports\": " << metrics.xrefs.exports << "," << newline;
    write_indent(2);
    oss << "\"resolved_xrefs\": " << metrics.xrefs.resolved_xrefs << "," << newline;
    write_indent(2);
    oss << "\"unresolved_xrefs\": " << metrics.xrefs.unresolved_xrefs << "," << newline;
    write_indent(2);
    oss << "\"high_confidence\": " << metrics.xrefs.high_confidence << "," << newline;
    write_indent(2);
    oss << "\"medium_confidence\": " << metrics.xrefs.medium_confidence << "," << newline;
    write_indent(2);
    oss << "\"low_confidence\": " << metrics.xrefs.low_confidence << "," << newline;
    write_indent(2);
    oss << "\"resolution_rate\": " << metrics.xrefs.resolution_rate << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // String metrics
    write_indent(1);
    oss << "\"strings\": {" << newline;
    write_indent(2);
    oss << "\"total_strings\": " << metrics.strings.total_strings << "," << newline;
    write_indent(2);
    oss << "\"ascii_strings\": " << metrics.strings.ascii_strings << "," << newline;
    write_indent(2);
    oss << "\"utf8_strings\": " << metrics.strings.utf8_strings << "," << newline;
    write_indent(2);
    oss << "\"utf16_le_strings\": " << metrics.strings.utf16_le_strings << "," << newline;
    write_indent(2);
    oss << "\"utf16_be_strings\": " << metrics.strings.utf16_be_strings << "," << newline;
    write_indent(2);
    oss << "\"pascal_strings\": " << metrics.strings.pascal_strings << "," << newline;
    write_indent(2);
    oss << "\"referenced_strings\": " << metrics.strings.referenced_strings << "," << newline;
    write_indent(2);
    oss << "\"unreferenced_strings\": " << metrics.strings.unreferenced_strings << "," << newline;
    write_indent(2);
    oss << "\"duplicated_strings\": " << metrics.strings.duplicated_strings << "," << newline;
    write_indent(2);
    oss << "\"total_bytes\": " << metrics.strings.total_bytes << "," << newline;
    write_indent(2);
    oss << "\"avg_string_length\": " << metrics.strings.avg_string_length << "," << newline;
    write_indent(2);
    oss << "\"max_string_length\": " << metrics.strings.max_string_length << "," << newline;
    write_indent(2);
    oss << "\"min_string_length\": " << metrics.strings.min_string_length << "," << newline;
    write_indent(2);
    oss << "\"high_confidence\": " << metrics.strings.high_confidence << "," << newline;
    write_indent(2);
    oss << "\"medium_confidence\": " << metrics.strings.medium_confidence << "," << newline;
    write_indent(2);
    oss << "\"low_confidence\": " << metrics.strings.low_confidence << "," << newline;
    write_indent(2);
    oss << "\"strings_by_section\": {" << newline;
    size_t sn = 0;
    for (const auto& [section, count] : metrics.strings.strings_by_section) {
        write_indent(3);
        oss << "\"" << json_escape(section) << "\": " << count;
        if (++sn < metrics.strings.strings_by_section.size()) oss << ",";
        oss << newline;
    }
    write_indent(2);
    oss << "}" << newline;
    write_indent(1);
    oss << "}," << newline;
    
    // Meta
    write_indent(1);
    oss << "\"analysis_time_ms\": " << metrics.analysis_time.count() << "," << newline;
    write_indent(1);
    oss << "\"complete\": " << (metrics.complete ? "true" : "false") << "," << newline;
    write_indent(1);
    oss << "\"warnings\": [";
    for (size_t i = 0; i < metrics.warnings.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "\"" << json_escape(metrics.warnings[i]) << "\"";
    }
    oss << "]," << newline;
    write_indent(1);
    oss << "\"errors\": [";
    for (size_t i = 0; i < metrics.errors.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "\"" << json_escape(metrics.errors[i]) << "\"";
    }
    oss << "]" << newline;
    
    oss << "}" << newline;
    
    return Result<std::string>::ok(oss.str());
}

Result<std::string> MetricsCollector::export_dot(const AnalysisMetrics& metrics) const {
    std::ostringstream oss;
    oss << "digraph fortress_analysis {" << "\n";
    oss << "  rankdir=TB;" << "\n";
    oss << "  node [shape=box, style=filled, fillcolor=lightgray];" << "\n";
    oss << "\n";
    
    // File node
    oss << "  \"File\" [label=\"Binary: " << json_escape(metrics.file.file_path) 
        << "\\nFormat: " << static_cast<int>(metrics.file.format)
        << "\\nArch: " << static_cast<int>(metrics.file.architecture)
        << "\", fillcolor=lightblue];" << "\n";
    
    // Sections
    for (const auto& sec : metrics.file.sections) {
        std::string sec_name = "sec_" + sec.name;
        std::replace(sec_name.begin(), sec_name.end(), '.', '_');
        oss << "  \"" << sec_name << "\" [label=\"Section: " << json_escape(sec.name) 
            << "\\nVA: " << std::hex << sec.virtual_address.value()
            << "\\nSize: " << std::dec << sec.virtual_size
            << "\\nFuncs: " << sec.function_count
            << "\\nStrs: " << sec.string_count
            << "\", fillcolor=lightyellow];" << "\n";
        oss << "  \"File\" -> \"" << sec_name << "\";" << "\n";
    }
    
    // Functions (simplified)
    if (metrics.functions.total_functions > 0) {
        oss << "  \"Functions\" [label=\"Functions: " << metrics.functions.total_functions 
            << "\\nHigh: " << metrics.functions.high_confidence
            << "\\nMed: " << metrics.functions.medium_confidence
            << "\\nLow: " << metrics.functions.low_confidence
            << "\", fillcolor=lightgreen];" << "\n";
        oss << "  \"File\" -> \"Functions\";" << "\n";
    }
    
    // Call graph summary
    if (metrics.call_graph.total_nodes > 0) {
        oss << "  \"CallGraph\" [label=\"Call Graph\\nNodes: " << metrics.call_graph.total_nodes
            << "\\nEdges: " << metrics.call_graph.total_edges
            << "\\nRecursive: " << metrics.call_graph.recursive_functions
            << "\", fillcolor=lightcoral];" << "\n";
        oss << "  \"File\" -> \"CallGraph\";" << "\n";
    }
    
    // XREF summary
    if (metrics.xrefs.total_xrefs > 0) {
        oss << "  \"XRefs\" [label=\"Cross-References\\nTotal: " << metrics.xrefs.total_xrefs
            << "\\nResolved: " << metrics.xrefs.resolved_xrefs
            << "\\nRate: " << (metrics.xrefs.resolution_rate * 100) << "%"
            << "\", fillcolor=lightpink];" << "\n";
        oss << "  \"File\" -> \"XRefs\";" << "\n";
    }
    
    // Strings summary
    if (metrics.strings.total_strings > 0) {
        oss << "  \"Strings\" [label=\"Strings\\nTotal: " << metrics.strings.total_strings
            << "\\nASCII: " << metrics.strings.ascii_strings
            << "\\nUTF-8: " << metrics.strings.utf8_strings
            << "\\nRefd: " << metrics.strings.referenced_strings
            << "\", fillcolor=lightgray];" << "\n";
        oss << "  \"File\" -> \"Strings\";" << "\n";
    }
    
    oss << "}" << "\n";
    return Result<std::string>::ok(oss.str());
}

Result<void> MetricsCollector::export_json_file(const AnalysisMetrics& metrics, 
                                                 const std::string& path, 
                                                 bool pretty) const {
    auto json_res = export_json(metrics, pretty);
    if (!json_res) return Result<void>::err(json_res.error());
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return Result<void>::err(ErrorCode::FileWriteError, "Cannot open file: " + path);
    }
    
    file << json_res.value();
    file.close();
    return Result<void>::ok();
}

Result<void> MetricsCollector::export_dot_file(const AnalysisMetrics& metrics, 
                                                const std::string& path) const {
    auto dot_res = export_dot(metrics);
    if (!dot_res) return Result<void>::err(dot_res.error());
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return Result<void>::err(ErrorCode::FileWriteError, "Cannot open file: " + path);
    }
    
    file << dot_res.value();
    file.close();
    return Result<void>::ok();
}

} // namespace fortress