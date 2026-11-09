// FORTRESS Call Graph Implementation
// Interprocedural call graph construction for binary analysis

#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <functional>

namespace fortress {

// ============================================================================
// CallGraph Implementation
// ============================================================================

const CallGraphNode* CallGraph::get_node(uint32_t id) const {
    if (id < nodes.size()) return &nodes[id];
    return nullptr;
}

CallGraphNode* CallGraph::get_node(uint32_t id) {
    if (id < nodes.size()) return &nodes[id];
    return nullptr;
}

const CallGraphNode* CallGraph::find_node_by_address(TypedAddress addr) const {
    auto it = address_to_node.find(addr.value());
    if (it != address_to_node.end()) return get_node(it->second);
    return nullptr;
}

const CallGraphNode* CallGraph::find_node_by_name(const std::string& name) const {
    auto it = name_to_node.find(name);
    if (it != name_to_node.end()) return get_node(it->second);
    return nullptr;
}

std::vector<const CallGraphEdge*> CallGraph::get_outgoing_edges(uint32_t node_id) const {
    std::vector<const CallGraphEdge*> result;
    if (node_id >= nodes.size()) return result;
    
    for (uint32_t edge_id : nodes[node_id].outgoing_edges) {
        if (edge_id < edges.size()) {
            result.push_back(&edges[edge_id]);
        }
    }
    return result;
}

std::vector<const CallGraphEdge*> CallGraph::get_incoming_edges(uint32_t node_id) const {
    std::vector<const CallGraphEdge*> result;
    if (node_id >= nodes.size()) return result;
    
    for (uint32_t edge_id : nodes[node_id].incoming_edges) {
        if (edge_id < edges.size()) {
            result.push_back(&edges[edge_id]);
        }
    }
    return result;
}

std::vector<std::vector<uint32_t>> CallGraph::find_cycles() const {
    std::vector<std::vector<uint32_t>> cycles;
    std::vector<int> color(nodes.size(), 0);
    std::vector<uint32_t> parent(nodes.size(), UINT32_MAX);
    std::vector<uint32_t> stack;
    
    std::function<void(uint32_t)> dfs = [&](uint32_t u) {
        color[u] = 1;
        stack.push_back(u);
        
        for (const auto* edge : get_outgoing_edges(u)) {
            uint32_t v = edge->target_node_id;
            if (v >= nodes.size()) continue;
            
            if (color[v] == 0) {
                parent[v] = u;
                dfs(v);
            } else if (color[v] == 1) {
                std::vector<uint32_t> cycle;
                for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
                    cycle.push_back(*it);
                    if (*it == v) break;
                }
                std::reverse(cycle.begin(), cycle.end());
                cycles.push_back(cycle);
            }
        }
        
        color[u] = 2;
        stack.pop_back();
    };
    
    for (uint32_t i = 0; i < nodes.size(); ++i) {
        if (color[i] == 0) {
            dfs(i);
        }
    }
    
    return cycles;
}

std::vector<uint32_t> CallGraph::find_recursive_functions() const {
    std::vector<uint32_t> recursive;
    for (const auto& node : nodes) {
        if (node.is_recursive) {
            recursive.push_back(node.id);
        }
    }
    return recursive;
}

std::vector<std::pair<uint32_t, uint32_t>> CallGraph::find_mutual_recursion() const {
    std::vector<std::pair<uint32_t, uint32_t>> mutual;
    for (const auto& node : nodes) {
        if (node.is_mutual_recursive) {
            for (uint32_t callee_id : node.callees) {
                if (callee_id < nodes.size() && nodes[callee_id].is_mutual_recursive) {
                    for (uint32_t caller_id : nodes[callee_id].callers) {
                        if (caller_id == node.id) {
                            mutual.emplace_back(node.id, callee_id);
                        }
                    }
                }
            }
        }
    }
    return mutual;
}

std::optional<std::vector<uint32_t>> CallGraph::find_path(uint32_t from, uint32_t to) const {
    if (from >= nodes.size() || to >= nodes.size()) return std::nullopt;
    
    std::vector<int> visited(nodes.size(), 0);
    std::vector<uint32_t> parent(nodes.size(), UINT32_MAX);
    std::queue<uint32_t> q;
    
    visited[from] = 1;
    q.push(from);
    
    while (!q.empty()) {
        uint32_t u = q.front();
        q.pop();
        
        if (u == to) {
            std::vector<uint32_t> path;
            uint32_t curr = to;
            while (curr != UINT32_MAX) {
                path.push_back(curr);
                curr = parent[curr];
            }
            std::reverse(path.begin(), path.end());
            return path;
        }
        
        for (const auto* edge : get_outgoing_edges(u)) {
            uint32_t v = edge->target_node_id;
            if (v < nodes.size() && !visited[v]) {
                visited[v] = 1;
                parent[v] = u;
                q.push(v);
            }
        }
    }
    
    return std::nullopt;
}

std::vector<uint32_t> CallGraph::get_transitive_callees(uint32_t node_id) const {
    std::unordered_set<uint32_t> visited;
    std::vector<uint32_t> result;
    std::queue<uint32_t> q;
    
    visited.insert(node_id);
    q.push(node_id);
    
    while (!q.empty()) {
        uint32_t u = q.front();
        q.pop();
        
        for (const auto* edge : get_outgoing_edges(u)) {
            uint32_t v = edge->target_node_id;
            if (v < nodes.size() && visited.insert(v).second) {
                result.push_back(v);
                q.push(v);
            }
        }
    }
    
    return result;
}

std::vector<uint32_t> CallGraph::get_transitive_callers(uint32_t node_id) const {
    std::unordered_set<uint32_t> visited;
    std::vector<uint32_t> result;
    std::queue<uint32_t> q;
    
    visited.insert(node_id);
    q.push(node_id);
    
    while (!q.empty()) {
        uint32_t u = q.front();
        q.pop();
        
        for (const auto* edge : get_incoming_edges(u)) {
            uint32_t v = edge->source_node_id;
            if (v < nodes.size() && visited.insert(v).second) {
                result.push_back(v);
                q.push(v);
            }
        }
    }
    
    return result;
}

bool CallGraph::validate(std::string& error) const {
    if (nodes.empty()) {
        error = "Call graph has no nodes";
        return false;
    }
    
    for (const auto& edge : edges) {
        if (edge.source_node_id >= nodes.size()) {
            error = "Edge " + std::to_string(&edge - &edges[0]) + " has invalid source node";
            return false;
        }
        if (edge.target_node_id >= nodes.size()) {
            error = "Edge " + std::to_string(&edge - &edges[0]) + " has invalid target node";
            return false;
        }
        
        const auto& src_node = nodes[edge.source_node_id];
        const auto& dst_node = nodes[edge.target_node_id];
        
        bool src_has_edge = false;
        for (uint32_t eid : src_node.outgoing_edges) {
            if (eid == &edge - &edges[0]) { src_has_edge = true; break; }
        }
        if (!src_has_edge) {
            error = "Source node " + std::to_string(edge.source_node_id) + " missing edge reference";
            return false;
        }
        
        bool dst_has_edge = false;
        for (uint32_t eid : dst_node.incoming_edges) {
            if (eid == &edge - &edges[0]) { dst_has_edge = true; break; }
        }
        if (!dst_has_edge) {
            error = "Target node " + std::to_string(edge.target_node_id) + " missing edge reference";
            return false;
        }
    }
    
    for (size_t i = 0; i < nodes.size(); ++i) {
        const auto& node = nodes[i];
        
        for (uint32_t edge_id : node.outgoing_edges) {
            if (edge_id >= edges.size()) {
                error = "Node " + std::to_string(i) + " references invalid outgoing edge";
                return false;
            }
        }
        
        for (uint32_t edge_id : node.incoming_edges) {
            if (edge_id >= edges.size()) {
                error = "Node " + std::to_string(i) + " references invalid incoming edge";
                return false;
            }
        }
        
        for (uint32_t callee_id : node.callees) {
            if (callee_id >= nodes.size()) {
                error = "Node " + std::to_string(i) + " references invalid callee";
                return false;
            }
        }
        
        for (uint32_t caller_id : node.callers) {
            if (caller_id >= nodes.size()) {
                error = "Node " + std::to_string(i) + " references invalid caller";
                return false;
            }
        }
    }
    
    return true;
}

std::string CallGraph::summary() const {
    std::ostringstream oss;
    oss << "CallGraph: " << nodes.size() << " nodes, " << edges.size() << " edges";
    if (!is_valid) oss << " [INVALID: " << error_message << "]";
    return oss.str();
}

void CallGraph::compute_statistics() {
    statistics.total_nodes = nodes.size();
    statistics.total_edges = edges.size();
    
    statistics.internal_functions = 0;
    statistics.external_functions = 0;
    statistics.import_functions = 0;
    statistics.thunk_functions = 0;
    statistics.recursive_functions = 0;
    statistics.mutual_recursive_pairs = 0;
    statistics.direct_calls = 0;
    statistics.indirect_calls = 0;
    statistics.unresolved_calls = 0;
    statistics.tail_calls = 0;
    statistics.edge_type_counts.clear();
    
    for (const auto& node : nodes) {
        if (node.is_external) statistics.external_functions++;
        else statistics.internal_functions++;
        
        if (node.is_thunk) statistics.thunk_functions++;
        if (node.is_recursive) statistics.recursive_functions++;
        if (node.is_mutual_recursive) statistics.mutual_recursive_pairs++;
        
        statistics.avg_callees_per_function += node.unique_callees;
        statistics.avg_callers_per_function += node.unique_callers;
    }
    
    if (!nodes.empty()) {
        statistics.avg_callees_per_function /= nodes.size();
        statistics.avg_callers_per_function /= nodes.size();
    }
    
    for (const auto& edge : edges) {
        switch (edge.type) {
            case CallEdgeType::Direct: statistics.direct_calls++; break;
            case CallEdgeType::Indirect: statistics.indirect_calls++; break;
            case CallEdgeType::Import: statistics.import_functions++; break;
            case CallEdgeType::TailCall: statistics.tail_calls++; break;
            default: break;
        }
        
        if (edge.confidence == CallResolutionConfidence::Unknown) {
            statistics.unresolved_calls++;
        }
        
        std::string type_str;
        switch (edge.type) {
            case CallEdgeType::Direct: type_str = "Direct"; break;
            case CallEdgeType::Indirect: type_str = "Indirect"; break;
            case CallEdgeType::Import: type_str = "Import"; break;
            case CallEdgeType::Thunk: type_str = "Thunk"; break;
            case CallEdgeType::TailCall: type_str = "TailCall"; break;
            case CallEdgeType::Recursive: type_str = "Recursive"; break;
            case CallEdgeType::MutualRecursive: type_str = "MutualRecursive"; break;
            case CallEdgeType::External: type_str = "External"; break;
            default: type_str = "Unknown"; break;
        }
        statistics.edge_type_counts[type_str]++;
    }
    
    std::unordered_set<std::string> seen;
    for (const auto& node : nodes) {
        if (node.is_mutual_recursive) {
            for (uint32_t callee_id : node.callees) {
                if (callee_id < nodes.size() && nodes[callee_id].is_mutual_recursive) {
                    std::string key = std::to_string(std::min(node.id, callee_id)) + "-" + 
                                     std::to_string(std::max(node.id, callee_id));
                    if (seen.insert(key).second) {
                        statistics.mutual_recursive_pairs++;
                    }
                }
            }
        }
    }
}

std::string CallGraph::to_json() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"nodes\": " << nodes.size() << ",\n";
    oss << "  \"edges\": " << edges.size() << ",\n";
    oss << "  \"internal_functions\": " << statistics.internal_functions << ",\n";
    oss << "  \"external_functions\": " << statistics.external_functions << ",\n";
    oss << "  \"import_functions\": " << statistics.import_functions << ",\n";
    oss << "  \"thunk_functions\": " << statistics.thunk_functions << ",\n";
    oss << "  \"recursive_functions\": " << statistics.recursive_functions << ",\n";
    oss << "  \"mutual_recursive_pairs\": " << statistics.mutual_recursive_pairs << ",\n";
    oss << "  \"direct_calls\": " << statistics.direct_calls << ",\n";
    oss << "  \"indirect_calls\": " << statistics.indirect_calls << ",\n";
    oss << "  \"unresolved_calls\": " << statistics.unresolved_calls << ",\n";
    oss << "  \"tail_calls\": " << statistics.tail_calls << ",\n";
    oss << "  \"valid\": " << (is_valid ? "true" : "false") << "\n";
    if (!error_message.empty()) {
        oss << "  \"error\": \"" << error_message << "\"\n";
    }
    oss << "}";
    return oss.str();
}

std::string CallGraph::to_dot(const std::string& graph_name) const {
    std::ostringstream oss;
    oss << "digraph " << graph_name << " {\n";
    oss << "  rankdir=LR;\n";
    oss << "  node [shape=box, fontname=\"Courier\"];\n";
    
    for (const auto& node : nodes) {
        std::string color = "lightgray";
        if (node.is_entry_point) color = "lightgreen";
        else if (node.is_external) color = "lightblue";
        else if (node.is_thunk) color = "lightyellow";
        else if (node.is_recursive) color = "lightcoral";
        
        std::string label = node.name + "\\n0x" + 
            std::to_string(node.address.value()) + "\\n";
        label += "calls: " + std::to_string(node.call_count) + "\\n";
        label += "callers: " + std::to_string(node.unique_callers);
        
        oss << "  " << node.id << " [label=\"" << label 
            << "\", style=filled, fillcolor=" << color << "];\n";
    }
    
    for (const auto& edge : edges) {
        std::string color = "black";
        std::string style = "solid";
        std::string label = "";
        
        switch (edge.type) {
            case CallEdgeType::Direct: color = "blue"; break;
            case CallEdgeType::Indirect: color = "orange"; style = "dashed"; label = "indirect"; break;
            case CallEdgeType::Import: color = "green"; label = "import"; break;
            case CallEdgeType::Thunk: color = "purple"; label = "thunk"; break;
            case CallEdgeType::TailCall: color = "red"; style = "dotted"; label = "tail"; break;
            case CallEdgeType::Recursive: color = "red"; label = "recursive"; break;
            case CallEdgeType::MutualRecursive: color = "red"; style = "dashed"; label = "mutual"; break;
            case CallEdgeType::External: color = "gray"; label = "external"; break;
            default: break;
        }
        
        if (edge.is_tail_call) style = "dotted";
        
        std::string conf_str;
        switch (edge.confidence) {
            case CallResolutionConfidence::Confirmed: conf_str = " [C]"; break;
            case CallResolutionConfidence::High: conf_str = " [H]"; break;
            case CallResolutionConfidence::Medium: conf_str = " [M]"; break;
            case CallResolutionConfidence::Low: conf_str = " [L]"; break;
            default: break;
        }
        
        oss << "  " << edge.source_node_id << " -> " << edge.target_node_id
            << " [color=" << color << ", style=" << style;
        if (!label.empty() || !conf_str.empty()) {
            oss << ", label=\"" << label << conf_str << "\"";
        }
        oss << "];\n";
    }
    
    oss << "}\n";
    return oss.str();
}

std::string CallGraph::to_dot_filtered(const std::string& graph_name,
                                        const std::unordered_set<std::string>& include_functions) const {
    std::ostringstream oss;
    oss << "digraph " << graph_name << " {\n";
    oss << "  rankdir=LR;\n";
    oss << "  node [shape=box, fontname=\"Courier\"];\n";
    
    for (const auto& node : nodes) {
        if (!include_functions.empty() && include_functions.find(node.name) == include_functions.end()) {
            continue;
        }
        
        std::string color = "lightgray";
        if (node.is_entry_point) color = "lightgreen";
        else if (node.is_external) color = "lightblue";
        else if (node.is_thunk) color = "lightyellow";
        else if (node.is_recursive) color = "lightcoral";
        
        std::string label = node.name + "\\n0x" + 
            std::to_string(node.address.value()) + "\\n";
        label += "calls: " + std::to_string(node.call_count) + "\\n";
        label += "callers: " + std::to_string(node.unique_callers);
        
        oss << "  " << node.id << " [label=\"" << label 
            << "\", style=filled, fillcolor=" << color << "];\n";
    }
    
    for (const auto& edge : edges) {
        const auto* src = get_node(edge.source_node_id);
        const auto* dst = get_node(edge.target_node_id);
        if (!src || !dst) continue;
        if (!include_functions.empty() && 
            (include_functions.find(src->name) == include_functions.end() ||
             include_functions.find(dst->name) == include_functions.end())) {
            continue;
        }
        
        std::string color = "black";
        std::string style = "solid";
        std::string label = "";
        
        switch (edge.type) {
            case CallEdgeType::Direct: color = "blue"; break;
            case CallEdgeType::Indirect: color = "orange"; style = "dashed"; label = "indirect"; break;
            case CallEdgeType::Import: color = "green"; label = "import"; break;
            case CallEdgeType::Thunk: color = "purple"; label = "thunk"; break;
            case CallEdgeType::TailCall: color = "red"; style = "dotted"; label = "tail"; break;
            case CallEdgeType::Recursive: color = "red"; label = "recursive"; break;
            case CallEdgeType::MutualRecursive: color = "red"; style = "dashed"; label = "mutual"; break;
            case CallEdgeType::External: color = "gray"; label = "external"; break;
            default: break;
        }
        
        if (edge.is_tail_call) style = "dotted";
        
        oss << "  " << edge.source_node_id << " -> " << edge.target_node_id
            << " [color=" << color << ", style=" << style;
        if (!label.empty()) oss << ", label=\"" << label << "\"";
        oss << "];\n";
    }
    
    oss << "}\n";
    return oss.str();
}

// ============================================================================
// CallGraphBuilder Implementation
// ============================================================================

CallGraphBuilder::CallGraphBuilder(const CallGraphConfig& config)
    : config_(config), cfg_builder_(nullptr) {}

CallGraphBuilder::~CallGraphBuilder() = default;

void CallGraphBuilder::set_cfg_builder(std::shared_ptr<CFGBuilder> cfg_builder) {
    cfg_builder_ = std::move(cfg_builder);
}

CallGraphResult CallGraphBuilder::build_call_graph(const BinaryAnalysisResult& analysis,
                                                    const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs) {
    resolutions_.clear();
    
    auto graph = std::make_unique<CallGraph>();
    BuildContext ctx;
    ctx.analysis = &analysis;
    ctx.cfgs = &cfgs;
    ctx.graph = graph.get();
    
    CallGraphResult result = build_call_graph_internal(analysis, cfgs, ctx);
    return result;
}

CallGraphResult CallGraphBuilder::build_call_graph(const BinaryAnalysisResult& analysis) {
    std::vector<std::unique_ptr<ControlFlowGraph>> empty_cfgs;
    return build_call_graph(analysis, empty_cfgs);
}

CallGraphResult CallGraphBuilder::build_local_call_graph(const BinaryAnalysisResult& analysis,
                                                          TypedAddress function_address,
                                                          size_t depth) {
    const FunctionInfo* target_func = nullptr;
    for (const auto& func : analysis.functions) {
        if (func.address == function_address.value()) {
            target_func = &func;
            break;
        }
    }
    
    if (!target_func) {
        return CallGraphResult("Function not found at address " + function_address.to_string());
    }
    
    auto result = build_call_graph(analysis);
    if (!result.success) return result;
    
    auto& graph = *result.graph;
    uint32_t target_node = UINT32_MAX;
    
    for (const auto& node : graph.nodes) {
        if (node.address.value() == function_address.value()) {
            target_node = node.id;
            break;
        }
    }
    
    if (target_node == UINT32_MAX) {
        return CallGraphResult("Function node not found in call graph");
    }
    
    std::unordered_set<uint32_t> include;
    std::queue<std::pair<uint32_t, size_t>> q;
    q.emplace(target_node, 0);
    include.insert(target_node);
    
    while (!q.empty()) {
        auto [node_id, d] = q.front();
        q.pop();
        
        if (d >= depth) continue;
        
        for (uint32_t callee_id : graph.nodes[node_id].callees) {
            if (include.insert(callee_id).second) {
                q.emplace(callee_id, d + 1);
            }
        }
        
        for (uint32_t caller_id : graph.nodes[node_id].callers) {
            if (include.insert(caller_id).second) {
                q.emplace(caller_id, d + 1);
            }
        }
    }
    
    auto filtered = std::make_unique<CallGraph>();
    std::unordered_map<uint32_t, uint32_t> old_to_new;
    
    for (uint32_t old_id : include) {
        const auto& old_node = graph.nodes[old_id];
        uint32_t new_id = static_cast<uint32_t>(filtered->nodes.size());
        old_to_new[old_id] = new_id;
        
        CallGraphNode new_node = old_node;
        new_node.id = new_id;
        new_node.outgoing_edges.clear();
        new_node.incoming_edges.clear();
        new_node.callees.clear();
        new_node.callers.clear();
        
        filtered->nodes.push_back(std::move(new_node));
        filtered->address_to_node[old_node.address.value()] = new_id;
        filtered->name_to_node[old_node.name] = new_id;
    }
    
    for (const auto& edge : graph.edges) {
        if (include.count(edge.source_node_id) && include.count(edge.target_node_id)) {
            uint32_t new_src = old_to_new[edge.source_node_id];
            uint32_t new_dst = old_to_new[edge.target_node_id];
            uint32_t new_edge_id = static_cast<uint32_t>(filtered->edges.size());
            
            CallGraphEdge new_edge = edge;
            new_edge.source_node_id = new_src;
            new_edge.target_node_id = new_dst;
            
            filtered->edges.push_back(std::move(new_edge));
            
            filtered->nodes[new_src].outgoing_edges.push_back(new_edge_id);
            filtered->nodes[new_dst].incoming_edges.push_back(new_edge_id);
            filtered->nodes[new_src].callees.push_back(new_dst);
            filtered->nodes[new_dst].callers.push_back(new_src);
        }
    }
    
    filtered->compute_statistics();
    filtered->is_valid = true;
    
    return CallGraphResult(std::move(filtered));
}

CallGraphResult CallGraphBuilder::build_call_graph_internal(const BinaryAnalysisResult& analysis,
                                                             const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                                             BuildContext& ctx) {
    for (const auto& func : analysis.functions) {
        create_or_get_node(ctx, const_cast<FunctionInfo*>(&func), false);
    }
    
    for (const auto& import : analysis.imports) {
        for (const auto& sym : import.functions) {
            if (sym.address != 0) {
                create_external_node(ctx, TypedAddress::va(sym.address), sym.name, sym.name);
            }
        }
    }
    
    std::vector<CallSite> call_sites = extract_call_sites(ctx, analysis, cfgs);
    
    resolve_all_calls(ctx, analysis, cfgs);
    
    for (const auto& resolution : resolutions_) {
        uint32_t src_id = create_or_get_node(ctx, resolution.site.caller, false);
        
        for (const auto& target : resolution.targets) {
            uint32_t dst_id = UINT32_MAX;
            
            if (target.function) {
                dst_id = create_or_get_node(ctx, target.function, target.is_external);
            } else if (target.address.valid()) {
                dst_id = create_external_node(ctx, target.address, "unknown_" + 
                    std::to_string(target.address.value()), target.symbol_name);
            }
            
            if (dst_id != UINT32_MAX) {
                add_edge(ctx, src_id, dst_id, resolution);
            }
        }
        
        if (resolution.targets.empty() && config_.include_unresolved) {
            add_edge(ctx, src_id, UINT32_MAX, resolution);
        }
    }
    
    if (config_.merge_duplicate_edges) {
        merge_edges(ctx);
    }
    
    if (config_.compute_recursion) {
        identify_recursion(ctx);
        identify_mutual_recursion(ctx);
    }
    
    if (config_.compute_statistics) {
        ctx.graph->compute_statistics();
    }
    
    std::string validation_error;
    if (!validate_graph(*ctx.graph, validation_error)) {
        ctx.graph->is_valid = false;
        ctx.graph->error_message = "Call graph validation failed: " + validation_error;
    } else {
        ctx.graph->is_valid = true;
    }
    
    // Transfer ownership of the graph
    auto graph_ptr = std::unique_ptr<CallGraph>(ctx.graph);
    ctx.graph = nullptr;
    return CallGraphResult(std::move(graph_ptr));
}

uint32_t CallGraphBuilder::create_or_get_node(BuildContext& ctx, FunctionInfo* function, bool is_external) {
    if (!function) return UINT32_MAX;
    
    TypedAddress addr = TypedAddress::va(function->address);
    auto it = ctx.graph->address_to_node.find(addr.value());
    if (it != ctx.graph->address_to_node.end()) {
        return it->second;
    }
    
    uint32_t id = static_cast<uint32_t>(ctx.graph->nodes.size());
    CallGraphNode node(id, function, function->name);
    node.address = addr;
    node.is_external = is_external;
    node.is_thunk = is_thunk_function(*function);
    node.is_entry_point = (function->address == ctx.analysis->entry_point);
    
    ctx.graph->nodes.push_back(std::move(node));
    ctx.graph->address_to_node[addr.value()] = id;
    ctx.graph->name_to_node[function->name] = id;
    
    return id;
}

uint32_t CallGraphBuilder::create_external_node(BuildContext& ctx, TypedAddress address, 
                                                 const std::string& name, const std::string& symbol_name) {
    (void)symbol_name;
    
    auto it = ctx.graph->address_to_node.find(address.value());
    if (it != ctx.graph->address_to_node.end()) {
        return it->second;
    }
    
    uint32_t id = static_cast<uint32_t>(ctx.graph->nodes.size());
    CallGraphNode node(id, nullptr, name);
    node.address = address;
    node.is_external = true;
    node.is_entry_point = false;
    
    ctx.graph->nodes.push_back(std::move(node));
    ctx.graph->address_to_node[address.value()] = id;
    ctx.graph->name_to_node[name] = id;
    
    return id;
}

void CallGraphBuilder::add_edge(BuildContext& ctx, uint32_t src_id, uint32_t dst_id, 
                                 const CallResolution& resolution) {
    if (src_id >= ctx.graph->nodes.size()) return;
    if (dst_id != UINT32_MAX && dst_id >= ctx.graph->nodes.size()) return;
    
    uint32_t edge_id = static_cast<uint32_t>(ctx.graph->edges.size());
    CallGraphEdge edge(src_id, dst_id, resolution.edge_type, 
                       resolution.targets.empty() ? CallResolutionConfidence::Unknown : 
                       resolution.targets[0].confidence);
    
    edge.call_sites.push_back(resolution.site);
    edge.is_recursive = resolution.is_recursive;
    edge.is_tail_call = (resolution.edge_type == CallEdgeType::TailCall);
    
    ctx.graph->edges.push_back(std::move(edge));
    
    if (dst_id != UINT32_MAX) {
        ctx.graph->nodes[src_id].outgoing_edges.push_back(edge_id);
        ctx.graph->nodes[dst_id].incoming_edges.push_back(edge_id);
        ctx.graph->nodes[src_id].callees.push_back(dst_id);
        ctx.graph->nodes[dst_id].callers.push_back(src_id);
        ctx.graph->nodes[src_id].call_count++;
    }
}

void CallGraphBuilder::merge_edges(BuildContext& ctx) {
    std::unordered_map<uint64_t, std::vector<uint32_t>> edge_groups;
    
    for (uint32_t i = 0; i < ctx.graph->edges.size(); ++i) {
        const auto& edge = ctx.graph->edges[i];
        uint64_t key = (static_cast<uint64_t>(edge.source_node_id) << 32) | 
                       (static_cast<uint64_t>(edge.target_node_id) << 8) | 
                       static_cast<uint64_t>(edge.type);
        edge_groups[key].push_back(i);
    }
    
    std::vector<CallGraphEdge> merged_edges;
    std::unordered_map<uint32_t, uint32_t> old_to_new;
    
    for (auto& [key, indices] : edge_groups) {
        if (indices.size() == 1) {
            uint32_t old_id = indices[0];
            uint32_t new_id = static_cast<uint32_t>(merged_edges.size());
            old_to_new[old_id] = new_id;
            merged_edges.push_back(std::move(ctx.graph->edges[old_id]));
        } else {
            uint32_t new_id = static_cast<uint32_t>(merged_edges.size());
            CallGraphEdge merged = ctx.graph->edges[indices[0]];
            
            for (size_t i = 1; i < indices.size(); ++i) {
                const auto& other = ctx.graph->edges[indices[i]];
                merged.call_sites.insert(merged.call_sites.end(), 
                                        other.call_sites.begin(), other.call_sites.end());
                merged.confidence = std::max(merged.confidence, other.confidence);
            }
            
            old_to_new[indices[0]] = new_id;
            merged_edges.push_back(std::move(merged));
            
            for (size_t i = 1; i < indices.size(); ++i) {
                old_to_new[indices[i]] = new_id;
            }
        }
    }
    
    for (auto& node : ctx.graph->nodes) {
        auto update_refs = [&](std::vector<uint32_t>& refs) {
            std::vector<uint32_t> new_refs;
            for (uint32_t old_id : refs) {
                auto it = old_to_new.find(old_id);
                if (it != old_to_new.end()) {
                    new_refs.push_back(it->second);
                }
            }
            std::sort(new_refs.begin(), new_refs.end());
            new_refs.erase(std::unique(new_refs.begin(), new_refs.end()), new_refs.end());
            refs = std::move(new_refs);
        };
        
        update_refs(node.outgoing_edges);
        update_refs(node.incoming_edges);
    }
    
    ctx.graph->edges = std::move(merged_edges);
}

void CallGraphBuilder::resolve_all_calls(BuildContext& ctx, const BinaryAnalysisResult& analysis,
                                          const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs) {
    std::vector<CallSite> call_sites = extract_call_sites(ctx, analysis, cfgs);
    
    for (const auto& site : call_sites) {
        CallResolution resolution;
        resolution.site = site;
        
        switch (site.edge_type) {
            case CallEdgeType::Direct:
                resolution = resolve_direct_call(ctx, site, analysis);
                break;
            case CallEdgeType::Indirect:
                resolution = resolve_indirect_call(ctx, site, analysis);
                break;
            case CallEdgeType::Import:
                resolution = resolve_import_call(ctx, site, analysis);
                break;
            default:
                resolution = resolve_direct_call(ctx, site, analysis);
                break;
        }
        
        resolutions_.push_back(std::move(resolution));
    }
}

CallResolution CallGraphBuilder::resolve_direct_call(BuildContext&, const CallSite& site, 
                                                      const BinaryAnalysisResult& analysis) {
    CallResolution resolution;
    resolution.site = site;
    resolution.edge_type = CallEdgeType::Direct;
    
    if (!site.address.valid()) {
        resolution.is_ambiguous = true;
        resolution.ambiguity_reason = "No target address";
        return resolution;
    }
    
    uint64_t target_addr = site.address.value();
    CallTarget target(TypedAddress::va(target_addr), CallResolutionConfidence::High, "Direct call");
    target.address = TypedAddress::va(target_addr);
    
    for (const auto& func : analysis.functions) {
        if (func.address == target_addr) {
            target.function = const_cast<FunctionInfo*>(&func);
            target.confidence = CallResolutionConfidence::Confirmed;
            target.resolution_method = "Function at target address";
            break;
        }
    }
    
    if (!target.function) {
        for (const auto& import : analysis.imports) {
            for (const auto& sym : import.functions) {
                if (sym.address == target_addr) {
                    target.is_import = true;
                    target.symbol_name = sym.name;
                    target.confidence = CallResolutionConfidence::High;
                    target.resolution_method = "Import table entry";
                    target.is_external = true;
                    break;
                }
            }
            if (target.is_import) break;
        }
    }
    
    if (config_.identify_thunks && !target.function) {
        TypedAddress thunk_target = resolve_thunk_target(target_addr);
        if (thunk_target.valid()) {
            target.address = thunk_target;
            target.is_thunk = true;
            target.confidence = CallResolutionConfidence::Medium;
            target.resolution_method = "Thunk resolution";
        }
    }
    
    resolution.targets.push_back(std::move(target));
    resolution.is_recursive = false;
    return resolution;
}

CallResolution CallGraphBuilder::resolve_indirect_call(BuildContext& ctx, const CallSite& site,
                                                        const BinaryAnalysisResult& analysis) {
    (void)ctx;
    CallResolution resolution;
    resolution.site = site;
    resolution.edge_type = CallEdgeType::Indirect;
    
    std::vector<CallTarget> targets = heuristic_resolve_indirect(site, analysis);
    
    if (targets.empty()) {
        CallTarget target(site.address, CallResolutionConfidence::Unknown, "Indirect call - unresolved");
        target.resolution_method = "No resolution possible";
        resolution.targets.push_back(std::move(target));
        resolution.is_ambiguous = false;
    } else if (targets.size() == 1) {
        resolution.targets.push_back(std::move(targets[0]));
    } else {
        resolution.targets = std::move(targets);
        resolution.is_ambiguous = true;
        resolution.ambiguity_reason = "Multiple candidates for indirect call";
    }
    
    return resolution;
}

CallResolution CallGraphBuilder::resolve_import_call(BuildContext& ctx, const CallSite& site,
                                                      const BinaryAnalysisResult& analysis) {
    CallResolution resolution;
    resolution.site = site;
    resolution.edge_type = CallEdgeType::Import;
    
    if (site.operands.empty()) {
        resolution.is_ambiguous = true;
        resolution.ambiguity_reason = "No symbol name in import call";
        return resolution;
    }
    
    for (const auto& import : analysis.imports) {
        for (const auto& sym : import.functions) {
            if (sym.name == site.operands || site.operands.find(sym.name) != std::string::npos) {
                CallTarget target(TypedAddress::va(sym.address), CallResolutionConfidence::Confirmed, "Import table");
                target.address = TypedAddress::va(sym.address);
                target.symbol_name = sym.name;
                target.is_import = true;
                target.is_external = true;
                target.resolution_method = "Import table lookup";
                resolution.targets.push_back(std::move(target));
                return resolution;
            }
        }
    }
    
    TypedAddress import_addr = resolve_import(ctx, site.operands);
    if (import_addr.valid()) {
        CallTarget target(import_addr, CallResolutionConfidence::High, "Symbol name lookup");
        target.symbol_name = site.operands;
        target.is_import = true;
        target.is_external = true;
        target.resolution_method = "Symbol name resolution";
        resolution.targets.push_back(std::move(target));
        return resolution;
    }
    
    resolution.is_ambiguous = true;
    resolution.ambiguity_reason = "Import symbol not found: " + site.operands;
    return resolution;
}

CallResolution CallGraphBuilder::resolve_thunk_call(BuildContext& ctx, const CallSite& site,
                                                     const BinaryAnalysisResult& analysis) {
    (void)ctx;
    CallResolution resolution;
    resolution.site = site;
    resolution.edge_type = CallEdgeType::Thunk;
    
    if (site.caller && is_thunk_function(*site.caller)) {
        TypedAddress target_addr = resolve_thunk_target(*site.caller);
        if (target_addr.valid()) {
            CallTarget target(target_addr, CallResolutionConfidence::Medium, "Thunk function");
            target.is_thunk = true;
            target.resolution_method = "Thunk target resolution";
            
            for (const auto& func : analysis.functions) {
                if (func.address == target_addr.value()) {
                    target.function = const_cast<FunctionInfo*>(&func);
                    target.confidence = CallResolutionConfidence::High;
                    break;
                }
            }
            
            resolution.targets.push_back(std::move(target));
            return resolution;
        }
    }
    
    resolution.is_ambiguous = true;
    resolution.ambiguity_reason = "Thunk target not found";
    return resolution;
}

std::vector<CallSite> CallGraphBuilder::extract_call_sites(BuildContext& ctx,
                                                            const BinaryAnalysisResult& analysis,
                                                            const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs) {
    std::vector<CallSite> call_sites;
    
    if (!cfgs.empty()) {
        for (const auto& cfg : cfgs) {
            std::vector<CallSite> cfg_sites = extract_call_sites_from_cfg(ctx, *cfg);
            call_sites.insert(call_sites.end(), cfg_sites.begin(), cfg_sites.end());
        }
    } else {
        for (const auto& func : analysis.functions) {
            for (uint64_t target_addr : func.call_targets) {
                CallSite site;
                site.address = TypedAddress::va(target_addr);
                site.caller = const_cast<FunctionInfo*>(&func);
                site.mnemonic = "call";
                site.operands = "0x" + std::to_string(target_addr);
                site.edge_type = CallEdgeType::Direct;
                call_sites.push_back(std::move(site));
            }
        }
    }
    
    return call_sites;
}

std::vector<CallSite> CallGraphBuilder::extract_call_sites_from_cfg(BuildContext&, 
                                                                      const ControlFlowGraph& cfg) {
    std::vector<CallSite> call_sites;
    
    for (const auto& block : cfg.blocks) {
        for (const auto& edge : block.successors) {
            if (edge.type == CFGEdgeType::Call || edge.type == CFGEdgeType::IndirectCall) {
                CallSite site;
                site.address = TypedAddress::va(block.start_address + block.size - 5);
                site.caller = const_cast<FunctionInfo*>(&cfg.function);
                site.mnemonic = edge.type == CFGEdgeType::Call ? "call" : "call";
                site.operands = edge.target_address ? "0x" + std::to_string(edge.target_address.value()) : "indirect";
                site.edge_type = edge.type == CFGEdgeType::Call ? CallEdgeType::Direct : CallEdgeType::Indirect;
                site.is_resolved = edge.is_resolved;
                call_sites.push_back(std::move(site));
            }
        }
    }
    
    return call_sites;
}

bool CallGraphBuilder::is_thunk_function(const FunctionInfo& function) const {
    if (function.size > 32) return false;
    if (function.name.find("thunk") != std::string::npos) return true;
    if (function.name.find("jmp_") != std::string::npos) return true;
    return false;
}

TypedAddress CallGraphBuilder::resolve_thunk_target(const FunctionInfo& function) const {
    (void)function;
    return TypedAddress::va(0);
}

TypedAddress CallGraphBuilder::resolve_thunk_target(uint64_t address) const {
    (void)address;
    return TypedAddress::va(0);
}

bool CallGraphBuilder::is_tail_call(const CallSite& site, const ControlFlowGraph* cfg) const {
    (void)site;
    (void)cfg;
    return false;
}

TypedAddress CallGraphBuilder::resolve_import(BuildContext& ctx, const std::string& symbol_name) const {
    if (!ctx.analysis) return TypedAddress::va(0);
    
    for (const auto& import : ctx.analysis->imports) {
        for (const auto& sym : import.functions) {
            if (sym.name == symbol_name) {
                return TypedAddress::va(sym.address);
            }
        }
    }
    return TypedAddress::va(0);
}

std::vector<CallTarget> CallGraphBuilder::heuristic_resolve_indirect(const CallSite& site,
                                                                      const BinaryAnalysisResult& analysis) const {
    (void)site;
    (void)analysis;
    return {};
}

void CallGraphBuilder::identify_recursion(BuildContext& ctx) {
    for (auto& node : ctx.graph->nodes) {
        for (uint32_t callee_id : node.callees) {
            if (callee_id == node.id) {
                node.is_recursive = true;
                for (uint32_t edge_id : node.outgoing_edges) {
                    if (edge_id < ctx.graph->edges.size()) {
                        auto& edge = ctx.graph->edges[edge_id];
                        if (edge.target_node_id == node.id) {
                            edge.type = CallEdgeType::Recursive;
                            edge.is_recursive = true;
                        }
                    }
                }
            }
        }
    }
}

void CallGraphBuilder::identify_mutual_recursion(BuildContext& ctx) {
    std::vector<int> index(ctx.graph->nodes.size(), -1);
    std::vector<int> lowlink(ctx.graph->nodes.size(), -1);
    std::vector<bool> on_stack(ctx.graph->nodes.size(), false);
    std::stack<uint32_t> stack;
    int idx = 0;
    std::vector<std::vector<uint32_t>> sccs;
    
    std::function<void(uint32_t)> strongconnect = [&](uint32_t v) {
        index[v] = lowlink[v] = idx++;
        stack.push(v);
        on_stack[v] = true;
        
        for (uint32_t callee_id : ctx.graph->nodes[v].callees) {
            if (callee_id >= ctx.graph->nodes.size()) continue;
            if (index[callee_id] == -1) {
                strongconnect(callee_id);
                lowlink[v] = std::min(lowlink[v], lowlink[callee_id]);
            } else if (on_stack[callee_id]) {
                lowlink[v] = std::min(lowlink[v], index[callee_id]);
            }
        }
        
        if (lowlink[v] == index[v]) {
            std::vector<uint32_t> scc;
            while (true) {
                uint32_t w = stack.top();
                stack.pop();
                on_stack[w] = false;
                scc.push_back(w);
                if (w == v) break;
            }
            if (scc.size() > 1) {
                sccs.push_back(std::move(scc));
            }
        }
    };
    
    for (uint32_t i = 0; i < ctx.graph->nodes.size(); ++i) {
        if (index[i] == -1) {
            strongconnect(i);
        }
    }
    
    for (const auto& scc : sccs) {
        for (uint32_t node_id : scc) {
            ctx.graph->nodes[node_id].is_mutual_recursive = true;
        }
    }
}

bool CallGraphBuilder::validate_graph(CallGraph& graph, std::string& error) const {
    return graph.validate(error);
}

} // namespace fortress
