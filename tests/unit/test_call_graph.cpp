// FORTRESS Call Graph Unit Tests
// Tests for Interprocedural call graph construction

#include <gtest/gtest.h>
#include <fortress/binary/analysis/call_graph.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/cfg_builder.h>
#include <fortress/core/types.h>
#include <vector>
#include <memory>

using namespace fortress;

// Test fixture
class CallGraphBuilderTest : public ::testing::Test {
protected:
    void SetUp() override {
        config = CallGraphConfig();
        config.compute_recursion = true;
        config.compute_statistics = true;
        config.merge_duplicate_edges = true;
        
        builder = std::make_unique<CallGraphBuilder>(config);
        
        analysis = make_test_analysis();
    }
    
    BinaryAnalysisResult make_test_analysis() {
        BinaryAnalysisResult analysis;
        analysis.format = BinaryFormat::PE;
        analysis.architecture = Architecture::X64;
        analysis.is_64bit = true;
        analysis.entry_point = 0x1000;
        
        // Add functions
        FunctionInfo func1;
        func1.name = "main";
        func1.address = 0x1000;
        func1.size = 100;
        func1.architecture = Architecture::X64;
        func1.confidence = ConfidenceLevel::High;
        func1.source = FunctionSource::EntryPoint;
        func1.call_targets = {0x2000, 0x3000};
        analysis.functions.push_back(func1);
        
        FunctionInfo func2;
        func2.name = "func_a";
        func2.address = 0x2000;
        func2.size = 50;
        func2.architecture = Architecture::X64;
        func2.confidence = ConfidenceLevel::High;
        func2.source = FunctionSource::Symbol;
        func2.call_targets = {0x3000};
        analysis.functions.push_back(func2);
        
        FunctionInfo func3;
        func3.name = "func_b";
        func3.address = 0x3000;
        func3.size = 30;
        func3.architecture = Architecture::X64;
        func3.confidence = ConfidenceLevel::High;
        func3.source = FunctionSource::Symbol;
        analysis.functions.push_back(func3);
        
        // Add import
        ImportInfo import;
        import.library_name = "kernel32.dll";
        SymbolInfo sym;
        sym.name = "GetTickCount";
        sym.address = 0x4000;
        sym.type = SymbolType::Function;
        import.functions.push_back(sym);
        analysis.imports.push_back(import);
        
        return analysis;
    }
    
    CallGraphConfig config;
    std::unique_ptr<CallGraphBuilder> builder;
    BinaryAnalysisResult analysis;
};

// ============================================================================
// Test: Basic call graph construction
// ============================================================================
TEST_F(CallGraphBuilderTest, BasicCallGraph) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    EXPECT_NE(result.graph, nullptr);
    EXPECT_TRUE(result.graph->is_valid);
    
    // Should have 3 internal functions + 1 import
    EXPECT_EQ(result.graph->nodes.size(), 4);
    EXPECT_EQ(result.graph->edges.size(), 3); // main->func_a, main->func_b, func_a->func_b
    
    // Check statistics
    EXPECT_EQ(result.graph->statistics.internal_functions, 3);
    EXPECT_EQ(result.graph->statistics.external_functions, 1);
    EXPECT_EQ(result.graph->statistics.direct_calls, 3);
}

// ============================================================================
// Test: Function calling another function
// ============================================================================
TEST_F(CallGraphBuilderTest, FunctionCallingAnother) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    // Find main and func_a nodes
    const auto* main_node = result.graph->find_node_by_name("main");
    const auto* func_a_node = result.graph->find_node_by_name("func_a");
    
    ASSERT_NE(main_node, nullptr);
    ASSERT_NE(func_a_node, nullptr);
    
    // main should call func_a
    bool found = false;
    for (uint32_t callee_id : main_node->callees) {
        if (callee_id == func_a_node->id) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

// ============================================================================
// Test: Multiple calls to same destination
// ============================================================================
TEST_F(CallGraphBuilderTest, MultipleCallsToSameDestination) {
    // Add another call from main to func_b
    analysis.functions[0].call_targets.push_back(0x3000);
    
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    // Edge should be merged (config.merge_duplicate_edges = true)
    const auto* main_node = result.graph->find_node_by_name("main");
    const auto* func_b_node = result.graph->find_node_by_name("func_b");
    
    ASSERT_NE(main_node, nullptr);
    ASSERT_NE(func_b_node, nullptr);
    
    // Should have only 1 edge to func_b (merged)
    int edge_count = 0;
    for (uint32_t callee_id : main_node->callees) {
        if (callee_id == func_b_node->id) edge_count++;
    }
    EXPECT_EQ(edge_count, 1);
    
    // But call_sites should have 2 entries
    for (uint32_t edge_id : main_node->outgoing_edges) {
        if (edge_id < result.graph->edges.size()) {
            const auto& edge = result.graph->edges[edge_id];
            if (edge.target_node_id == func_b_node->id) {
                EXPECT_EQ(edge.call_sites.size(), 2);
            }
        }
    }
}

// ============================================================================
// Test: Recursive calls
// ============================================================================
TEST_F(CallGraphBuilderTest, RecursiveCalls) {
    // Add recursive call
    FunctionInfo recursive_func;
    recursive_func.name = "recursive";
    recursive_func.address = 0x5000;
    recursive_func.size = 100;
    recursive_func.architecture = Architecture::X64;
    recursive_func.confidence = ConfidenceLevel::High;
    recursive_func.source = FunctionSource::Symbol;
    recursive_func.call_targets = {0x5000}; // calls itself
    analysis.functions.push_back(recursive_func);
    
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* rec_node = result.graph->find_node_by_name("recursive");
    ASSERT_NE(rec_node, nullptr);
    
    EXPECT_TRUE(rec_node->is_recursive);
    EXPECT_EQ(result.graph->statistics.recursive_functions, 1);
    
    // Check recursive edge
    bool found_recursive = false;
    for (uint32_t edge_id : rec_node->outgoing_edges) {
        if (edge_id < result.graph->edges.size()) {
            const auto& edge = result.graph->edges[edge_id];
            if (edge.type == CallEdgeType::Recursive) {
                found_recursive = true;
                EXPECT_TRUE(edge.is_recursive);
            }
        }
    }
    EXPECT_TRUE(found_recursive);
}

// ============================================================================
// Test: Mutual recursion
// ============================================================================
TEST_F(CallGraphBuilderTest, MutualRecursion) {
    FunctionInfo func_x;
    func_x.name = "mutual_x";
    func_x.address = 0x6000;
    func_x.size = 50;
    func_x.architecture = Architecture::X64;
    func_x.confidence = ConfidenceLevel::High;
    func_x.source = FunctionSource::Symbol;
    func_x.call_targets = {0x6100};
    analysis.functions.push_back(func_x);
    
    FunctionInfo func_y;
    func_y.name = "mutual_y";
    func_y.address = 0x6100;
    func_y.size = 50;
    func_y.architecture = Architecture::X64;
    func_y.confidence = ConfidenceLevel::High;
    func_y.source = FunctionSource::Symbol;
    func_y.call_targets = {0x6000};
    analysis.functions.push_back(func_y);
    
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* x_node = result.graph->find_node_by_name("mutual_x");
    const auto* y_node = result.graph->find_node_by_name("mutual_y");
    
    ASSERT_NE(x_node, nullptr);
    ASSERT_NE(y_node, nullptr);
    
    EXPECT_TRUE(x_node->is_mutual_recursive);
    EXPECT_TRUE(y_node->is_mutual_recursive);
    
    // Check mutual recursive pairs count
    EXPECT_EQ(result.graph->statistics.mutual_recursive_pairs, 1);
    
    // Check edges
    bool found_mutual_x = false;
    bool found_mutual_y = false;
    for (uint32_t edge_id : x_node->outgoing_edges) {
        if (edge_id < result.graph->edges.size()) {
            const auto& edge = result.graph->edges[edge_id];
            if (edge.target_node_id == y_node->id && edge.type == CallEdgeType::MutualRecursive) {
                found_mutual_x = true;
            }
        }
    }
    for (uint32_t edge_id : y_node->outgoing_edges) {
        if (edge_id < result.graph->edges.size()) {
            const auto& edge = result.graph->edges[edge_id];
            if (edge.target_node_id == x_node->id && edge.type == CallEdgeType::MutualRecursive) {
                found_mutual_y = true;
            }
        }
    }
    EXPECT_TRUE(found_mutual_x);
    EXPECT_TRUE(found_mutual_y);
}

// ============================================================================
// Test: Call to imported function
// ============================================================================
TEST_F(CallGraphBuilderTest, CallToImportedFunction) {
    // Add call to import
    analysis.functions[0].call_targets.push_back(0x4000);
    
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* main_node = result.graph->find_node_by_name("main");
    const auto* import_node = result.graph->find_node_by_name("GetTickCount");
    
    ASSERT_NE(main_node, nullptr);
    ASSERT_NE(import_node, nullptr);
    
    EXPECT_TRUE(import_node->is_external);
    EXPECT_TRUE(import_node->is_import);
    
    // Check import edge
    bool found_import = false;
    for (uint32_t edge_id : main_node->outgoing_edges) {
        if (edge_id < result.graph->edges.size()) {
            const auto& edge = result.graph->edges[edge_id];
            if (edge.target_node_id == import_node->id && edge.type == CallEdgeType::Import) {
                found_import = true;
                EXPECT_EQ(edge.confidence, CallResolutionConfidence::Confirmed);
            }
        }
    }
    EXPECT_TRUE(found_import);
}

// ============================================================================
// Test: Indirect call unresolved
// ============================================================================
TEST_F(CallGraphBuilderTest, IndirectCallUnresolved) {
    // This test would require CFG with indirect call edge
    // For now, test that builder handles empty CFGs
    std::vector<std::unique_ptr<ControlFlowGraph>> empty_cfgs;
    
    CallGraphConfig config;
    config.include_unresolved = true;
    auto builder2 = std::make_unique<CallGraphBuilder>(config);
    
    auto result = builder2->build_call_graph(analysis, empty_cfgs);
    
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.graph->is_valid);
}

// ============================================================================
// Test: External functions included
// ============================================================================
TEST_F(CallGraphBuilderTest, ExternalFunctionsIncluded) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    // Import function should be included
    const auto* import_node = result.graph->find_node_by_name("GetTickCount");
    ASSERT_NE(import_node, nullptr);
    EXPECT_TRUE(import_node->is_external);
    EXPECT_TRUE(import_node->is_import);
    
    EXPECT_EQ(result.graph->statistics.external_functions, 1);
    EXPECT_EQ(result.graph->statistics.import_functions, 1);
}

// ============================================================================
// Test: Build call graph without CFGs
// ============================================================================
TEST_F(CallGraphBuilderTest, BuildWithoutCFGs) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.graph->is_valid);
    
    // Should still build from function call_targets
    EXPECT_GT(result.graph->edges.size(), 0);
}

// ============================================================================
// Test: Build local call graph
// ============================================================================
TEST_F(CallGraphBuilderTest, BuildLocalCallGraph) {
    auto result = builder->build_local_call_graph(analysis, TypedAddress::va(0x1000), 1);
    
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.graph->is_valid);
    
    // Should include main and its direct callees
    const auto* main_node = result.graph->find_node_by_name("main");
    ASSERT_NE(main_node, nullptr);
    
    // At depth 1, should have func_a and func_b
    EXPECT_EQ(result.graph->nodes.size(), 3);
}

// ============================================================================
// Test: Cycles detection
// ============================================================================
TEST_F(CallGraphBuilderTest, CyclesDetection) {
    // Add mutual recursion
    FunctionInfo func_x;
    func_x.name = "cycle_x";
    func_x.address = 0x7000;
    func_x.size = 50;
    func_x.architecture = Architecture::X64;
    func_x.confidence = ConfidenceLevel::High;
    func_x.source = FunctionSource::Symbol;
    func_x.call_targets = {0x7100};
    analysis.functions.push_back(func_x);
    
    FunctionInfo func_y;
    func_y.name = "cycle_y";
    func_y.address = 0x7100;
    func_y.size = 50;
    func_y.architecture = Architecture::X64;
    func_y.confidence = ConfidenceLevel::High;
    func_y.source = FunctionSource::Symbol;
    func_y.call_targets = {0x7000};
    analysis.functions.push_back(func_y);
    
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    auto cycles = result.graph->find_cycles();
    EXPECT_GT(cycles.size(), 0);
    
    // Should find the 2-node cycle
    bool found_cycle = false;
    for (const auto& cycle : cycles) {
        if (cycle.size() == 2) {
            found_cycle = true;
            break;
        }
    }
    EXPECT_TRUE(found_cycle);
}

// ============================================================================
// Test: Path finding
// ============================================================================
TEST_F(CallGraphBuilderTest, PathFinding) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* main_node = result.graph->find_node_by_name("main");
    const auto* func_b_node = result.graph->find_node_by_name("func_b");
    
    ASSERT_NE(main_node, nullptr);
    ASSERT_NE(func_b_node, nullptr);
    
    // Should find path from main to func_b (direct)
    auto path = result.graph->find_path(main_node->id, func_b_node->id);
    EXPECT_TRUE(path.has_value());
    EXPECT_GE(path->size(), 2);
    EXPECT_EQ(path->front(), main_node->id);
    EXPECT_EQ(path->back(), func_b_node->id);
}

// ============================================================================
// Test: Transitive callees
// ============================================================================
TEST_F(CallGraphBuilderTest, TransitiveCallees) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* main_node = result.graph->find_node_by_name("main");
    ASSERT_NE(main_node, nullptr);
    
    auto callees = result.graph->get_transitive_callees(main_node->id);
    
    // Should find both func_a and func_b
    EXPECT_GE(callees.size(), 2);
}

// ============================================================================
// Test: Transitive callers
// ============================================================================
TEST_F(CallGraphBuilderTest, TransitiveCallers) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* func_b_node = result.graph->find_node_by_name("func_b");
    ASSERT_NE(func_b_node, nullptr);
    
    auto callers = result.graph->get_transitive_callers(func_b_node->id);
    
    // Should find main
    EXPECT_GE(callers.size(), 1);
}

// ============================================================================
// Test: JSON export
// ============================================================================
TEST_F(CallGraphBuilderTest, JSONExport) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    std::string json = result.graph->to_json();
    
    EXPECT_TRUE(json.find("nodes") != std::string::npos);
    EXPECT_TRUE(json.find("edges") != std::string::npos);
    EXPECT_TRUE(json.find("internal_functions") != std::string::npos);
    EXPECT_TRUE(json.find("external_functions") != std::string::npos);
    EXPECT_TRUE(json.find("direct_calls") != std::string::npos);
    EXPECT_TRUE(json.find("valid") != std::string::npos);
    EXPECT_TRUE(json.find("true") != std::string::npos);
}

// ============================================================================
// Test: GraphViz DOT export
// ============================================================================
TEST_F(CallGraphBuilderTest, DotExport) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    std::string dot = result.graph->to_dot("test_callgraph");
    
    EXPECT_TRUE(dot.find("digraph test_callgraph") != std::string::npos);
    EXPECT_TRUE(dot.find("->") != std::string::npos);
}

// ============================================================================
// Test: Filtered DOT export
// ============================================================================
TEST_F(CallGraphBuilderTest, FilteredDotExport) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    std::unordered_set<std::string> include = {"main", "func_a"};
    std::string dot = result.graph->to_dot_filtered("filtered", include);
    
    EXPECT_TRUE(dot.find("digraph filtered") != std::string::npos);
    EXPECT_TRUE(dot.find("main") != std::string::npos);
    EXPECT_TRUE(dot.find("func_a") != std::string::npos);
    EXPECT_TRUE(dot.find("func_b") == std::string::npos); // Excluded
    EXPECT_TRUE(dot.find("GetTickCount") == std::string::npos); // Excluded
}

// ============================================================================
// Test: Validation
// ============================================================================
TEST_F(CallGraphBuilderTest, Validation) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.graph->is_valid);
    
    std::string error;
    EXPECT_TRUE(result.graph->validate(error));
    EXPECT_TRUE(error.empty());
}

// ============================================================================
// Test: Summary
// ============================================================================
TEST_F(CallGraphBuilderTest, Summary) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    std::string summary = result.graph->summary();
    
    EXPECT_TRUE(summary.find("CallGraph") != std::string::npos);
    EXPECT_TRUE(summary.find("nodes") != std::string::npos);
    EXPECT_TRUE(summary.find("edges") != std::string::npos);
}

// ============================================================================
// Test: Statistics
// ============================================================================
TEST_F(CallGraphBuilderTest, Statistics) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto& stats = result.graph->statistics;
    
    EXPECT_EQ(stats.internal_functions, 3);
    EXPECT_EQ(stats.external_functions, 1);
    EXPECT_EQ(stats.import_functions, 1);
    EXPECT_EQ(stats.direct_calls, 3);
    EXPECT_GT(stats.avg_callees_per_function, 0);
    EXPECT_GT(stats.avg_callers_per_function, 0);
}

// ============================================================================
// Test: Config options
// ============================================================================
TEST_F(CallGraphBuilderTest, ConfigOptions) {
    CallGraphConfig config;
    config.compute_recursion = false;
    config.compute_statistics = false;
    config.merge_duplicate_edges = false;
    config.include_unresolved = false;
    config.follow_imports = false;
    
    auto builder2 = std::make_unique<CallGraphBuilder>(config);
    auto result = builder2->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    // Recursion should not be identified
    EXPECT_EQ(result.graph->statistics.recursive_functions, 0);
    
    // Statistics should not be computed (or be zero)
    EXPECT_EQ(result.graph->statistics.total_nodes, 0);
    EXPECT_EQ(result.graph->statistics.total_edges, 0);
    
    // Imports should not be followed
    const auto* import_node = result.graph->find_node_by_name("GetTickCount");
    EXPECT_EQ(import_node, nullptr);
}

// ============================================================================
// Test: Thunk detection (placeholder)
// ============================================================================
TEST_F(CallGraphBuilderTest, ThunkDetection) {
    // Add a thunk-like function
    FunctionInfo thunk;
    thunk.name = "thunk_func";
    thunk.address = 0x8000;
    thunk.size = 16; // Small
    thunk.architecture = Architecture::X64;
    thunk.confidence = ConfidenceLevel::High;
    thunk.source = FunctionSource::Symbol;
    analysis.functions.push_back(thunk);
    
    // Add call to thunk
    analysis.functions[0].call_targets.push_back(0x8000);
    
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* thunk_node = result.graph->find_node_by_name("thunk_func");
    ASSERT_NE(thunk_node, nullptr);
    
    // Should be identified as thunk
    EXPECT_TRUE(thunk_node->is_thunk);
}

// ============================================================================
// Test: Find node by address
// ============================================================================
TEST_F(CallGraphBuilderTest, FindNodeByAddress) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* node = result.graph->find_node_by_address(TypedAddress::va(0x2000));
    ASSERT_NE(node, nullptr);
    EXPECT_EQ(node->name, "func_a");
}

// ============================================================================
// Test: Find node by name
// ============================================================================
TEST_F(CallGraphBuilderTest, FindNodeByName) {
    auto result = builder->build_call_graph(analysis);
    
    EXPECT_TRUE(result.success);
    
    const auto* node = result.graph->find_node_by_name("func_b");
    ASSERT_NE(node, nullptr);
    EXPECT_EQ(node->address.value(), 0x3000);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}