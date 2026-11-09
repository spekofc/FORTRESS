with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

# Update the build_call_graph_internal signature and return type
old = """CallGraphResult CallGraphBuilder::build_call_graph_internal(const BinaryAnalysisResult& analysis,
                                                             const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                                             BuildContext& ctx) {"""

new = """bool CallGraphBuilder::build_call_graph_internal(const BinaryAnalysisResult& analysis,
                                                             const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                                             BuildContext& ctx,
                                                             CallGraph& graph) {"""

content = content.replace(old, new)

# Update the return statements in build_call_graph_internal
old_return = """    return CallGraphResult(std::move(ctx.graph));
}"""

new_return = """    // Transfer ownership is handled by caller
    return true;
}"""

content = content.replace(old_return, new_return)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done fixing build_call_graph_internal')