with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

# Fix build_call_graph to properly transfer ownership
old = """CallGraphResult CallGraphBuilder::build_call_graph(const BinaryAnalysisResult& analysis,
                                                    const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs) {
    resolutions_.clear();
    
    BuildContext ctx;
    ctx.analysis = &analysis;
    ctx.cfgs = &cfgs;
    
    auto graph = std::make_unique<CallGraph>();
    ctx.graph = graph.get();
    
    CallGraphResult result = build_call_graph_internal(analysis, cfgs, ctx);
    if (result.success) {
        result.graph = std::move(graph);
    }
    return result;
}"""

new = """CallGraphResult CallGraphBuilder::build_call_graph(const BinaryAnalysisResult& analysis,
                                                    const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs) {
    resolutions_.clear();
    
    BuildContext ctx;
    ctx.analysis = &analysis;
    ctx.cfgs = &cfgs;
    
    auto graph = std::make_unique<CallGraph>();
    ctx.graph = graph.get();
    
    bool success = build_call_graph_internal(analysis, cfgs, ctx, *graph);
    if (success) {
        return CallGraphResult(std::move(graph));
    } else {
        return CallGraphResult("Call graph construction failed");
    }
}"""

content = content.replace(old, new)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done fixing build_call_graph')