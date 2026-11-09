with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    lines = f.readlines()

# Find the build_call_graph function and rewrite it
new_function = """CallGraphResult CallGraphBuilder::build_call_graph(const BinaryAnalysisResult& analysis,
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
}
"""

# Find the function and replace it
in_function = False
brace_count = 0
new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    if 'CallGraphResult CallGraphBuilder::build_call_graph(const BinaryAnalysisResult& analysis,' in line:
        # Skip until we find the end of this function
        new_lines.append(new_function)
        # Skip old function
        while i < len(lines):
            if lines[i].strip() == '}':
                brace_count += 1
                if brace_count >= 2:  # Function has 2 opening braces typically
                    i += 1
                    break
            i += 1
    else:
        new_lines.append(line)
        i += 1

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.writelines(new_lines)
print('Done')