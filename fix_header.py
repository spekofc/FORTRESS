with open('include/fortress/binary/analysis/call_graph.h', 'r') as f:
    content = f.read()

old = """    CallGraphResult build_call_graph_internal(const BinaryAnalysisResult& analysis,
                                               const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs);"""

new = """    bool build_call_graph_internal(const BinaryAnalysisResult& analysis,
                                               const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs,
                                               BuildContext& ctx,
                                               CallGraph& graph);"""

content = content.replace(old, new)

with open('include/fortress/binary/analysis/call_graph.h', 'w') as f:
    f.write(content)
print('Done fixing header')