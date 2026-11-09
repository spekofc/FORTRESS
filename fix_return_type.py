with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

# Fix the return type
content = content.replace(
    "CallGraphResult CallGraphBuilder::build_call_graph_internal(const BinaryAnalysisResult& analysis,",
    "bool CallGraphBuilder::build_call_graph_internal(const BinaryAnalysisResult& analysis,"
)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done')