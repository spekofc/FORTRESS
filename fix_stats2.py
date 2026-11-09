with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

# Update the statistics to count Import edges as direct calls
old = """    for (const auto& edge : edges) {
        switch (edge.type) {
            case CallEdgeType::Direct: statistics.direct_calls++; break;
            case CallEdgeType::Indirect: statistics.indirect_calls++; break;
            case CallEdgeType::TailCall: statistics.tail_calls++; break;
            default: break;
        }
        
        // Count import functions: direct calls to import nodes
        if (edge.type == CallEdgeType::Direct && edge.target_node_id < nodes.size() && nodes[edge.target_node_id].is_import) {
            statistics.import_functions++;
        }"""

new = """    for (const auto& edge : edges) {
        switch (edge.type) {
            case CallEdgeType::Direct: statistics.direct_calls++; break;
            case CallEdgeType::Indirect: statistics.indirect_calls++; break;
            case CallEdgeType::Import: 
                statistics.direct_calls++;  // Import calls are also direct calls
                statistics.import_functions++; 
                break;
            case CallEdgeType::TailCall: statistics.tail_calls++; break;
            default: break;
        }"""

content = content.replace(old, new)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done')