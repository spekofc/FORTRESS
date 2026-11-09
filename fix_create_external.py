with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

old = """uint32_t CallGraphBuilder::create_external_node(BuildContext& ctx, TypedAddress address, 
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
}"""

new = """uint32_t CallGraphBuilder::create_external_node(BuildContext& ctx, TypedAddress address, 
                                                  const std::string& name, const std::string& symbol_name,
                                                  bool is_import) {
    (void)symbol_name;
    
    auto it = ctx.graph->address_to_node.find(address.value());
    if (it != ctx.graph->address_to_node.end()) {
        return it->second;
    }
    
    uint32_t id = static_cast<uint32_t>(ctx.graph->nodes.size());
    CallGraphNode node(id, nullptr, name);
    node.address = address;
    node.is_external = true;
    node.is_import = is_import;
    node.is_entry_point = false;
    
    ctx.graph->nodes.push_back(std::move(node));
    ctx.graph->address_to_node[address.value()] = id;
    ctx.graph->name_to_node[name] = id;
    
    return id;
}"""

content = content.replace(old, new)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done')