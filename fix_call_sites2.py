with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

# Fix the call sites to pass the is_import parameter
content = content.replace(
    'dst_id = create_external_node(ctx, target.address, "unknown_" + \n                    std::to_string(target.address.value()), target.symbol_name);',
    'dst_id = create_external_node(ctx, target.address, "unknown_" + \n                    std::to_string(target.address.value()), target.symbol_name, target.is_import);'
)

content = content.replace(
    'dst_id = create_external_node(ctx, target.address, "unknown_" + \n                std::to_string(target.address.value()), target.symbol_name);',
    'dst_id = create_external_node(ctx, target.address, "unknown_" + \n                std::to_string(target.address.value()), target.symbol_name, target.is_import);'
)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done')