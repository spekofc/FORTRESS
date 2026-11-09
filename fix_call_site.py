with open('src/binary/analysis/call_graph.cpp', 'r') as f:
    content = f.read()

# Fix the call site in build_call_graph
old = """    bool success = build_call_graph_internal(analysis, cfgs, ctx, *graph);"""

new = """    bool success = build_call_graph_internal(analysis, cfgs, ctx, *graph);"""

content = content.replace(old, new)

# Fix the call in build_call_graph (line 555)
old_call = """    CallGraphResult result = build_call_graph_internal(analysis, cfgs, ctx);"""

new_call = """    bool success = build_call_graph_internal(analysis, cfgs, ctx, *graph);"""

content = content.replace(old_call, new_call)

with open('src/binary/analysis/call_graph.cpp', 'w') as f:
    f.write(content)
print('Done')