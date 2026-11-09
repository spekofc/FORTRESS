with open('docs/PHASE3_PLAN.md', 'r') as f:
    content = f.read()

old = "**All tests passing in Debug configuration.**"
new = "**153/162 tests passing in Debug configuration** (94.4% - 9 CallGraph tests failing due to recursion/merge edge cases; core infrastructure solid)."

content = content.replace(old, new)

with open('docs/PHASE3_PLAN.md', 'w') as f:
    f.write(content)
print('Done')