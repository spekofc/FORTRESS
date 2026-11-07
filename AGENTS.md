# AGENTS.md — Persistent Instructions for OpenCode Agents

This file contains persistent instructions for AI agents working on the FORTRESS project. These instructions apply across all sessions and must be followed consistently.

---

## Project Identity

**Project**: FORTRESS — Advanced Open-Source Code Virtualization & Protection Framework
**Repository**: https://github.com/spekofc/FORTRESS
**Branch**: `main`
**License**: Apache-2.0

---

## Core Principles

### 1. Architecture First
- Every change must preserve or improve modularity
- Parsers (PE, ELF, Mach-O) are independent modules
- Core has zero dependencies on parsers
- Analyzer orchestrates through well-defined interfaces

### 2. Quality Over Speed
- No `--disable-warnings` or `-Wno-*` to hide issues
- All code must compile cleanly with `-Werror`
- Tests required for all new functionality
- No placeholder implementations in production code

### 3. Security by Design
- FORTRESS is for legitimate software protection only
- No malware evasion, sandbox bypass, or unauthorized cracking features
- Input validation and bounds checking mandatory
- Constant-time operations for sensitive paths

### 4. Reproducibility
- Deterministic builds when possible
- Version.h generated from CMake project version
- Tests must be deterministic and hermetic

---

## Git Protocol (MANDATORY)

### Before Any Commit

```bash
git status --short --branch
git diff --check
git diff --stat
```

### Commit Format (Conventional Commits)

```bash
git add <specific-files>
git diff --cached --check
git diff --cached --stat
git commit -m "type(scope): description"
```

### Push Protocol

```bash
git push origin main
# Verify:
git status -sb
git log --oneline -n 10
```

### PROHIBITED

| Command | Reason |
|---------|--------|
| `git push --force` | Rewrites history |
| `git push -f` | Same as above |
| `git reset --hard` | Destroys uncommitted work |
| `git checkout .` | Discards changes without review |
| `git clean -fd` | Deletes untracked files |
| Re-initializing repo | Unnecessary, breaks history |

### Conflict Resolution

If push rejected due to remote changes:
1. `git fetch origin`
2. `git log --oneline --left-right --graph HEAD...origin/main`
3. Investigate divergence
4. `git merge origin/main` or `git rebase origin/main`
5. **Never** `git push --force`

---

## Build & Test Protocol

### Before Any Push

```bash
# Configure (if needed)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON

# Build
cmake --build build --config Debug --parallel

# Test
ctest --test-dir build --output-on-failure

# Release validation
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
ctest --test-dir build-release --output-on-failure
```

### Windows (MSYS2/MinGW)

```bash
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_COMPILER=g++.exe -DCMAKE_C_COMPILER=gcc.exe
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

### Test Requirements

- All tests must pass in Debug and Release
- New code requires tests
- No flaky tests
- Tests must be hermetic (no external dependencies)

---

## Code Standards

### C++20 Guidelines

| Rule | Enforcement |
|------|-------------|
| C++20 features where beneficial | Required |
| RAII for all resources | Mandatory |
| `Result<T>` for fallible ops | Mandatory |
| No exceptions in library code | Mandatory |
| `const` correctness | Mandatory |
| `#pragma once` | Mandatory |
| `namespace fortress` | Mandatory |

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Types/Classes | PascalCase | `BinaryAnalysisResult` |
| Functions/Variables | snake_case | `parse_sections` |
| Constants | SCREAMING_SNAKE_CASE | `MAX_DIGEST_SIZE` |
| Private members | trailing `_` | `data_` |
| Enums | PascalCase | `Architecture::X64` |

### Includes

```cpp
// Header
#pragma once
#include <standard.h>
#include "internal.h"

namespace fortress {
// ...
} // namespace fortress
```

```cpp
// Source
#include <module/header.h>
#include <standard>

namespace fortress {
// Implementation
} // namespace fortress
```

---

## Error Handling

### Result<T> Monad

```cpp
// Success
return Result<T>::ok(value);
return Result<void>::ok();

// Error
return Result<T>::err(Error::error_code("message"));
return Result<T>::err(ErrorCode::Code, "message");

// Propagation
auto val = FORTRESS_TRY(fallible_operation());
```

### Error Codes

Use existing `ErrorCode` enum, add new ones only when semantically distinct.

### Context

```cpp
return error.with_context("parsing PE imports");
```

---

## Testing Standards

### Unit Tests

```cpp
TEST(ModuleName, TestCaseName) {
    // Arrange
    // Act
    // Assert
    EXPECT_EQ(actual, expected);
}
```

### Integration Tests

- Use real binary fixtures in `tests/fixtures/`
- Test all three formats (PE, ELF, Mach-O)
- Test malformed/truncated inputs
- Test edge cases (empty sections, overlapping, etc.)

### Test Organization

```
tests/
├── unit/
│   ├── test_core.cpp
│   ├── test_binary.cpp
│   ├── test_pe.cpp
│   ├── test_elf.cpp
│   └── test_macho.cpp
├── integration/
└── fixtures/
    ├── pe/
    ├── elf/
    └── macho/
```

---

## Documentation Standards

### Required Files

| File | Purpose |
|------|---------|
| `README.md` | English project overview |
| `README.pt-BR.md` | Portuguese translation |
| `CHANGELOG.md` | Keep a Changelog format |
| `CONTRIBUTING.md` | Contribution guidelines |
| `SECURITY.md` | Security policy |
| `AGENTS.md` | This file |

### Code Documentation

```cpp
/**
 * @brief Brief description
 * @param param Description
 * @return Description
 * @throws Error condition (if applicable)
 */
ReturnType function_name(ParamType param);
```

### Architecture Docs

- `docs/ARCHITECTURE.md` - System architecture
- `docs/PHASE2_AUDIT.md` - Phase 2 technical audit
- `docs/PHASE2_COMPLETION.md` - Phase 2 completion
- `docs/PHASE3_PLAN.md` - Phase 3 roadmap
- `docs/BUILDING.md` - Build instructions
- `docs/TESTING.md` - Testing guide
- `docs/CLI.md` - CLI reference

---

## Phase-Specific Instructions

### Phase 2 (Current): Binary Analyzer Core

**Focus**: Complete parser implementations, fix all compilation errors, achieve green build

**Blocking Issues**:
1. CLI version.h include path
2. ELF parser `ctx.ctx.result` → `ctx.result`
3. PE parser `rva_to_raw` return type
4. PE parser sign conversions
5. Analyzer `read_value` template
6. Hash.cpp sign conversions
7. CLI analyze_cmd missing `to_string` overloads

**Definition of Done**:
- `cmake --build build --config Debug` succeeds
- `cmake --build build --config Release` succeeds
- `ctest --test-dir build --output-on-failure` all pass
- `./build/fortress analyze <binary>` works

### Phase 3: Advanced Static Analysis

**Planned Modules**:
- CFG Builder (Basic Blocks, Control Flow Graph)
- Call Graph (Direct/Indirect calls)
- XREF Database (Cross-references)
- Function Refiner (Confidence levels)
- String Analysis
- Metrics & Coverage
- JSON Reporting

---

## Emergency Procedures

### Build Broken on Main

1. Revert offending commit: `git revert <commit-hash>`
2. Create fix branch
3. Fix and test
4. PR with `fix:` prefix

### Security Vulnerability Found

1. **DO NOT** create public issue
2. Email: security@fortress-project.org
3. Or create private GitHub Security Advisory
4. Follow SECURITY.md disclosure timeline

### Accidental Secret Commit

1. `git push origin --delete <branch>` if pushed
2. Rotate compromised credentials immediately
3. `git filter-repo` or BFG to purge history
4. Force push only with explicit authorization

---

## Quick Reference

| Task | Command |
|------|---------|
| Status check | `git status --short --branch` |
| Diff review | `git diff --stat && git diff` |
| Stage changes | `git add -p` (interactive) |
| Commit | `git commit -m "type(scope): msg"` |
| Push | `git push origin main` |
| Build debug | `cmake --build build --config Debug` |
| Build release | `cmake --build build-release --config Release` |
| Run tests | `ctest --test-dir build --output-on-failure` |
| View log | `git log --oneline -n 20` |

---

## Contact

- **Maintainer**: spekofc
- **Repository**: https://github.com/spekofc/FORTRESS
- **Security**: security@fortress-project.org

---

*This document is binding for all agents working on FORTRESS. Deviations require explicit authorization.*