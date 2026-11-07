# Contributing to FORTRESS

Thank you for your interest in contributing to FORTRESS! This document outlines the guidelines and processes for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:
- Be respectful and inclusive
- Focus on constructive feedback
- No harassment, discrimination, or offensive behavior
- Respect differing viewpoints and experiences

## How to Contribute

### Reporting Bugs

1. Check existing issues first to avoid duplicates
2. Create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, compiler, CMake version)
   - Minimal reproduction case if possible

### Suggesting Features

1. Open a feature request issue
2. Describe the problem it solves
3. Explain the proposed solution
4. Discuss alternatives considered
4. Be open to discussion and iteration

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/your-feature-name`
3. **Make your changes** following the guidelines below
4. **Run tests**: `cmake --build build --config Debug && ctest --test-dir build --output-on-failure`
5. **Commit** with Conventional Commits format
6. **Push** to your fork
7. **Open a Pull Request** against `main`

## Development Setup

### Prerequisites

- CMake 3.25+
- Ninja 1.11+
- C++20 compatible compiler (GCC 12+, Clang 15+, MSVC 19.3+)
- LLVM 18+ (for MC layer)
- nlohmann_json 3.10+

### Building

```bash
# Debug build with tests
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure

# Release build
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel
```

### Windows (MSYS2/MinGW)

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-cmake mingw-w64-ucrt-x86_64-ninja \
          mingw-w64-ucrt-x86_64-llvm mingw-w64-ucrt-x86_64-nlohmann-json

cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_COMPILER=g++.exe -DCMAKE_C_COMPILER=gcc.exe
cmake --build build --config Debug
```

## Code Style

### C++ Guidelines

- **C++20** features encouraged where beneficial
- **RAII** for resource management
- **Const correctness** - mark methods and parameters `const` when appropriate
- **Error handling** - Use `Result<T>` monad, avoid exceptions in library code
- **No raw owning pointers** - Use `std::unique_ptr`, `std::shared_ptr`, or containers
- **Include guards** - Use `#pragma once`
- **Namespace** - All code in `fortress` namespace, sub-namespaces for modules

### Formatting

- **Indentation**: 4 spaces, no tabs
- **Line length**: 120 characters max
- **Braces**: Allman style (braces on new lines)
- **Naming**:
  - Types: `PascalCase` (e.g., `BinaryAnalysisResult`)
  - Functions/variables: `snake_case` (e.g., `parse_sections`)
  - Constants: `SCREAMING_SNAKE_CASE` (e.g., `MAX_DIGEST_SIZE`)
  - Private members: trailing underscore (e.g., `data_`)

### Headers

```cpp
// Header comment required
// Module: Brief description
// File: filename.h

#pragma once

#include <dependency1.h>
#include <dependency2.h>

namespace fortress {

// Declarations...

} // namespace fortress
```

### Source Files

```cpp
// Module: Brief description

#include <module/header.h>
#include <standard_headers>

// Implementation...

} // namespace fortress
```

## Testing

### Requirements

- All new code must have tests
- Tests must pass in Debug and Release configurations
- Aim for >80% code coverage
- Integration tests for parsers with real binary fixtures

### Running Tests

```bash
# All tests
ctest --test-dir build --output-on-failure

# Specific test
./build/fortress_tests --gtest_filter=BinaryAnalyzerTest.DetectPE

# With coverage (Linux)
cmake -S . -B build-coverage -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage"
cmake --build build-coverage
ctest --test-dir build-coverage
lcov --capture --directory build-coverage --output-file coverage.info
genhtml coverage.info --output-directory coverage-html
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code restructuring |
| `perf` | Performance improvement |
| `test` | Adding tests |
| `chore` | Maintenance tasks |
| `build` | Build system changes |
| `ci` | CI configuration changes |

### Examples

```
feat(parser): add Mach-O fat binary support

fix(analyzer): handle truncated PE headers gracefully

docs: update README with Windows build instructions

refactor(core): simplify Result<T> construction

test(binary): add malformed ELF test fixtures
```

## Architecture Guidelines

### Modularity

- Each parser (PE, ELF, Mach-O) is independent
- Core infrastructure has no dependencies on parsers
- Analyzer orchestrates parsers through interface
- New formats should follow existing patterns

### Error Handling

- Use `Result<T>` for fallible operations
- Never throw exceptions across module boundaries
- Errors must have actionable messages
- Preserve error context with `with_context()`

### Performance

- Avoid unnecessary copies (use `std::span`, `std::string_view`)
- Prefer stack allocation for small objects
- Use `std::vector::reserve()` when size known
- Profile before optimizing

## Documentation

- Update README.md for user-facing changes
- Update CHANGELOG.md for each release
- Document public APIs in headers with Doxygen-style comments
- Keep PHASE2_AUDIT.md, PHASE2_COMPLETION_REPORT.md current

## Review Process

1. All PRs require at least one review
2. CI must pass (build + tests)
3. Code must follow style guidelines
4. Tests must cover new functionality
5. Documentation updated if needed

## Getting Help

- **Discord/Slack**: [Link if available]
- **GitHub Discussions**: For questions and design discussions
- **GitHub Issues**: For bugs and feature requests
- **Email**: [maintainer email if available]

---

Thank you for contributing to FORTRESS! Your efforts help make software protection more accessible and transparent.