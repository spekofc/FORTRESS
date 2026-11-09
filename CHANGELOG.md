# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CFG Builder** (Phase 3 Milestone 2):
  - Control Flow Graph construction for binary analysis
  - Leader identification for basic block boundaries
  - Basic block construction from decoded instructions
  - Control flow edges: fallthrough, conditional/unconditional branches, calls, returns
  - Indirect branch/call handling (unresolved tracking)
  - Loop detection using Havlak's algorithm
  - Dominator tree computation (iterative data flow analysis)
  - Dominance frontier calculation
  - Unreachable code detection
  - CFG validation (structure integrity, edge consistency)
  - JSON serialization of CFG structure
  - GraphViz DOT export for visualization
  - 15 unit tests covering linear functions, conditionals, loops, calls, indirect branches, multiple returns, empty functions
- **Analysis Data Model** (Phase 3 Milestone 1):
  - Unified normalized representation (`NormalizedAnalysisResult`) across PE, ELF, Mach-O
  - Strongly-typed address system: `TypedAddress` with `AddressSpace` (FileOffset, RVA, VA, SegmentVA)
  - Format-specific address converters: `PEAddressConverter`, `ELFAddressConverter`, `MachOAddressConverter`
  - Explicit conversion semantics with validation and overflow protection
  - Round-trip normalization: `normalize_analysis_result()` / `denormalize_analysis_result()`
  - Format-specific metadata preservation in `BinaryMetadata::FormatSpecificData`
  - 38 new unit tests covering all model components and converters
  - Ambiguous conversion detection for overlapping sections/segments
  - SegmentVA round-trip with segment index encoding (Mach-O)
  - JSON escaping for safe serialization with nlohmann_json
- **Binary Parsers**: PE32/PE32+ parser (DOS header, COFF, Optional header, sections, imports, exports, relocations, debug, TLS), ELF32/ELF64 parser (headers, program/section headers, symtab/dynsym, dynamic section, relocations, notes, build ID), Mach-O 32/64-bit + Fat binary parser (load commands, segments, symtab, UUID, LC_MAIN)
- **Binary Analyzer**: Unified `BinaryAnalyzer` interface with automatic format detection, parser dispatch, post-processing, and validation
- **CLI**: `fortress analyze` command with options for sections, imports, exports, functions, symbols, relocations, debug info, JSON output
- **Build System**: CMake 3.25+ with Ninja, LLVM 18+ integration, GoogleTest via FetchContent, cross-platform support (Windows/Linux/macOS)
- **Tests**: Unit tests for core (error, Result, string utils, hashing, file utils), binary (format detection, data structures), PE, ELF, Mach-O parsers, analysis model, CFG builder (138/138 passing)
- **Documentation**: Comprehensive README (English/Portuguese), PHASE2_AUDIT.md, PHASE2_COMPLETION_REPORT.md, PHASE2_FINAL_SUMMARY.md, PHASE3_PLAN.md

### Changed

- Refactored ELF parser to use `ctx.result->` consistently instead of `result->`
- Fixed Mach-O parser sign conversion warnings with explicit casts
- Updated CLI to use generated `fortress/version.h` instead of `fortress/core/version.h`
- Updated roadmap: Phase 2 complete, Phase 3 Milestone 1 (Analysis Data Model) complete
- Updated test status: All parser tests passing in Debug (123/123 tests passing)

### Fixed

- **PE Parser**: Entry point calculation (ImageBase + AddressOfEntryPoint RVA), section name trimming (8-byte fixed field with null padding), ambiguous conversion detection for overlapping sections
- **ELF Parser**: Section name resolution via shstrtab (explicit byte arrays in test fixtures), ambiguous conversion detection for overlapping segments/sections, p_filesz vs p_memsz distinction enforced
- **Mach-O Parser**: LC_MAIN command detection (masking LC_REQ_DYLD bit), entry point parsing (direct byte stream read), 32-bit test fixture buffer size, BinaryAnalyzer magic detection endianness, SegmentVA round-trip with segment index encoding, ambiguous conversion detection for overlapping segments
- **Address Model**: TypedAddress SegmentVA encoding with segment index (16 bits) + offset (48 bits), validation and overflow protection, deprecated legacy factory
- **JSON**: Proper string escaping for quotes, backslashes, control characters, Unicode
- ELF parser `std::byte` to `uint8_t` conversions with explicit casts
- ELF parser `SHF_READ` → `SHF_ALLOC` correction
- Mach-O parser sign conversion warnings with explicit casts
- Hash.cpp sign conversion warnings in entropy calculation, constant_time_equal, format_digest
- Analyzer `read_value` template with proper `const void*` cast
- CLI version.h include path using `${CMAKE_BINARY_DIR}/include`
- Mach-O parser unused parameter warnings with `[[maybe_unused]]`
- ELF parser unused variable warnings with `[[maybe_unused]]`
- ELF parser unused functions marked with `[[maybe_unused]]`

### Security

- Added constant-time digest comparison in `Digest::constant_time_equal()`
- Removed `NOMINMAX` redefinition in file_utils.cpp
- FileMapping RAII ensures proper handle cleanup on Windows and Unix

### Documentation

- Added comprehensive README.md (English) and README.pt-BR.md (Portuguese)
- Created PHASE2_AUDIT.md with complete technical audit
- Created PHASE2_COMPLETION_REPORT.md and PHASE2_FINAL_SUMMARY.md
- Added PHASE3_PLAN.md with roadmap for Phase 3
- Added LICENSE (Apache-2.0)

---

## [0.2.0] - 2025-11-08