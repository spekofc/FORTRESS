# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Core Infrastructure**: Error handling with `Error` class and `Result<T>` monad, file utilities with `FileMapping` RAII, comprehensive hashing (SHA256, SHA1, MD5, BLAKE2b, BLAKE3, CRC32, xxHash), entropy calculation, string utilities
- **Binary Parsers**: PE32/PE32+ parser (DOS header, COFF, Optional header, sections, imports, exports, relocations, debug, TLS), ELF32/ELF64 parser (headers, program/section headers, symtab/dynsym, dynamic section, relocations, notes, build ID), Mach-O 32/64-bit + Fat binary parser (load commands, segments, symtab, UUID, LC_MAIN)
- **Binary Analyzer**: Unified `BinaryAnalyzer` interface with automatic format detection, parser dispatch, post-processing, and validation
- **CLI**: `fortress analyze` command with options for sections, imports, exports, functions, symbols, relocations, debug info, JSON output
- **Build System**: CMake 3.25+ with Ninja, LLVM 18+ integration, GoogleTest via FetchContent, cross-platform support (Windows/Linux/macOS)
- **Tests**: Unit tests for core (error, Result, string utils, hashing, file utils), binary (format detection, data structures), PE, ELF, Mach-O parsers
- **Documentation**: Comprehensive README (English/Portuguese), PHASE2_AUDIT.md, PHASE2_COMPLETION_REPORT.md, PHASE2_FINAL_SUMMARY.md, PHASE3_PLAN.md

### Changed

- Refactored ELF parser to use `ctx.result->` consistently instead of `result->`
- Fixed Mach-O parser sign conversion warnings with explicit casts
- Updated CLI to use generated `fortress/version.h` instead of `fortress/core/version.h`

### Fixed

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

## [0.1.0] - 2024-11-07

### Added

- Initial repository structure with CMake, core infrastructure, binary parsers, analyzer, CLI, and tests
- Apache-2.0 license
- Basic CMake configuration with LLVM integration