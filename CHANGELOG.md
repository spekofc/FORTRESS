# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Analysis Data Model** (Phase 3 Milestone 1):
  - Unified normalized representation (`NormalizedAnalysisResult`) across PE, ELF, Mach-O
  - Strongly-typed address system: `TypedAddress` with `AddressSpace` (FileOffset, RVA, VA, SegmentVA)
  - Format-specific address converters: `PEAddressConverter`, `ELFAddressConverter`, `MachOAddressConverter`
  - Explicit conversion semantics with validation and overflow protection
  - Round-trip normalization: `normalize_analysis_result()` / `denormalize_analysis_result()`
  - Format-specific metadata preservation in `BinaryMetadata::FormatSpecificData`
  - 38 new unit tests covering all model components and converters
- **Binary Parsers**: PE32/PE32+ parser (DOS header, COFF, Optional header, sections, imports, exports, relocations, debug, TLS), ELF32/ELF64 parser (headers, program/section headers, symtab/dynsym, dynamic section, relocations, notes, build ID), Mach-O 32/64-bit + Fat binary parser (load commands, segments, symtab, UUID, LC_MAIN)
- **Binary Analyzer**: Unified `BinaryAnalyzer` interface with automatic format detection, parser dispatch, post-processing, and validation
- **CLI**: `fortress analyze` command with options for sections, imports, exports, functions, symbols, relocations, debug info, JSON output
- **Build System**: CMake 3.25+ with Ninja, LLVM 18+ integration, GoogleTest via FetchContent, cross-platform support (Windows/Linux/macOS)
- **Tests**: Unit tests for core (error, Result, string utils, hashing, file utils), binary (format detection, data structures), PE, ELF, Mach-O parsers, analysis model
- **Documentation**: Comprehensive README (English/Portuguese), PHASE2_AUDIT.md, PHASE2_COMPLETION_REPORT.md, PHASE2_FINAL_SUMMARY.md, PHASE3_PLAN.md

### Changed

- Refactored ELF parser to use `ctx.result->` consistently instead of `result->`
- Fixed Mach-O parser sign conversion warnings with explicit casts
- Updated CLI to use generated `fortress/version.h` instead of `fortress/core/version.h`
- Updated roadmap: Phase 2 complete, Phase 3 Milestone 1 (Analysis Data Model) complete
- Updated test status: All parser tests passing in Debug

### Fixed

- **PE Parser**: Entry point calculation (ImageBase + AddressOfEntryPoint RVA), section name trimming (8-byte fixed field with null padding)
- **ELF Parser**: Section name resolution via shstrtab (explicit byte arrays in test fixtures)
- **Mach-O Parser**: LC_MAIN command detection (masking LC_REQ_DYLD bit), entry point parsing (direct byte stream read), 32-bit test fixture buffer size, BinaryAnalyzer magic detection endianness
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

### Added

- **Hashing Module Overhaul**:
  - SHA-384 and SHA-512 now use OpenSSL EVP (`EVP_sha384()`, `EVP_sha512()`) — FIPS 180-4 compliant
  - SHA3-256, SHA3-512, BLAKE2b use OpenSSL EVP when available; return explicit `UnsupportedOperation` error otherwise
  - BLAKE3 returns explicit `UnsupportedOperation` error (not implemented)
  - Removed all manual SHA-384/SHA-512 implementations (incomplete round constants)
- **Reference Test Vectors Added**:
  - SHA3-256: "hello world" = `644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938`
  - SHA3-512: "hello world" = `840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a`
  - BLAKE2b: "hello world" = `021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0`
  - CRC32C: "hello world" = `0xC99465AA`, "123456789" = `0xE3069283`
  - xxHash64: "hello world" = `0xBB75740C8181914A`
- **Test Coverage**:
  - MD5 RFC 1321: all 7 test vectors passing
  - SHA-384, SHA-512: FIPS 180-4 test vectors from OpenSSL default provider
  - CRC32: canonical vector `0xCBF43926` for "123456789"
  - CRC32: "hello world" = `0x0D4A1185`
  - CRC32C: canonical vectors for "hello world" and "123456789"
  - xxHash64: reference vector for "hello world"
  - Unsupported algorithms (SHA-3, BLAKE2b, BLAKE3): return explicit `UnsupportedOperation` errors
- **Reference Implementations**: CRC32, CRC32C, xxHash64 (safe unaligned access via `memcpy`), Entropy
- **Error Handling**: OpenSSL EVP error checking in `EVPHashContext`
- **Tests**: All 12 CoreHash tests passing (Debug & Release)

### Changed

- **Build System**:
  - Removed global `-Wno-sign-conversion`; added targeted `-Wno-sign-conversion` only for third-party code (googletest)
  - Fixed sign-conversion warnings in `hash.cpp`, `test_core.cpp`, `elf_parser.cpp`
  - Removed global `-Wno-conversion` and `-Wno-sign-compare` suppressions
- **Tests**:
  - Updated SHA-384/SHA-512 test vectors to match OpenSSL default provider (FIPS 180-4)
  - Fixed CRC32 test vector for "hello world" (0x0D4A1185)
  - Added reference vectors for CRC32C and xxHash64
  - Fixed CoreError.Context test (message vs context distinction)
  - Added UnsupportedAlgorithms test for SHA3-256, SHA3-512, BLAKE2b, BLAKE3
- **Code Cleanup**:
  - Removed manual SHA-384/SHA-512 implementations (incomplete round constants)
  - Removed SHA3Context, BLAKE3Context, BLAKE2bContext placeholder classes
  - Fixed xxHash64 unaligned access with `memcpy`-based reads
  - Fixed CRC32 test vector for "hello world" (0x0D4A1185)
  - Fixed CRC32C reference vector for "123456789"
- **Documentation**:
  - Updated README.md: Hashing status table, test results, BLAKE3 marked as "Not implemented (planned)"
  - Updated README.pt-BR.md: same updates in Portuguese
  - Updated README example output with correct SHA-384/SHA-512 vectors
  - Updated CHANGELOG.md with detailed v0.2.0 entry
  - Removed BLAKE3 from CLI example output

### Fixed

- ELF parser `std::byte` to `uint16_t` conversion in `bswap16` with explicit `static_cast`
- Mach-O `cputype_to_architecture` now checks full cputype first (including 64-bit flag)
- CoreError.Context test: context message stored in `context_` not `message_`
- Fixed sign-conversion warnings in `hash.cpp` and `test_core.cpp` (loop variable types)
- Fixed `xxHash64` unaligned access with `memcpy`-based reads (`XXH_read64`, `XXH_read32`)
- Fixed `format_digest` char to `unsigned char` cast for `std::toupper`
- Fixed CRC32 test vector for "hello world" (0x0D4A1185, not 0xD4A1185E)
- Fixed xxHash64 reference vector for "hello world" (0xbb75740c8181914a)
- Fixed ELF test buffer sizes (increased from 1024 to 0x5000 bytes)
- **PE Parser**: entry point calculation (returns 4096 vs 0x00401000), section name includes null padding
- **ELF Parser**: SectionPermissions test fails (section name matching)
- **Mach-O Parser**: entry point parsing (returns 0 instead of 0x100001000)

### Security

- Added constant-time digest comparison in `Digest::constant_time_equal()`
- Removed `NOMINMAX` redefinition in file_utils.cpp
- FileMapping RAII ensures proper handle cleanup on Windows and Unix

### Documentation

- Updated README.md: Hashing status table, test results, BLAKE3 marked as "Not implemented (planned)"
- Updated README.pt-BR.md: same updates in Portuguese
- Updated README example output with correct SHA-384/SHA-512 vectors
- Updated CHANGELOG.md with detailed v0.2.0 entry
- Removed BLAKE3 from CLI example output
- Updated roadmap: Phase 2 remains In Progress (parser crashes need fixes)

---

## [0.1.0] - 2024-11-07

### Added

- Initial repository structure with CMake, core infrastructure, binary parsers, analyzer, CLI, and tests
- Apache-2.0 license
- Basic CMake configuration with LLVM integration