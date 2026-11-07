# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in FORTRESS, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, email us at: **security@fortress-project.org** (or create a private GitHub Security Advisory)

Include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Affected versions
- Any known mitigations or workarounds
- Your contact information for follow-up

### What to Expect

1. **Acknowledgment**: Within 48 hours
2. **Assessment**: Within 7 days
3. **Fix Timeline**: Communicated after assessment
4. **Disclosure**: Coordinated disclosure after fix is available

### Scope

This policy covers:
- FORTRESS core library (`src/core/`, `src/binary/`, `src/cli/`)
- Binary parsers (PE, ELF, Mach-O)
- Binary analyzer and related components
- CLI tool (`fortress`)

Out of scope:
- Third-party dependencies (LLVM, nlohmann_json, etc.)
- Operating system vulnerabilities
- Issues in user applications using FORTRESS

## Security Considerations

### Intended Use

FORTRESS is designed for **legitimate software protection**:
- Protecting intellectual property in commercial applications
- Authorized security research and vulnerability analysis
- Educational purposes in compiler design and binary analysis
- Authorized software auditing and compliance verification

### Prohibited Uses

FORTRESS must NOT be used for:
- Malware obfuscation or evasion
- Antivirus/EDR evasion
- Sandbox bypass or anti-analysis for malicious purposes
- Unauthorized software cracking
- License bypass or piracy
- Any illegal activity

### Hardening Measures

FORTRESS implements several security hardening measures:

| Measure | Description |
|---------|-------------|
| Constant-time comparison | `Digest::constant_time_equal()` for timing-safe digest comparison |
| RAII resource management | `FileMapping` ensures proper handle cleanup |
| Input validation | All parsers validate bounds, offsets, and sizes |
| No code execution | Static analysis only - no binary execution |
| Error handling | `Result<T>` monad prevents exception-based vulnerabilities |
| Constant-time operations | Critical paths avoid data-dependent branches |

### Dependency Security

We regularly audit dependencies:
- **LLVM**: Official releases from llvm.org
- **nlohmann_json**: Header-only, widely audited
- **GoogleTest**: Official Google releases
- **Standard library**: C++20 standard library

Vulnerabilities in dependencies are tracked via:
- GitHub Dependabot alerts
- CVE monitoring
- Regular dependency updates

## Disclosure Timeline

| Phase | Timeline |
|-------|----------|
| Report received | Day 0 |
| Acknowledgment | Day 0-2 |
| Initial assessment | Day 1-7 |
| Fix development | Day 7-30 (varies by severity) |
| Testing & validation | 1-2 weeks |
| Coordinated disclosure | After fix release |
| Public advisory | After users have time to update |

## Security Contacts

- **Primary**: security@fortress-project.org
- **Backup**: GitHub Security Advisories

## Hall of Fame

We recognize responsible disclosure:

*No vulnerabilities reported yet - be the first!*

---

## Legal Disclaimer

FORTRESS is provided "AS IS" without warranty. The authors are not liable for any misuse or damages arising from the use of this software. Users are responsible for compliance with applicable laws and regulations.

By using FORTRESS, you agree to use it only for legitimate, authorized purposes.