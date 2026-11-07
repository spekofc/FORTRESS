// FORTRESS Binary Analyzer
// High-level interface for binary analysis

#pragma once

#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/error.h>
#include <filesystem>
#include <optional>
#include <functional>

namespace fortress {

// Analysis options
struct AnalysisOptions {
    // What to analyze
    bool analyze_sections = true;
    bool analyze_symbols = true;
    bool analyze_imports = true;
    bool analyze_exports = true;
    bool analyze_relocations = true;
    bool analyze_functions = true;
    bool analyze_disassembly = false; // Requires disassembly engine
    bool analyze_debug = true;
    bool analyze_resources = false;

    // Limits
    Size max_file_size = 500 * 1024 * 1024; // 500 MB
    Size max_disassembly_size = 1024 * 1024; // 1 MB
    Size max_functions = 100000;

    // Behavior
    bool follow_symlinks = true;
    bool strict_validation = false;
    bool compute_hashes = true;
    bool compute_entropy = true;

    // Disassembly (when enabled)
    Architecture force_architecture = Architecture::Unknown;
    Address disassembly_base = 0;
    Size disassembly_offset = 0;

    // Output
    bool include_raw_bytes = false;
    bool include_section_data = false;
};

// Analysis result callback for streaming
using AnalysisProgressCallback = std::function<void(const std::string& stage, float progress)>;

// Main analyzer class
class BinaryAnalyzer {
public:
    BinaryAnalyzer() = default;
    ~BinaryAnalyzer() = default;

    // Analyze a file
    Result<BinaryAnalysisResult> analyze(const std::filesystem::path& path, const AnalysisOptions& options = {});

    // Analyze from memory
    Result<BinaryAnalysisResult> analyze(std::span<const std::byte> data, const AnalysisOptions& options = {});

    // Analyze from file mapping (for large files)
    Result<BinaryAnalysisResult> analyze(const FileMapping& mapping, const AnalysisOptions& options = {});

    // Detect format without full analysis
    static Result<BinaryFormat> detect_format(const std::filesystem::path& path);
    static Result<BinaryFormat> detect_format(std::span<const std::byte> data);
    static Result<BinaryFormat> detect_format(const FileMapping& mapping);

    // Get supported formats
    static std::vector<BinaryFormat> supported_formats();

    // Get supported architectures
    static std::vector<Architecture> supported_architectures();

private:
    // Format-specific analysis
    Result<BinaryAnalysisResult> analyze_pe(const FileMapping& mapping, const AnalysisOptions& options);
    Result<BinaryAnalysisResult> analyze_elf(const FileMapping& mapping, const AnalysisOptions& options);
    Result<BinaryAnalysisResult> analyze_macho(const FileMapping& mapping, const AnalysisOptions& options);

    // Common post-processing
    void post_process(BinaryAnalysisResult& result, const AnalysisOptions& options);

    // Validation
    Result<void> validate_result(BinaryAnalysisResult& result);
};

} // namespace fortress