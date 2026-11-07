// FORTRESS Binary Analyzer Implementation

#include <fortress/binary/analysis/analyzer.h>
#include <fortress/binary/formats/pe/pe_parser.h>
#include <fortress/binary/formats/elf/elf_parser.h>
#include <fortress/binary/formats/macho/macho_parser.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/hash.h>
#include <fortress/core/string_utils.h>
#include <fstream>

namespace fortress {

// Helper: read typed value from buffer
template<typename T>
static T read_value(const std::byte* ptr) {
    T val;
    std::memcpy(&val, ptr, sizeof(T));
    return val;
}

Result<BinaryFormat> BinaryAnalyzer::detect_format(const std::filesystem::path& path) {
    auto data_result = file_utils::read_file(path, 0, 16);
    if (!data_result) return data_result.error();
    return detect_format(data_result.value());
}

Result<BinaryFormat> BinaryAnalyzer::detect_format(std::span<const std::byte> data) {
    if (data.size() < 4) return Error::truncated("Data too small for format detection");

    uint32_t magic = read_value<uint32_t>(data.data());

    // PE: MZ signature at offset 0, PE signature at e_lfanew
    if (magic == 0x5A4D) { // "MZ"
        if (data.size() >= 0x40) {
            uint32_t pe_offset = read_value<uint32_t>(data.data() + 0x3C);
            if (pe_offset + 4 <= data.size()) {
                uint32_t pe_sig = read_value<uint32_t>(data.data() + pe_offset);
                if (pe_sig == 0x00004550) { // "PE\0\0"
                    return BinaryFormat::PE;
                }
            }
        }
        return BinaryFormat::PE; // Likely PE
    }

    // ELF: 0x7F ELF
    if (magic == 0x464C457F) {
        return BinaryFormat::ELF;
    }

    // Mach-O: FEEDFACE/FEEDFACF/CAFEBABE
    if (magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE || magic == 0xCFFACFED) {
        return BinaryFormat::MachO;
    }
    if (magic == 0xCAFEBABE || magic == 0xBEBAFECA) {
        return BinaryFormat::MachO; // Fat binary
    }

    return Error::invalid_format("Unknown binary format");
}

std::vector<BinaryFormat> BinaryAnalyzer::supported_formats() {
    return {BinaryFormat::PE, BinaryFormat::ELF, BinaryFormat::MachO};
}

std::vector<Architecture> BinaryAnalyzer::supported_architectures() {
    return {
        Architecture::X86, Architecture::X64,
        Architecture::ARM32, Architecture::ARM64,
        Architecture::MIPS32, Architecture::MIPS64,
        Architecture::PPC32, Architecture::PPC64,
        Architecture::RISCV32, Architecture::RISCV64
    };
}

Result<BinaryAnalysisResult> BinaryAnalyzer::analyze(const std::filesystem::path& path, const AnalysisOptions& options) {
    // Check file size
    auto size_result = file_utils::file_size(path);
    if (!size_result) return size_result.error();

    if (size_result.value() > options.max_file_size) {
        return Error::unsupported_operation("File exceeds maximum size: " + std::to_string(size_result.value()));
    }

    // Map file for efficient access
    auto mapping_result = file_utils::map_file_read_only(path);
    if (!mapping_result) return mapping_result.error();

    BinaryAnalysisResult result;
    result.file_path = path;

    return analyze(mapping_result.value(), options);
}

Result<BinaryAnalysisResult> BinaryAnalyzer::analyze(std::span<const std::byte> data, const AnalysisOptions& options) {
    // Detect format
    auto format_result = detect_format(data);
    if (!format_result) return format_result.error();

    // For memory data, we'd need a different approach - for now delegate to file path
    return Error::unsupported_operation("Memory buffer analysis not yet implemented");
}

Result<BinaryAnalysisResult> BinaryAnalyzer::analyze(const FileMapping& mapping, const AnalysisOptions& options) {
    BinaryAnalysisResult result;
    result.file_path = mapping.path();

    // Detect format from mapped data
    auto format_result = detect_format(mapping.data().first(16));
    if (!format_result) return format_result.error();

    BinaryFormat format = format_result.value();

    Result<BinaryAnalysisResult> analysis_result;
    switch (format) {
        case BinaryFormat::PE:
            analysis_result = analyze_pe(mapping, options);
            break;
        case BinaryFormat::ELF:
            analysis_result = analyze_elf(mapping, options);
            break;
        case BinaryFormat::MachO:
            analysis_result = analyze_macho(mapping, options);
            break;
        default:
            return Error::unsupported_operation("Format not supported: " + to_string(format));
    }

    if (!analysis_result) return analysis_result.error();

    result = std::move(analysis_result.value());
    result.file_path = mapping.path();

    // Post-process
    post_process(result, options);

    // Validate
    auto val_result = validate_result(result);
    if (!val_result) {
        result.errors.push_back("Validation failed: " + val_result.error().to_string());
    }

    return result;
}

Result<BinaryAnalysisResult> BinaryAnalyzer::analyze_pe(const FileMapping& mapping, const AnalysisOptions& /*options*/) {
    pe::PEParser parser;
    auto result = parser.parse(mapping);
    return result;
}

Result<BinaryAnalysisResult> BinaryAnalyzer::analyze_elf(const FileMapping& mapping, const AnalysisOptions& /*options*/) {
    elf::ELFParser parser;
    auto result = parser.parse(mapping);
    return result;
}

Result<BinaryAnalysisResult> BinaryAnalyzer::analyze_macho(const FileMapping& mapping, const AnalysisOptions& /*options*/) {
    macho::MachOParser parser;
    auto result = parser.parse(mapping);
    return result;
}

void BinaryAnalyzer::post_process(BinaryAnalysisResult& result, const AnalysisOptions& options) {
    // Sort functions by address
    std::sort(result.functions.begin(), result.functions.end(),
        [](const FunctionInfo& a, const FunctionInfo& b) { return a.address < b.address; });

    // Remove duplicate functions (same address)
    auto it = std::unique(result.functions.begin(), result.functions.end(),
        [](const FunctionInfo& a, const FunctionInfo& b) { return a.address == b.address; });
    result.functions.erase(it, result.functions.end());

    // Limit functions
    if (result.functions.size() > options.max_functions) {
        result.warnings.push_back("Function count limited to " + std::to_string(options.max_functions));
        result.functions.resize(options.max_functions);
    }

    // Add format-specific limitations
    if (result.format == BinaryFormat::PE) {
        result.limitations.push_back("PE: Import/export parsing may be incomplete for complex binaries");
        result.limitations.push_back("PE: .NET metadata not parsed");
    } else if (result.format == BinaryFormat::ELF) {
        result.limitations.push_back("ELF: Version symbols (VERSYM) not fully parsed");
        result.limitations.push_back("ELF: GNU hash table not parsed");
    } else if (result.format == BinaryFormat::MachO) {
        result.limitations.push_back("Mach-O: Chained fixups not parsed");
        result.limitations.push_back("Mach-O: DYLD exports trie not parsed");
    }
}

Result<void> BinaryAnalyzer::validate_result(BinaryAnalysisResult& result) {
    if (!result.valid_format) {
        return Error::invalid_format("Format not validated");
    }

    if (result.entry_point == 0 && result.format != BinaryFormat::ELF) {
        result.warnings.push_back("Entry point not found");
    }

    if (result.sections.empty()) {
        result.warnings.push_back("No sections found");
    }

    if (result.functions.empty()) {
        result.warnings.push_back("No functions discovered");
    }

    // Check for overlapping sections
    for (size_t i = 0; i < result.sections.size(); ++i) {
        const auto& a = result.sections[i];
        if (a.raw_size == 0 || a.file_offset == INVALID_OFFSET) continue;

        for (size_t j = i + 1; j < result.sections.size(); ++j) {
            const auto& b = result.sections[j];
            if (b.raw_size == 0 || b.file_offset == INVALID_OFFSET) continue;

            if (a.file_offset < b.file_offset + b.raw_size &&
                b.file_offset < a.file_offset + a.raw_size) {
                result.overlapping_sections = true;
                result.warnings.push_back("Overlapping sections: " + a.name + " and " + b.name);
            }
        }
    }

    return Result<void>::ok();
}

} // namespace fortress