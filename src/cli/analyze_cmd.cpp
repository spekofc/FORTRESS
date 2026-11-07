// FORTRESS CLI - Analyze Command

#include <fortress/binary/analysis/analyzer.h>
#include <fortress/binary/analysis/binary_info.h>
#include <fortress/core/error.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/string_utils.h>
#include <fortress/version.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace fortress::cli {

struct AnalyzeOptions {
    std::filesystem::path input_file;
    std::filesystem::path output_file;
    bool json_output = false;
    bool show_sections = false;
    bool show_imports = false;
    bool show_exports = false;
    bool show_functions = false;
    bool show_symbols = false;
    bool show_relocations = false;
    bool show_disassembly = false;
    bool show_debug = false;
    bool verbose = false;
    bool quiet = false;
    std::string filter_section;
    std::string filter_function;
    Address disasm_address = 0;
    Size disasm_size = 0;
};

static void print_analyze_help() {
    std::cout << "Usage: fortress analyze -i <input> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --input <file>          Input binary file (required)\n";
    std::cout << "  -o, --output <file>         Output file for JSON report\n";
    std::cout << "  --json                      Output JSON to stdout\n";
    std::cout << "  --sections                  Show section details\n";
    std::cout << "  --imports                   Show imported functions\n";
    std::cout << "  --exports                   Show exported functions\n";
    std::cout << "  --functions                 Show discovered functions\n";
    std::cout << "  --symbols                   Show all symbols\n";
    std::cout << "  --relocations               Show relocations\n";
    std::cout << "  --disassembly               Show disassembly (experimental)\n";
    std::cout << "  --debug                     Show debug information\n";
    std::cout << "  -v, --verbose               Verbose output\n";
    std::cout << "  -q, --quiet                 Minimal output\n";
    std::cout << "  --filter-section <name>     Filter sections by name\n";
    std::cout << "  --filter-function <name>    Filter functions by name\n";
    std::cout << "  --disasm-addr <addr>        Disassembly start address\n";
    std::cout << "  --disasm-size <size>        Disassembly size\n";
    std::cout << "  -h, --help                  Show this help\n";
}

static Result<AnalyzeOptions> parse_args(const std::vector<std::string>& args) {
    AnalyzeOptions opts;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];

        if (arg == "-h" || arg == "--help") {
            print_analyze_help();
            std::exit(0);
        } else if (arg == "-i" || arg == "--input") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--input requires a value");
            opts.input_file = args[++i];
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--output requires a value");
            opts.output_file = args[++i];
        } else if (arg == "--json") {
            opts.json_output = true;
        } else if (arg == "--sections") {
            opts.show_sections = true;
        } else if (arg == "--imports") {
            opts.show_imports = true;
        } else if (arg == "--exports") {
            opts.show_exports = true;
        } else if (arg == "--functions") {
            opts.show_functions = true;
        } else if (arg == "--symbols") {
            opts.show_symbols = true;
        } else if (arg == "--relocations") {
            opts.show_relocations = true;
        } else if (arg == "--disassembly") {
            opts.show_disassembly = true;
        } else if (arg == "--debug") {
            opts.show_debug = true;
        } else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-q" || arg == "--quiet") {
            opts.quiet = true;
        } else if (arg == "--filter-section") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--filter-section requires a value");
            opts.filter_section = args[++i];
        } else if (arg == "--filter-function") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--filter-function requires a value");
            opts.filter_function = args[++i];
        } else if (arg == "--disasm-addr") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--disasm-addr requires a value");
            opts.disasm_address = std::stoull(args[++i], nullptr, 0);
        } else if (arg == "--disasm-size") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--disasm-size requires a value");
            opts.disasm_size = std::stoull(args[++i], nullptr, 0);
        } else if (!arg.empty() && arg[0] == '-') {
            return Error::invalid_argument("Unknown option: " + arg);
        } else if (opts.input_file.empty()) {
            opts.input_file = arg;
        }
    }

    if (opts.input_file.empty()) {
        return Error::invalid_argument("Input file required. Use -i <file> or provide as positional argument.");
    }

    return opts;
}

static void print_section(const BinaryAnalysisResult& result, const AnalyzeOptions& opts) {
    std::cout << "\n=== Sections (" << result.sections.size() << ") ===\n";
    std::cout << std::left << std::setw(20) << "Name"
              << std::setw(18) << "Virtual Addr"
              << std::setw(12) << "VSize"
              << std::setw(12) << "RawSize"
              << std::setw(10) << "Offset"
              << std::setw(12) << "Perms"
              << std::setw(8) << "Entropy"
              << "Characteristics\n";
    std::cout << std::string(120, '-') << "\n";

    for (const auto& sec : result.sections) {
        if (!opts.filter_section.empty() && sec.name.find(opts.filter_section) == std::string::npos) continue;

        std::string perms;
        if (sec.is_readable()) perms += "R";
        if (sec.is_writable()) perms += "W";
        if (sec.is_executable()) perms += "X";

        std::cout << std::left << std::setw(20) << sec.name.substr(0, 19)
                  << std::setw(18) << format_address(sec.virtual_address)
                  << std::setw(12) << format_size(sec.virtual_size)
                  << std::setw(12) << format_size(sec.raw_size)
                  << std::setw(10) << (sec.file_offset == INVALID_OFFSET ? "-" : "0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&sec.file_offset), 8)))
                  << std::setw(12) << perms
                  << std::setw(8) << std::fixed << std::setprecision(2) << sec.entropy
                  << sec.characteristics << "\n";
    }
}

static void print_imports(const BinaryAnalysisResult& result, const AnalyzeOptions& opts) {
    std::cout << "\n=== Imports ===\n";
    for (const auto& imp : result.imports) {
        std::cout << "\n  Library: " << imp.library_name;
        if (imp.is_delay_load) std::cout << " (delay-load)";
        std::cout << "\n";
        for (const auto& sym : imp.functions) {
            if (!opts.filter_function.empty() && sym.name.find(opts.filter_function) == std::string::npos) continue;
            std::cout << "    " << format_address(sym.address) << "  " << sym.name;
            if (sym.import_ordinal) std::cout << " [ordinal " << sym.import_ordinal << "]";
            std::cout << "\n";
        }
    }
}

static void print_exports(const BinaryAnalysisResult& result, const AnalyzeOptions& opts) {
    std::cout << "\n=== Exports ===\n";
    for (const auto& exp : result.exports) {
        std::cout << "\n  Library: " << exp.library_name << "\n";
        for (const auto& sym : exp.functions) {
            if (!opts.filter_function.empty() && sym.name.find(opts.filter_function) == std::string::npos) continue;
            std::cout << "    " << format_address(sym.address) << "  " << sym.name << "\n";
        }
    }
}

static void print_functions(const BinaryAnalysisResult& result, const AnalyzeOptions& opts) {
    std::cout << "\n=== Functions (" << result.functions.size() << ") ===\n";
    std::cout << std::left << std::setw(18) << "Address"
              << std::setw(10) << "Size"
              << std::setw(14) << "Confidence"
              << std::setw(16) << "Source"
              << std::setw(8) << "Flags"
              << "Name\n";
    std::cout << std::string(120, '-') << "\n";

    for (const auto& fn : result.functions) {
        if (!opts.filter_function.empty() && fn.name.find(opts.filter_function) == std::string::npos) continue;

        std::string flags;
        if (fn.has_symbol) flags += "S";
        if (fn.is_exported) flags += "E";
        if (fn.is_imported) flags += "I";
        if (fn.is_thunk) flags += "T";

        std::cout << std::left << std::setw(18) << format_address(fn.address)
                  << std::setw(10) << (fn.size ? format_size(fn.size) : "-")
                  << std::setw(14) << to_string(fn.confidence)
                  << std::setw(16) << to_string(fn.source)
                  << std::setw(8) << flags
                  << fn.name << "\n";
    }
}

static void print_symbols(const BinaryAnalysisResult& result, const AnalyzeOptions& opts) {
    std::cout << "\n=== Symbols (" << result.symbols.size() << ") ===\n";
    std::cout << std::left << std::setw(18) << "Address"
              << std::setw(10) << "Size"
              << std::setw(10) << "Type"
              << std::setw(10) << "Binding"
              << std::setw(10) << "Vis"
              << "Name\n";
    std::cout << std::string(120, '-') << "\n";

    for (const auto& sym : result.symbols) {
        if (!opts.filter_function.empty() && sym.name.find(opts.filter_function) == std::string::npos) continue;

        std::string type_str = to_string(sym.type);
        std::string bind_str = to_string(sym.binding);
        std::string vis_str = to_string(sym.visibility);

        std::cout << std::left << std::setw(18) << format_address(sym.address)
                  << std::setw(10) << (sym.size ? format_size(sym.size) : "-")
                  << std::setw(10) << type_str.substr(0, 9)
                  << std::setw(10) << bind_str.substr(0, 9)
                  << std::setw(10) << vis_str.substr(0, 9)
                  << sym.name << "\n";
    }
}

static void print_relocations(const BinaryAnalysisResult& result, const AnalyzeOptions& /*opts*/) {
    std::cout << "\n=== Relocations (" << result.relocations.size() << ") ===\n";
    std::cout << std::left << std::setw(18) << "Address"
              << std::setw(14) << "Kind"
              << std::setw(12) << "Section"
              << "Symbol\n";
    std::cout << std::string(100, '-') << "\n";

    size_t count = 0;
    for (const auto& reloc : result.relocations) {
        if (count++ > 100) {
            std::cout << "... (" << result.relocations.size() - 100 << " more)\n";
            break;
        }
        std::cout << std::left << std::setw(18) << format_address(reloc.virtual_address)
                  << std::setw(14) << to_string(reloc.kind).substr(0, 13)
                  << std::setw(12) << reloc.section_name.substr(0, 11)
                  << reloc.symbol_name << "\n";
    }
}

static void print_debug(const BinaryAnalysisResult& result, const AnalyzeOptions& /*opts*/) {
    std::cout << "\n=== Debug Information ===\n";
    std::cout << "  Has debug symbols: " << (result.debug_info.has_debug_symbols ? "Yes" : "No") << "\n";
    if (!result.debug_info.debug_type.empty()) std::cout << "  Debug type: " << result.debug_info.debug_type << "\n";
    if (!result.debug_info.build_id.empty()) std::cout << "  Build ID: " << result.debug_info.build_id << "\n";
    if (!result.debug_info.debug_directory.empty()) std::cout << "  Debug directory: " << result.debug_info.debug_directory << "\n";
    if (!result.debug_info.source_files.empty()) {
        std::cout << "  Source files: " << result.debug_info.source_files.size() << "\n";
    }
    std::cout << "  Stripped: " << (result.debug_info.stripped ? "Yes" : "No") << "\n";
}

static void print_summary(const BinaryAnalysisResult& result) {
    std::cout << "\n=== Summary ===\n";
    std::cout << "  File: " << result.file_path.filename().string() << "\n";
    std::cout << "  Format: " << to_string(result.format) << "\n";
    std::cout << "  Architecture: " << to_string(result.architecture) << (result.is_64bit ? " (64-bit)" : " (32-bit)") << "\n";
    std::cout << "  Endianness: " << to_string(result.endianness) << "\n";
    std::cout << "  OS/ABI: " << result.os_abi << "\n";
    std::cout << "  Entry Point: " << format_address(result.entry_point) << "\n";
    std::cout << "  Sections: " << result.total_sections << "\n";
    std::cout << "  Imports: " << result.total_imports << "\n";
    std::cout << "  Exports: " << result.total_exports << "\n";
    std::cout << "  Symbols: " << result.total_symbols << "\n";
    std::cout << "  Relocations: " << result.total_relocations << "\n";
    std::cout << "  Functions: " << result.total_functions << " (" << result.confirmed_functions << " confirmed, " << result.estimated_functions << " estimated)\n";
    std::cout << "  Analysis Time: " << result.analysis_duration.count() << " ms\n";

    if (!result.hashes.md5.has_value() && !result.hashes.sha256.has_value()) {
        // Hashes not computed
    } else {
        std::cout << "\n  Hashes:\n";
        if (result.hashes.md5) std::cout << "    MD5:      " << result.hashes.md5->to_hex() << "\n";
        if (result.hashes.sha1) std::cout << "    SHA1:     " << result.hashes.sha1->to_hex() << "\n";
        if (result.hashes.sha256) std::cout << "    SHA256:   " << result.hashes.sha256->to_hex() << "\n";
        if (result.hashes.sha512) std::cout << "    SHA512:   " << result.hashes.sha512->to_hex() << "\n";
        if (result.hashes.blake3) std::cout << "    BLAKE3:   " << result.hashes.blake3->to_hex() << "\n";
    }

    if (!result.warnings.empty()) {
        std::cout << "\n  Warnings:\n";
        for (const auto& w : result.warnings) std::cout << "    - " << w << "\n";
    }
    if (!result.errors.empty()) {
        std::cout << "\n  Errors:\n";
        for (const auto& e : result.errors) std::cout << "    - " << e << "\n";
    }
}

static nlohmann::json to_json(const BinaryAnalysisResult& result) {
    nlohmann::json j;
    j["file"] = result.file_path.string();
    j["format"] = to_string(result.format);
    j["architecture"] = to_string(result.architecture);
    j["is_64bit"] = result.is_64bit;
    j["endianness"] = to_string(result.endianness);
    j["os_abi"] = result.os_abi;
    j["entry_point"] = format_address(result.entry_point);
    j["sections"] = nlohmann::json::array();
    for (const auto& sec : result.sections) {
        nlohmann::json s;
        s["name"] = sec.name;
        s["virtual_address"] = format_address(sec.virtual_address);
        s["virtual_size"] = sec.virtual_size;
        s["raw_size"] = sec.raw_size;
        s["file_offset"] = sec.file_offset == INVALID_OFFSET ? nlohmann::json() : nlohmann::json(sec.file_offset);
        s["permissions"] = {
            {"read", sec.is_readable()},
            {"write", sec.is_writable()},
            {"execute", sec.is_executable()}
        };
        s["entropy"] = sec.entropy;
        s["characteristics"] = sec.characteristics;
        j["sections"].push_back(s);
    }
    j["imports"] = nlohmann::json::array();
    for (const auto& imp : result.imports) {
        nlohmann::json i;
        i["library"] = imp.library_name;
        i["delay_load"] = imp.is_delay_load;
        i["functions"] = nlohmann::json::array();
        for (const auto& sym : imp.functions) {
            i["functions"].push_back({{"address", format_address(sym.address)}, {"name", sym.name}, {"ordinal", sym.import_ordinal}});
        }
        j["imports"].push_back(i);
    }
    j["exports"] = nlohmann::json::array();
    for (const auto& exp : result.exports) {
        nlohmann::json e;
        e["library"] = exp.library_name;
        e["functions"] = nlohmann::json::array();
        for (const auto& sym : exp.functions) {
            e["functions"].push_back({{"address", format_address(sym.address)}, {"name", sym.name}});
        }
        j["exports"].push_back(e);
    }
    j["symbols"] = nlohmann::json::array();
    for (const auto& sym : result.symbols) {
        nlohmann::json sym_json;
        sym_json["address"] = format_address(sym.address);
        sym_json["size"] = sym.size;
        sym_json["name"] = sym.name;
        sym_json["type"] = to_string(sym.type);
        sym_json["binding"] = to_string(sym.binding);
        sym_json["visibility"] = to_string(sym.visibility);
        sym_json["imported"] = sym.is_imported;
        sym_json["exported"] = sym.is_exported;
        j["symbols"].push_back(sym_json);
    }
    j["functions"] = nlohmann::json::array();
    for (const auto& fn : result.functions) {
        nlohmann::json fn_json;
        fn_json["address"] = format_address(fn.address);
        fn_json["size"] = fn.size;
        fn_json["name"] = fn.name;
        fn_json["confidence"] = to_string(fn.confidence);
        fn_json["source"] = to_string(fn.source);
        fn_json["exported"] = fn.is_exported;
        fn_json["imported"] = fn.is_imported;
        j["functions"].push_back(fn_json);
    }
    j["hashes"] = {
        {"md5", result.hashes.md5 ? result.hashes.md5->to_hex() : nullptr},
        {"sha1", result.hashes.sha1 ? result.hashes.sha1->to_hex() : nullptr},
        {"sha256", result.hashes.sha256 ? result.hashes.sha256->to_hex() : nullptr},
        {"sha512", result.hashes.sha512 ? result.hashes.sha512->to_hex() : nullptr},
        {"blake3", result.hashes.blake3 ? result.hashes.blake3->to_hex() : nullptr}
    };
    j["analysis_duration_ms"] = result.analysis_duration.count();
    j["warnings"] = result.warnings;
    j["errors"] = result.errors;
    return j;
}

int analyze_command(const std::vector<std::string>& args) {
    auto opts_result = parse_args(args);
    if (!opts_result) {
        std::cerr << "Error: " << opts_result.error().to_string() << "\n";
        print_analyze_help();
        return 1;
    }
    AnalyzeOptions opts = opts_result.value();

    // Configure analysis
    AnalysisOptions analysis_opts;
    analysis_opts.analyze_sections = true;
    analysis_opts.analyze_symbols = opts.show_symbols || opts.show_functions || opts.show_imports || opts.show_exports;
    analysis_opts.analyze_imports = opts.show_imports;
    analysis_opts.analyze_exports = opts.show_exports;
    analysis_opts.analyze_relocations = opts.show_relocations;
    analysis_opts.analyze_functions = opts.show_functions || opts.show_symbols;
    analysis_opts.analyze_debug = opts.show_debug;
    analysis_opts.compute_hashes = true;
    analysis_opts.compute_entropy = true;

    // Run analysis
    BinaryAnalyzer analyzer;
    if (!opts.quiet) std::cout << "Analyzing " << opts.input_file << "...\n";

    auto result = analyzer.analyze(opts.input_file, analysis_opts);
    if (!result) {
        std::cerr << "Analysis failed: " << result.error().to_string() << "\n";
        return 1;
    }

    BinaryAnalysisResult analysis = std::move(result.value());

    // Output
    if (opts.json_output || !opts.output_file.empty()) {
        nlohmann::json json = to_json(analysis);
        std::string output = json.dump(2);

        if (opts.json_output) {
            std::cout << output << "\n";
        }
        if (!opts.output_file.empty()) {
            std::ofstream out(opts.output_file);
            out << output;
            if (!opts.quiet) std::cout << "Report written to " << opts.output_file << "\n";
        }
    } else {
        print_summary(analysis);

        if (opts.show_sections) print_section(analysis, opts);
        if (opts.show_imports) print_imports(analysis, opts);
        if (opts.show_exports) print_exports(analysis, opts);
        if (opts.show_functions) print_functions(analysis, opts);
        if (opts.show_symbols) print_symbols(analysis, opts);
        if (opts.show_relocations) print_relocations(analysis, opts);
        if (opts.show_debug) print_debug(analysis, opts);
    }

    return analysis.errors.empty() ? 0 : 1;
}

} // namespace fortress::cli