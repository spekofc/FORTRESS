// FORTRESS CLI - CFG Command
// Control Flow Graph analysis

#include <fortress/binary/analysis/analyzer.h>
#include <fortress/binary/analysis/cfg_builder.h>
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

namespace fortress::cli {

struct CFGOptions {
    std::filesystem::path input_file;
    std::filesystem::path output_file;
    bool json_output = false;
    bool show_graph = false;
    bool show_blocks = false;
    bool show_edges = false;
    bool show_loops = false;
    bool show_dominators = false;
    bool show_unreachable = false;
    bool dot_output = false;
    std::filesystem::path dot_file;
    std::string filter_function;
    bool verbose = false;
    bool quiet = false;
};

static void print_cfg_help() {
    std::cout << "Usage: fortress cfg -i <input> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --input <file>          Input binary file (required)\n";
    std::cout << "  -o, --output <file>         Output file for JSON report\n";
    std::cout << "  --json                      Output JSON to stdout\n";
    std::cout << "  --graph                     Show CFG summary\n";
    std::cout << "  --blocks                    Show basic blocks\n";
    std::cout << "  --edges                     Show CFG edges\n";
    std::cout << "  --loops                     Show detected loops\n";
    std::cout << "  --dominators                Show dominator tree\n";
    std::cout << "  --unreachable               Show unreachable blocks\n";
    std::cout << "  --dot                       Output GraphViz DOT format\n";
    std::cout << "  --dot-file <file>           Write DOT to file\n";
    std::cout << "  --filter-function <name>    Filter by function name\n";
    std::cout << "  -v, --verbose               Verbose output\n";
    std::cout << "  -q, --quiet                 Minimal output\n";
    std::cout << "  -h, --help                  Show this help\n";
}

static Result<CFGOptions> parse_args(const std::vector<std::string>& args) {
    CFGOptions opts;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];

        if (arg == "-h" || arg == "--help") {
            print_cfg_help();
            std::exit(0);
        } else if (arg == "-i" || arg == "--input") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--input requires a value");
            opts.input_file = args[++i];
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--output requires a value");
            opts.output_file = args[++i];
        } else if (arg == "--json") {
            opts.json_output = true;
        } else if (arg == "--graph") {
            opts.show_graph = true;
        } else if (arg == "--blocks") {
            opts.show_blocks = true;
        } else if (arg == "--edges") {
            opts.show_edges = true;
        } else if (arg == "--loops") {
            opts.show_loops = true;
        } else if (arg == "--dominators") {
            opts.show_dominators = true;
        } else if (arg == "--unreachable") {
            opts.show_unreachable = true;
        } else if (arg == "--dot") {
            opts.dot_output = true;
        } else if (arg == "--dot-file") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--dot-file requires a value");
            opts.dot_file = args[++i];
        } else if (arg == "--filter-function") {
            if (i + 1 >= args.size()) return Error::invalid_argument("--filter-function requires a value");
            opts.filter_function = args[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-q" || arg == "--quiet") {
            opts.quiet = true;
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

static void print_cfg_summary(const BinaryAnalysisResult& result, const CFGOptions&) {
    std::cout << "\n=== CFG Summary ===\n";
    std::cout << "  Total Functions: " << result.total_functions << "\n";
    std::cout << "  (CFG build required for detailed stats)\n";
}

static void print_basic_blocks(const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs, const CFGOptions& opts) {
    std::cout << "\n=== Basic Blocks ===\n";
    for (const auto& cfg_ptr : cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        if (!opts.filter_function.empty() && 
            cfg.function.name.find(opts.filter_function) == std::string::npos) {
            continue;
        }
        
        std::cout << "\nFunction: " << cfg.function.name 
                  << " (" << format_address(cfg.function.address) << ")\n";
        std::cout << std::left << std::setw(8) << "ID"
                  << std::setw(18) << "Start VA"
                  << std::setw(8) << "Size"
                  << std::setw(10) << "Instrs"
                  << std::setw(8) << "Succs"
                  << std::setw(8) << "Preds"
                  << "Flags\n";
        std::cout << std::string(80, '-') << "\n";
        
        for (const auto& block : cfg.blocks) {
            std::string flags;
            if (block.is_entry_block) flags += "E";
            if (block.has_return) flags += "R";
            if (block.has_call) flags += "C";
            if (block.has_indirect_branch) flags += "I";
            
            std::cout << std::left << std::setw(8) << block.id
                      << std::setw(18) << format_address(block.start_address)
                      << std::setw(8) << block.size
                      << std::setw(10) << block.instructions.size()
                      << std::setw(8) << block.successors.size()
                      << std::setw(8) << block.predecessors.size()
                      << flags << "\n";
        }
    }
}

static void print_edges(const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs, const CFGOptions& opts) {
    std::cout << "\n=== CFG Edges ===\n";
    for (const auto& cfg_ptr : cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        if (!opts.filter_function.empty() && 
            cfg.function.name.find(opts.filter_function) == std::string::npos) {
            continue;
        }
        
        std::cout << "\nFunction: " << cfg.function.name << "\n";
        for (const auto& block : cfg.blocks) {
            for (const auto& edge : block.successors) {
                std::string type_str;
                switch (edge.type) {
                    case CFGEdgeType::Fallthrough: type_str = "Fallthrough"; break;
                    case CFGEdgeType::ConditionalBranch: type_str = "Conditional"; break;
                    case CFGEdgeType::UnconditionalBranch: type_str = "Unconditional"; break;
                    case CFGEdgeType::Call: type_str = "Call"; break;
                    case CFGEdgeType::Return: type_str = "Return"; break;
                    case CFGEdgeType::IndirectBranch: type_str = "IndirectBranch"; break;
                    case CFGEdgeType::IndirectCall: type_str = "IndirectCall"; break;
                    case CFGEdgeType::ExceptionEdge: type_str = "Exception"; break;
                    case CFGEdgeType::InterruptEdge: type_str = "Interrupt"; break;
                    default: type_str = "Unknown"; break;
                }
                
                std::cout << "  Block " << block.id << " -> Block " << edge.target_block_id
                          << " (" << type_str << ")\n";
            }
        }
    }
}

static void print_loops(const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs, const CFGOptions& opts) {
    std::cout << "\n=== Loops ===\n";
    for (const auto& cfg_ptr : cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        if (!opts.filter_function.empty() && 
            cfg.function.name.find(opts.filter_function) == std::string::npos) {
            continue;
        }
        
        if (cfg.loops.empty()) {
            std::cout << "  Function " << cfg.function.name << ": No loops detected\n";
            continue;
        }
        
        std::cout << "\nFunction: " << cfg.function.name << "\n";
        for (const auto& loop : cfg.loops) {
            std::cout << "  Loop header: Block " << loop.header_id
                      << ", Depth: " << loop.depth
                      << ", Reducible: " << (loop.is_reducible ? "Yes" : "No")
                      << ", Blocks: " << loop.body_blocks.size() << "\n";
        }
    }
}

static void print_dominators(const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs, const CFGOptions& opts) {
    std::cout << "\n=== Dominator Tree ===\n";
    for (const auto& cfg_ptr : cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        if (!opts.filter_function.empty() && 
            cfg.function.name.find(opts.filter_function) == std::string::npos) {
            continue;
        }
        
        std::cout << "\nFunction: " << cfg.function.name << "\n";
        std::cout << std::left << std::setw(8) << "Block"
                  << std::setw(8) << "IDom"
                  << "DFrontier\n";
        std::cout << std::string(50, '-') << "\n";
        
        for (size_t i = 0; i < cfg.dominator_tree.size(); ++i) {
            std::string idom = (cfg.dominator_tree[i] == UINT32_MAX) ? "root" : std::to_string(cfg.dominator_tree[i]);
            std::string df = "-";
            
            std::cout << std::left << std::setw(8) << i
                      << std::setw(8) << idom
                      << df << "\n";
        }
    }
}

static void print_unreachable(const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs, const CFGOptions& opts) {
    std::cout << "\n=== Unreachable Blocks ===\n";
    for (const auto& cfg_ptr : cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        if (!opts.filter_function.empty() && 
            cfg.function.name.find(opts.filter_function) == std::string::npos) {
            continue;
        }
        
        if (cfg.unreachable_blocks.empty()) {
            std::cout << "  Function " << cfg.function.name << ": No unreachable blocks\n";
            continue;
        }
        
        std::cout << "\nFunction: " << cfg.function.name << "\n";
        for (uint32_t block_id : cfg.unreachable_blocks) {
            if (block_id < cfg.blocks.size()) {
                const auto& block = cfg.blocks[block_id];
                std::cout << "  Block " << block_id << " at " << format_address(block.start_address) << "\n";
            }
        }
    }
}

static void export_dot(const std::vector<std::unique_ptr<ControlFlowGraph>>& cfgs, const CFGOptions&) {
    for (const auto& cfg_ptr : cfgs) {
        if (!cfg_ptr) continue;
        const auto& cfg = *cfg_ptr;
        
        std::cout << "digraph CFG_" << cfg.function.name << " {\n";
        std::cout << "  rankdir=TB;\n";
        std::cout << "  node [shape=box];\n";
        
        for (const auto& block : cfg.blocks) {
            std::string label = "B" + std::to_string(block.id);
            label += "\\n" + format_address(block.start_address);
            label += "\\nSize: " + std::to_string(block.size);
            label += "\\nInstr: " + std::to_string(block.instructions.size());
            
            std::string color = "lightgray";
            if (block.is_entry_block) color = "lightgreen";
            else if (block.has_return) color = "lightcoral";
            else if (block.has_call) color = "lightyellow";
            
            std::cout << "  B" << block.id << " [label=\"" << label << "\", fillcolor=" << color << "];\n";
        }
        
        for (const auto& block : cfg.blocks) {
            for (const auto& edge : block.successors) {
                std::string style = "solid";
                std::string color = "black";
                switch (edge.type) {
                    case CFGEdgeType::ConditionalBranch: style = "dashed"; color = "blue"; break;
                    case CFGEdgeType::Call: color = "green"; break;
                    case CFGEdgeType::Return: color = "red"; break;
                    case CFGEdgeType::ExceptionEdge: style = "dotted"; color = "purple"; break;
                    default: break;
                }
                std::cout << "  B" << block.id << " -> B" << edge.target_block_id 
                          << " [style=" << style << ", color=" << color << "];\n";
            }
        }
        
        std::cout << "}\n";
    }
}

int cfg_command(const std::vector<std::string>& args) {
    auto opts_result = parse_args(args);
    if (!opts_result) {
        std::cerr << "Error: " << opts_result.error().to_string() << "\n";
        print_cfg_help();
        return 1;
    }
    CFGOptions opts = opts_result.value();

    // Configure analysis
    AnalysisOptions analysis_opts;
    analysis_opts.analyze_sections = true;
    analysis_opts.analyze_symbols = true;
    analysis_opts.analyze_functions = true;
    analysis_opts.analyze_debug = false;
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

    // Build CFGs
    CFGBuilder cfg_builder;
    std::vector<std::unique_ptr<ControlFlowGraph>> cfgs;
    
    if (!opts.quiet) std::cout << "Building CFGs...\n";
    
    // Get code section bytes for disassembly
    std::vector<uint8_t> code_bytes;
    uint64_t code_base = 0;
    for (const auto& sec : analysis.sections) {
        if (sec.is_code() && sec.bytes.empty() == false) {
            code_bytes = sec.bytes;
            code_base = sec.virtual_address;
            break;
        }
    }
    
    for (const auto& func : analysis.functions) {
        if (!opts.filter_function.empty() && 
            func.name.find(opts.filter_function) == std::string::npos) {
            continue;
        }
        
        auto cfg_result = cfg_builder.build_cfg(func, analysis, code_bytes, code_base);
        if (cfg_result.success && cfg_result.cfg) {
            cfgs.push_back(std::move(cfg_result.cfg));
        }
    }

    if (!opts.quiet) std::cout << "Built " << cfgs.size() << " CFGs\n";

    // Output
    if (opts.json_output || !opts.output_file.empty()) {
        if (!opts.quiet) std::cout << "JSON export not yet implemented\n";
    } else {
        if (opts.show_graph) print_cfg_summary(analysis, opts);
        if (opts.show_blocks) print_basic_blocks(cfgs, opts);
        if (opts.show_edges) print_edges(cfgs, opts);
        if (opts.show_loops) print_loops(cfgs, opts);
        if (opts.show_dominators) print_dominators(cfgs, opts);
        if (opts.show_unreachable) print_unreachable(cfgs, opts);
        if (opts.dot_output) export_dot(cfgs, opts);
        
        if (!opts.show_graph && !opts.show_blocks && !opts.show_edges && 
            !opts.show_loops && !opts.show_dominators && !opts.show_unreachable && 
            !opts.dot_output) {
            print_cfg_summary(analysis, opts);
        }
    }

    if (opts.dot_file.empty() == false) {
        std::ofstream out(opts.dot_file);
        std::streambuf* coutbuf = std::cout.rdbuf();
        std::cout.rdbuf(out.rdbuf());
        export_dot(cfgs, opts);
        std::cout.rdbuf(coutbuf);
        if (!opts.quiet) std::cout << "DOT written to " << opts.dot_file << "\n";
    }

    return analysis.errors.empty() ? 0 : 1;
}

} // namespace fortress::cli