// FORTRESS Analysis Data Model Implementation

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/binary_info.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <memory>

namespace fortress {

// ============================================================================
// TypedAddress Implementation
// ============================================================================

std::string TypedAddress::to_string() const {
    const char* space_str = "INVALID";
    switch (space_) {
        case AddressSpace::FileOffset: space_str = "FO"; break;
        case AddressSpace::RVA: space_str = "RVA"; break;
        case AddressSpace::VA: space_str = "VA"; break;
        case AddressSpace::SegmentVA: space_str = "SEG_VA"; break;
        default: space_str = "INVALID"; break;
    }
    std::ostringstream oss;
    oss << space_str << ":0x" << std::hex << std::uppercase << value_;
    return oss.str();
}

// ============================================================================
// NormalizedAnalysisResult Implementation
// ============================================================================

std::string NormalizedAnalysisResult::summary() const {
    std::ostringstream oss;
    oss << "=== Normalized Analysis Summary ===\n"
        << "  File: " << metadata.file_path.filename().string() << "\n"
        << "  Format: " << to_string(metadata.format) << "\n"
        << "  Architecture: " << to_string(metadata.architecture) << " (" << (metadata.is_64bit ? "64-bit" : "32-bit") << ")\n"
        << "  Endianness: " << to_string(metadata.endianness) << "\n"
        << "  OS/ABI: " << metadata.os_abi << "\n"
        << "  Entry Point: " << metadata.entry_point.to_string() << "\n"
        << "  Sections: " << sections.size() << "\n"
        << "  Symbols: " << symbols.size() << "\n"
        << "  Imports: " << imports.size() << " libraries\n"
        << "  Exports: " << exports.size() << " libraries\n"
        << "  Relocations: " << relocations.size() << "\n"
        << "  Functions: " << functions.size() << " (" << confirmed_functions << " confirmed, " << estimated_functions << " estimated)\n"
        << "  Analysis Time: " << analysis_duration.count() << " ms\n"
        << "  Valid Format: " << (valid_format ? "Yes" : "No") << "\n";
    if (!warnings.empty()) {
        oss << "  Warnings: " << warnings.size() << "\n";
    }
    if (!errors.empty()) {
        oss << "  Errors: " << errors.size() << "\n";
    }
    return oss.str();
}

// Helper function for JSON string escaping
static std::string json_escape(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c));
                } else {
                    oss << c;
                }
                break;
        }
    }
    return oss.str();
}

std::string NormalizedAnalysisResult::to_json() const {
    std::ostringstream oss;
    oss << "{\n"
        << "  \"file\": \"" << json_escape(metadata.file_path.string()) << "\",\n"
        << "  \"format\": \"" << to_string(metadata.format) << "\",\n"
        << "  \"architecture\": \"" << to_string(metadata.architecture) << "\",\n"
        << "  \"endianness\": \"" << to_string(metadata.endianness) << "\",\n"
        << "  \"is_64bit\": " << (metadata.is_64bit ? "true" : "false") << ",\n"
        << "  \"entry_point\": \"" << metadata.entry_point.to_string() << "\",\n"
        << "  \"sections\": " << sections.size() << ",\n"
        << "  \"symbols\": " << symbols.size() << ",\n"
        << "  \"imports\": " << imports.size() << ",\n"
        << "  \"exports\": " << exports.size() << ",\n"
        << "  \"relocations\": " << relocations.size() << ",\n"
        << "  \"functions\": " << functions.size() << ",\n"
        << "  \"confirmed_functions\": " << confirmed_functions << ",\n"
        << "  \"estimated_functions\": " << estimated_functions << ",\n"
        << "  \"valid_format\": " << (valid_format ? "true" : "false") << "\n"
        << "}";
    return oss.str();
}

std::optional<const NormalizedSection*> NormalizedAnalysisResult::find_section_by_va(TypedAddress va) const {
    if (va.space() != AddressSpace::VA) return std::nullopt;
    for (const auto& sec : sections) {
        if (sec.contains_va(va)) {
            return &sec;
        }
    }
    return std::nullopt;
}

std::optional<const NormalizedSection*> NormalizedAnalysisResult::find_section_by_file_offset(TypedAddress offset) const {
    if (offset.space() != AddressSpace::FileOffset) return std::nullopt;
    for (const auto& sec : sections) {
        if (sec.contains_file_offset(offset)) {
            return &sec;
        }
    }
    return std::nullopt;
}

std::optional<const NormalizedFunction*> NormalizedAnalysisResult::find_function_by_va(TypedAddress va) const {
    if (va.space() != AddressSpace::VA) return std::nullopt;
    for (const auto& fn : functions) {
        if (fn.address == va) {
            return &fn;
        }
        // Also check if within function range (with overflow protection)
        if (fn.size > 0) {
            if (fn.address.value() > std::numeric_limits<uint64_t>::max() - fn.size) {
                // Overflow in range calculation
                continue;
            }
            uint64_t fn_end = fn.address.value() + fn.size;
            if (fn.address.value() <= va.value() && va.value() < fn_end) {
                return &fn;
            }
        }
    }
    return std::nullopt;
}

std::optional<const NormalizedSymbol*> NormalizedAnalysisResult::find_symbol_by_name(const std::string& name) const {
    for (const auto& sym : symbols) {
        if (sym.name == name) {
            return &sym;
        }
    }
    return std::nullopt;
}

std::vector<const NormalizedRelocation*> NormalizedAnalysisResult::find_relocations_in_section(const std::string& section_name) const {
    std::vector<const NormalizedRelocation*> result;
    for (const auto& reloc : relocations) {
        if (reloc.section_name == section_name) {
            result.push_back(&reloc);
        }
    }
    return result;
}

// ============================================================================
// Conversion: BinaryAnalysisResult -> NormalizedAnalysisResult
// ============================================================================

NormalizedAnalysisResult normalize_analysis_result(
    const BinaryAnalysisResult& result,
    std::shared_ptr<AddressConverter> converter) {
    
    NormalizedAnalysisResult normalized;
    
    // Copy metadata
    normalized.metadata.file_path = result.file_path;
    normalized.metadata.format = result.format;
    normalized.metadata.architecture = result.architecture;
    normalized.metadata.endianness = result.endianness;
    normalized.metadata.is_64bit = result.is_64bit;
    normalized.metadata.is_32bit = result.is_32bit;
    normalized.metadata.os_abi = result.os_abi;
    normalized.metadata.machine_type = result.machine_type;
    normalized.metadata.entry_point = TypedAddress::va(result.entry_point);
    normalized.metadata.entry_point_file_offset = result.entry_point_offset != INVALID_OFFSET 
        ? TypedAddress::file_offset(result.entry_point_offset)
        : TypedAddress::file_offset(INVALID_OFFSET);
    // Use image_base from result if available (PE parser sets it)
    normalized.metadata.image_base = result.image_base;
    normalized.metadata.hashes = result.hashes;
    
    // Set converter
    normalized.converter = converter;
    
    // Convert sections
    normalized.sections.reserve(result.sections.size());
    for (const auto& sec : result.sections) {
        NormalizedSection nsec;
        nsec.name = sec.name;
        nsec.file_offset = sec.file_offset != INVALID_OFFSET 
            ? TypedAddress::file_offset(sec.file_offset)
            : TypedAddress::file_offset(0);
        nsec.virtual_address = TypedAddress::va(sec.virtual_address);
        // For PE, virtual_address is typically VA = ImageBase + RVA
        // For ELF/Mach-O, virtual_address is already VA
        if (result.format == BinaryFormat::PE && result.image_base > 0) {
            uint64_t rva = sec.virtual_address >= result.image_base 
                ? sec.virtual_address - result.image_base 
                : sec.virtual_address;
            nsec.rva = TypedAddress::rva(rva);
        }
        nsec.virtual_size = sec.virtual_size;
        nsec.raw_size = sec.raw_size;
        nsec.alignment = sec.alignment;
        nsec.permissions = sec.permissions;
        nsec.characteristics = sec.characteristics;
        nsec.entropy = sec.entropy;
        nsec.segment_name = sec.name; // Will be overridden for Mach-O
        normalized.sections.push_back(std::move(nsec));
    }
    
    // Convert symbols
    normalized.symbols.reserve(result.symbols.size());
    for (const auto& sym : result.symbols) {
        NormalizedSymbol nsym;
        nsym.name = sym.name;
        nsym.address = TypedAddress::va(sym.address);
        nsym.size = sym.size;
        nsym.type = sym.type;
        nsym.binding = sym.binding;
        nsym.visibility = sym.visibility;
        nsym.section_name = sym.section_name;
        nsym.section_index = sym.section_index;
        nsym.is_imported = sym.is_imported;
        nsym.is_exported = sym.is_exported;
        nsym.import_library = sym.import_library;
        nsym.import_ordinal = sym.import_ordinal;
        nsym.is_weak = (sym.binding == SymbolBinding::Weak);
        normalized.symbols.push_back(std::move(nsym));
    }
    
    // Convert imports
    normalized.imports.reserve(result.imports.size());
    for (const auto& imp : result.imports) {
        NormalizedImport nimp;
        nimp.library_name = imp.library_name;
        nimp.is_delay_load = imp.is_delay_load;
        nimp.is_bound = imp.is_bound;
        for (const auto& fn : imp.functions) {
            NormalizedSymbol nsym;
            nsym.name = fn.name;
            nsym.address = TypedAddress::va(fn.address);
            nsym.size = fn.size;
            nsym.type = fn.type;
            nsym.binding = fn.binding;
            nsym.visibility = fn.visibility;
            nsym.section_name = fn.section_name;
            nsym.section_index = fn.section_index;
            nsym.is_imported = fn.is_imported;
            nsym.is_exported = fn.is_exported;
            nsym.import_library = fn.import_library;
            nsym.import_ordinal = fn.import_ordinal;
            nimp.functions.push_back(std::move(nsym));
        }
        normalized.imports.push_back(std::move(nimp));
    }
    
    // Convert exports
    normalized.exports.reserve(result.exports.size());
    for (const auto& exp : result.exports) {
        NormalizedExport nexp;
        nexp.library_name = exp.library_name;
        nexp.ordinal_base = exp.ordinal_base;
        nexp.number_of_functions = exp.number_of_functions;
        nexp.number_of_names = exp.number_of_names;
        for (const auto& fn : exp.functions) {
            NormalizedSymbol nsym;
            nsym.name = fn.name;
            nsym.address = TypedAddress::va(fn.address);
            nsym.size = fn.size;
            nsym.type = fn.type;
            nsym.binding = fn.binding;
            nsym.visibility = fn.visibility;
            nsym.section_name = fn.section_name;
            nsym.section_index = fn.section_index;
            nsym.is_imported = fn.is_imported;
            nsym.is_exported = fn.is_exported;
            nsym.import_library = fn.import_library;
            nsym.import_ordinal = fn.import_ordinal;
            nexp.functions.push_back(std::move(nsym));
        }
        normalized.exports.push_back(std::move(nexp));
    }
    
    // Convert relocations (note: RelocationInfo doesn't have section_index in binary_info.h)
    normalized.relocations.reserve(result.relocations.size());
    for (const auto& reloc : result.relocations) {
        NormalizedRelocation nreloc;
        nreloc.offset = reloc.offset != INVALID_OFFSET 
            ? TypedAddress::file_offset(reloc.offset)
            : TypedAddress::file_offset(0);
        nreloc.virtual_address = TypedAddress::va(reloc.virtual_address);
        nreloc.kind = reloc.kind;
        nreloc.symbol_name = reloc.symbol_name;
        nreloc.symbol_index = reloc.symbol_index;
        nreloc.addend = reloc.addend;
        nreloc.section_name = reloc.section_name;
        nreloc.section_index = 0; // Not available in current RelocationInfo
        normalized.relocations.push_back(std::move(nreloc));
    }
    
    // Convert functions
    normalized.functions.reserve(result.functions.size());
    for (const auto& fn : result.functions) {
        NormalizedFunction nfn;
        nfn.address = TypedAddress::va(fn.address);
        nfn.file_offset = fn.file_offset != INVALID_OFFSET 
            ? TypedAddress::file_offset(fn.file_offset)
            : TypedAddress::file_offset(INVALID_OFFSET);
        nfn.size = fn.size;
        nfn.architecture = fn.architecture;
        nfn.confidence = fn.confidence;
        nfn.source = fn.source;
        nfn.name = fn.name;
        nfn.section_name = fn.section_name;
        nfn.mangled_name = fn.mangled_name;
        nfn.demangled_name = fn.demangled_name;
        nfn.has_symbol = fn.has_symbol;
        nfn.is_exported = fn.is_exported;
        nfn.is_imported = fn.is_imported;
        nfn.is_thunk = fn.is_thunk;
        nfn.has_unwind_info = fn.has_unwind_info;
        nfn.has_exception_handler = fn.has_exception_handler;
        
        // Convert call targets and jump targets to TypedAddress (VA)
        nfn.call_targets.reserve(fn.call_targets.size());
        for (auto addr : fn.call_targets) {
            nfn.call_targets.push_back(TypedAddress::va(addr));
        }
        nfn.jump_targets.reserve(fn.jump_targets.size());
        for (auto addr : fn.jump_targets) {
            nfn.jump_targets.push_back(TypedAddress::va(addr));
        }
        nfn.basic_block_starts.reserve(fn.basic_block_offsets.size());
        for (auto offset : fn.basic_block_offsets) {
            nfn.basic_block_starts.push_back(TypedAddress::va(offset));
        }
        
        nfn.virtualizable = fn.virtualizable;
        nfn.virtualization_notes = fn.virtualization_notes;
        
        normalized.functions.push_back(std::move(nfn));
    }
    
    // Copy analysis metadata
    normalized.analysis_time = result.analysis_time;
    normalized.analysis_duration = result.analysis_duration;
    normalized.warnings = result.warnings;
    normalized.errors = result.errors;
    normalized.limitations = result.limitations;
    
    // Statistics
    normalized.total_functions = result.total_functions;
    normalized.confirmed_functions = result.confirmed_functions;
    normalized.estimated_functions = result.estimated_functions;
    normalized.total_imports = result.total_imports;
    normalized.total_exports = result.total_exports;
    normalized.total_sections = result.total_sections;
    normalized.total_symbols = result.total_symbols;
    normalized.total_relocations = result.total_relocations;
    
    // Validation flags
    normalized.valid_format = result.valid_format;
    normalized.truncated = result.truncated;
    normalized.corrupted = result.corrupted;
    normalized.overlapping_sections = result.overlapping_sections;
    
    return normalized;
}

// ============================================================================
// Conversion: NormalizedAnalysisResult -> BinaryAnalysisResult
// ============================================================================

BinaryAnalysisResult denormalize_analysis_result(const NormalizedAnalysisResult& normalized) {
    BinaryAnalysisResult result;
    
    // Copy metadata
    result.file_path = normalized.metadata.file_path;
    result.format = normalized.metadata.format;
    result.architecture = normalized.metadata.architecture;
    result.endianness = normalized.metadata.endianness;
    result.is_64bit = normalized.metadata.is_64bit;
    result.is_32bit = normalized.metadata.is_32bit;
    result.os_abi = normalized.metadata.os_abi;
    result.machine_type = normalized.metadata.machine_type;
    result.entry_point = normalized.metadata.entry_point.value();
    result.entry_point_offset = normalized.metadata.entry_point_file_offset.value();
    result.image_base = normalized.metadata.image_base;
    result.hashes = normalized.metadata.hashes;
    
    // Convert sections
    result.sections.reserve(normalized.sections.size());
    for (const auto& sec : normalized.sections) {
        SectionInfo info;
        info.name = sec.name;
        info.file_offset = sec.file_offset.value();
        info.virtual_address = sec.virtual_address.value();
        info.virtual_size = sec.virtual_size;
        info.raw_size = sec.raw_size;
        info.alignment = sec.alignment;
        info.permissions = sec.permissions;
        info.characteristics = sec.characteristics;
        info.entropy = sec.entropy;
        result.sections.push_back(std::move(info));
    }
    
    // Convert symbols
    result.symbols.reserve(normalized.symbols.size());
    for (const auto& sym : normalized.symbols) {
        SymbolInfo info;
        info.name = sym.name;
        info.address = sym.address.value();
        info.size = sym.size;
        info.type = sym.type;
        info.binding = sym.binding;
        info.visibility = sym.visibility;
        info.section_name = sym.section_name;
        info.section_index = sym.section_index;
        info.is_imported = sym.is_imported;
        info.is_exported = sym.is_exported;
        info.import_library = sym.import_library;
        info.import_ordinal = sym.import_ordinal;
        result.symbols.push_back(std::move(info));
    }
    
    // Convert imports
    result.imports.reserve(normalized.imports.size());
    for (const auto& imp : normalized.imports) {
        ImportInfo info;
        info.library_name = imp.library_name;
        info.is_delay_load = imp.is_delay_load;
        info.is_bound = imp.is_bound;
        info.functions.reserve(imp.functions.size());
        for (const auto& fn : imp.functions) {
            SymbolInfo sym;
            sym.name = fn.name;
            sym.address = fn.address.value();
            sym.size = fn.size;
            sym.type = fn.type;
            sym.binding = fn.binding;
            sym.visibility = fn.visibility;
            sym.section_name = fn.section_name;
            sym.section_index = fn.section_index;
            sym.is_imported = fn.is_imported;
            sym.is_exported = fn.is_exported;
            sym.import_library = fn.import_library;
            sym.import_ordinal = fn.import_ordinal;
            info.functions.push_back(std::move(sym));
        }
        result.imports.push_back(std::move(info));
    }
    
    // Convert exports
    result.exports.reserve(normalized.exports.size());
    for (const auto& exp : normalized.exports) {
        ExportInfo info;
        info.library_name = exp.library_name;
        info.ordinal_base = exp.ordinal_base;
        info.number_of_functions = exp.number_of_functions;
        info.number_of_names = exp.number_of_names;
        info.functions.reserve(exp.functions.size());
        for (const auto& fn : exp.functions) {
            SymbolInfo sym;
            sym.name = fn.name;
            sym.address = fn.address.value();
            sym.size = fn.size;
            sym.type = fn.type;
            sym.binding = fn.binding;
            sym.visibility = fn.visibility;
            sym.section_name = fn.section_name;
            sym.section_index = fn.section_index;
            sym.is_imported = fn.is_imported;
            sym.is_exported = fn.is_exported;
            sym.import_library = fn.import_library;
            sym.import_ordinal = fn.import_ordinal;
            info.functions.push_back(std::move(sym));
        }
        result.exports.push_back(std::move(info));
    }
    
    // Convert relocations
    result.relocations.reserve(normalized.relocations.size());
    for (const auto& reloc : normalized.relocations) {
        RelocationInfo info;
        info.offset = reloc.offset.value();
        info.virtual_address = reloc.virtual_address.value();
        info.kind = reloc.kind;
        info.symbol_name = reloc.symbol_name;
        info.symbol_index = reloc.symbol_index;
        info.addend = reloc.addend;
        info.section_name = reloc.section_name;
        // section_index not available in RelocationInfo
        result.relocations.push_back(std::move(info));
    }
    
    // Convert functions
    result.functions.reserve(normalized.functions.size());
    for (const auto& fn : normalized.functions) {
        FunctionInfo info;
        info.address = fn.address.value();
        info.file_offset = fn.file_offset.value();
        info.size = fn.size;
        info.architecture = fn.architecture;
        info.confidence = fn.confidence;
        info.source = fn.source;
        info.name = fn.name;
        info.section_name = fn.section_name;
        info.mangled_name = fn.mangled_name;
        info.demangled_name = fn.demangled_name;
        info.has_symbol = fn.has_symbol;
        info.is_exported = fn.is_exported;
        info.is_imported = fn.is_imported;
        info.is_thunk = fn.is_thunk;
        info.has_unwind_info = fn.has_unwind_info;
        info.has_exception_handler = fn.has_exception_handler;
        
        info.call_targets.reserve(fn.call_targets.size());
        for (auto addr : fn.call_targets) {
            info.call_targets.push_back(addr.value());
        }
        info.jump_targets.reserve(fn.jump_targets.size());
        for (auto addr : fn.jump_targets) {
            info.jump_targets.push_back(addr.value());
        }
        info.basic_block_offsets.reserve(fn.basic_block_starts.size());
        for (auto addr : fn.basic_block_starts) {
            info.basic_block_offsets.push_back(addr.value());
        }
        
        info.virtualizable = fn.virtualizable;
        info.virtualization_notes = fn.virtualization_notes;
        
        result.functions.push_back(std::move(info));
    }
    
    // Analysis metadata
    result.analysis_time = normalized.analysis_time;
    result.analysis_duration = normalized.analysis_duration;
    result.warnings = normalized.warnings;
    result.errors = normalized.errors;
    result.limitations = normalized.limitations;
    
    // Statistics
    result.total_functions = normalized.total_functions;
    result.confirmed_functions = normalized.confirmed_functions;
    result.estimated_functions = normalized.estimated_functions;
    result.total_imports = normalized.total_imports;
    result.total_exports = normalized.total_exports;
    result.total_sections = normalized.total_sections;
    result.total_symbols = normalized.total_symbols;
    result.total_relocations = normalized.total_relocations;
    
    // Validation
    result.valid_format = normalized.valid_format;
    result.truncated = normalized.truncated;
    result.corrupted = normalized.corrupted;
    result.overlapping_sections = normalized.overlapping_sections;
    
    return result;
}

} // namespace fortress