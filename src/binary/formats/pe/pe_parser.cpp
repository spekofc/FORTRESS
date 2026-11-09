// FORTRESS PE Parser Implementation

#include <fortress/binary/formats/pe/pe_parser.h>
#include <fortress/core/hash.h>
#include <fortress/core/string_utils.h>
#include <algorithm>
#include <cstring>

namespace fortress::pe {

// Helper: read typed value from buffer
template<typename T>
static T read_value(const std::byte* ptr) {
    T val;
    std::memcpy(&val, static_cast<const void*>(ptr), sizeof(T));
    return val;
}

static uint16_t read_u16(const std::byte* ptr) { return read_value<uint16_t>(ptr); }
static uint32_t read_u32(const std::byte* ptr) { return read_value<uint32_t>(ptr); }

// Parse entry point
Result<BinaryAnalysisResult> PEParser::parse(const FileMapping& mapping) {
    return parse(mapping.data());
}

Result<BinaryAnalysisResult> PEParser::parse(std::span<const std::byte> data) {
    BinaryAnalysisResult result;
    result.format = BinaryFormat::PE;
    result.analysis_time = std::chrono::system_clock::now();
    auto start_time = std::chrono::steady_clock::now();

    Context ctx;
    ctx.base = data.data();
    ctx.size = data.size();
    ctx.result = &result;

    auto finish = [&](Error err) -> Result<BinaryAnalysisResult> {
        result.analysis_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time);
        result.warnings = std::move(ctx.warnings);
        result.errors = std::move(ctx.errors);
        result.limitations.push_back("PE parsing completed");
        if (err) {
            result.errors.push_back(err.to_string());
            return err;
        }
        result.valid_format = true;
        return result;
    };

    // Compute hashes
    result.hashes = compute_all_hashes(data).value_or(MultiHashResult{});

    // Validate DOS header
    auto dos_result = validate_dos_header(ctx);
    if (!dos_result) return finish(dos_result.error());

    // Validate PE signature
    auto pe_result = validate_pe_signature(ctx);
    if (!pe_result) return finish(pe_result.error());

    // Parse COFF header
    auto coff_result = parse_coff_header(ctx);
    if (!coff_result) return finish(coff_result.error());

    // Parse optional header
    auto opt_result = parse_optional_header(ctx);
    if (!opt_result) return finish(opt_result.error());

    // Parse sections
    auto sec_result = parse_sections(ctx);
    if (!sec_result) return finish(sec_result.error());

    // Validate sections
    auto val_result = validate_sections(ctx);
    if (!val_result) return finish(val_result.error());

    // Fill basic info
    result.architecture = machine_to_architecture(ctx.coff_header->machine);
    result.is_64bit = ctx.is_64bit;
    result.is_32bit = !ctx.is_64bit;
    result.endianness = Endianness::Little;
    result.os_abi = "windows";
    result.machine_type = std::to_string(ctx.coff_header->machine);
    // Entry point in PE optional header is an RVA; add ImageBase to get VA
    uint32_t entry_rva = ctx.is_64bit ?
        read_u32(reinterpret_cast<const std::byte*>(ctx.optional_header) + offsetof(OptionalHeader64, address_of_entry_point)) :
        read_u32(reinterpret_cast<const std::byte*>(ctx.optional_header) + offsetof(OptionalHeader32, address_of_entry_point));
    result.entry_point = ctx.image_base + entry_rva;
    result.image_base = ctx.image_base;
    const std::byte* entry_ptr = rva_to_raw(ctx, static_cast<uint32_t>(entry_rva));
    result.entry_point_offset = entry_ptr ?
        static_cast<Offset>(entry_ptr - ctx.base) :
        INVALID_OFFSET;

    // Parse data directories
    parse_exports(ctx, result);
    parse_imports(ctx, result);
    parse_relocations(ctx, result);
    parse_debug(ctx, result);
    parse_tls(ctx, result);
    parse_load_config(ctx, result);
    parse_resources(ctx, result);

    // Discover functions
    discover_functions(ctx, result);

    // Compute statistics
    result.total_sections = result.sections.size();
    result.total_imports = 0;
    for (const auto& imp : result.imports) result.total_imports += imp.functions.size();
    result.total_exports = 0;
    for (const auto& exp : result.exports) result.total_exports += exp.functions.size();
    result.total_symbols = result.symbols.size();
    result.total_relocations = result.relocations.size();
    result.total_functions = result.functions.size();
    result.confirmed_functions = 0;
    result.estimated_functions = 0;
    for (const auto& fn : result.functions) {
        if (fn.confidence >= ConfidenceLevel::High) result.confirmed_functions++;
        else result.estimated_functions++;
    }

    return finish(Error::success());
}

// Validate DOS Header
Result<void> PEParser::validate_dos_header(Context& ctx) {
    if (ctx.size < sizeof(DOSHeader)) {
        return Error::truncated("File too small for DOS header");
    }

    ctx.dos_header = reinterpret_cast<const DOSHeader*>(ctx.base);

    if (ctx.dos_header->e_magic != DOS_SIGNATURE) {
        return Error::invalid_format("Invalid DOS signature (not MZ)");
    }

    if (ctx.dos_header->e_lfanew >= ctx.size) {
        return Error::invalid_format("e_lfanew points beyond file end");
    }

    if (ctx.dos_header->e_lfanew < sizeof(DOSHeader)) {
        ctx.warnings.push_back("e_lfanew points inside DOS header");
    }

    return Result<void>::ok();
}

// Validate PE Signature
Result<void> PEParser::validate_pe_signature(Context& ctx) {
    const std::byte* pe_sig_ptr = ctx.base + ctx.dos_header->e_lfanew;
    if (pe_sig_ptr + 4 > ctx.base + ctx.size) {
        return Error::truncated("PE signature beyond file end");
    }

    uint32_t sig = read_u32(pe_sig_ptr);
    if (sig != PE_SIGNATURE) {
        return Error::invalid_format("Invalid PE signature (not PE\\0\\0)");
    }

    return Result<void>::ok();
}

// Parse COFF Header
Result<void> PEParser::parse_coff_header(Context& ctx) {
    const std::byte* coff_ptr = ctx.base + ctx.dos_header->e_lfanew + 4;
    if (coff_ptr + sizeof(COFFHeader) > ctx.base + ctx.size) {
        return Error::truncated("COFF header truncated");
    }

    ctx.coff_header = reinterpret_cast<const COFFHeader*>(coff_ptr);
    ctx.number_of_sections = ctx.coff_header->number_of_sections;

    if (ctx.coff_header->number_of_sections == 0) {
        ctx.warnings.push_back("No sections in PE file");
    }
    if (ctx.coff_header->number_of_sections > 96) {
        ctx.warnings.push_back("Unusually high section count: " + std::to_string(ctx.coff_header->number_of_sections));
    }

    return Result<void>::ok();
}

// Parse Optional Header
Result<void> PEParser::parse_optional_header(Context& ctx) {
    const std::byte* opt_ptr = reinterpret_cast<const std::byte*>(ctx.coff_header) + sizeof(COFFHeader);

    if (ctx.coff_header->size_of_optional_header < 2) {
        return Error::invalid_header("Optional header too small");
    }

    uint16_t magic = read_u16(opt_ptr);
    ctx.is_64bit = is_pe32plus(magic);

    Size opt_size = ctx.is_64bit ? sizeof(OptionalHeader64) : sizeof(OptionalHeader32);
    if (ctx.coff_header->size_of_optional_header < opt_size) {
        ctx.warnings.push_back("Optional header size smaller than expected");
    }

    if (opt_ptr + opt_size > ctx.base + ctx.size) {
        return Error::truncated("Optional header truncated");
    }

    ctx.optional_header = opt_ptr;

    // Parse data directories
    const std::byte* dir_ptr;
    if (ctx.is_64bit) {
        const auto* opt = reinterpret_cast<const OptionalHeader64*>(opt_ptr);
        ctx.image_base = opt->image_base;
        ctx.section_alignment = opt->section_alignment;
        ctx.file_alignment = opt->file_alignment;
        dir_ptr = reinterpret_cast<const std::byte*>(opt) + sizeof(OptionalHeader64);
    } else {
        const auto* opt = reinterpret_cast<const OptionalHeader32*>(opt_ptr);
        ctx.image_base = opt->image_base;
        ctx.section_alignment = opt->section_alignment;
        ctx.file_alignment = opt->file_alignment;
        dir_ptr = reinterpret_cast<const std::byte*>(opt) + sizeof(OptionalHeader32);
    }

    if (dir_ptr + NUMBER_OF_DIRECTORIES * sizeof(DataDirectory) > ctx.base + ctx.size) {
        return Error::truncated("Data directories truncated");
    }

    ctx.directories = reinterpret_cast<const DataDirectory*>(dir_ptr);
    return Result<void>::ok();
}

// Parse Sections
Result<void> PEParser::parse_sections(Context& ctx) {
    const std::byte* sec_ptr = reinterpret_cast<const std::byte*>(ctx.directories) + NUMBER_OF_DIRECTORIES * sizeof(DataDirectory);

    if (sec_ptr + ctx.number_of_sections * sizeof(SectionHeader) > ctx.base + ctx.size) {
        return Error::truncated("Section headers truncated");
    }

    ctx.sections = reinterpret_cast<const SectionHeader*>(sec_ptr);

    for (uint16_t i = 0; i < ctx.number_of_sections; ++i) {
        const auto& sec = ctx.sections[i];
        SectionInfo info;
        info.name = std::string(reinterpret_cast<const char*>(sec.name), 8);
        // Remove trailing null padding from section name
        auto null_pos = info.name.find('\0');
        if (null_pos != std::string::npos) {
            info.name.resize(null_pos);
        }

        info.virtual_address = ctx.image_base + sec.virtual_address;
        info.virtual_size = sec.virtual_size;
        info.raw_size = sec.size_of_raw_data;
        info.file_offset = sec.pointer_to_raw_data;
        info.alignment = ctx.file_alignment;
        info.permissions = section_characteristics_to_permissions(sec.characteristics);
        info.characteristics = section_characteristics_to_string(sec.characteristics);

        // Calculate entropy if section has data
        if (sec.size_of_raw_data > 0 && sec.pointer_to_raw_data > 0) {
            if (sec.pointer_to_raw_data + sec.size_of_raw_data <= static_cast<uint32_t>(ctx.size)) {
                auto data = std::span<const std::byte>(ctx.base + sec.pointer_to_raw_data, sec.size_of_raw_data);
                info.entropy = calculate_entropy(data);
            }
        }

        ctx.result->sections.push_back(std::move(info));
    }

    return Result<void>::ok();
}

// Validate Sections
Result<void> PEParser::validate_sections(Context& ctx) {
    // Check for overlapping sections
    for (uint16_t i = 0; i < ctx.number_of_sections; ++i) {
        const auto& a = ctx.sections[i];
        if (a.size_of_raw_data == 0) continue;

        Offset a_start = a.pointer_to_raw_data;
        Offset a_end = a_start + a.size_of_raw_data;

        for (uint16_t j = i + 1; j < ctx.number_of_sections; ++j) {
            const auto& b = ctx.sections[j];
            if (b.size_of_raw_data == 0) continue;

            Offset b_start = b.pointer_to_raw_data;
            Offset b_end = b_start + b.size_of_raw_data;

            if (a_start < b_end && b_start < a_end) {
                ctx.warnings.push_back("Overlapping sections: " + std::string(a.name, 8) + " and " + std::string(b.name, 8));
                // Mark in result
            }
        }
    }

    return Result<void>::ok();
}

// RVA to raw offset
const std::byte* PEParser::rva_to_raw(Context& ctx, uint32_t rva) const {
    if (rva == 0) return nullptr;

    for (uint16_t i = 0; i < ctx.number_of_sections; ++i) {
        const auto& sec = ctx.sections[i];
        uint32_t sec_rva = sec.virtual_address;
        uint32_t sec_end = sec_rva + std::max(sec.virtual_size, sec.size_of_raw_data);

        if (rva >= sec_rva && rva < sec_end) {
            uint32_t offset_in_section = rva - sec_rva;
            if (sec.pointer_to_raw_data + offset_in_section < ctx.size) {
                return ctx.base + sec.pointer_to_raw_data + offset_in_section;
            }
        }
    }
    return nullptr;
}

Address PEParser::rva_to_va(Context& ctx, uint32_t rva) const {
    return ctx.image_base + rva;
}

std::string PEParser::read_string(Context& ctx, uint32_t rva) const {
    const std::byte* ptr = rva_to_raw(ctx, rva);
    if (!ptr) return "";
    return read_string_at(ptr);
}

std::string PEParser::read_string_at(const std::byte* ptr, Size max_len) const {
    std::string result;
    for (Size i = 0; i < max_len; ++i) {
        char c = static_cast<char>(ptr[i]);
        if (c == '\0') break;
        result.push_back(c);
    }
    return result;
}

SectionPermission PEParser::section_characteristics_to_permissions(uint32_t chars) const {
    SectionPermission perms = SectionPermission::None;
    if (chars & SECTION_MEM_READ) perms = perms | SectionPermission::Read;
    if (chars & SECTION_MEM_WRITE) perms = perms | SectionPermission::Write;
    if (chars & SECTION_MEM_EXECUTE) perms = perms | SectionPermission::Execute;
    return perms;
}

std::string PEParser::section_characteristics_to_string(uint32_t chars) const {
    std::vector<std::string> parts;
    if (chars & SECTION_CNT_CODE) parts.push_back("CODE");
    if (chars & SECTION_CNT_INITIALIZED_DATA) parts.push_back("INIT_DATA");
    if (chars & SECTION_CNT_UNINITIALIZED_DATA) parts.push_back("UNINIT_DATA");
    if (chars & SECTION_LNK_COMDAT) parts.push_back("COMDAT");
    if (chars & SECTION_MEM_DISCARDABLE) parts.push_back("DISCARDABLE");
    if (chars & SECTION_MEM_NOT_CACHED) parts.push_back("NOT_CACHED");
    if (chars & SECTION_MEM_NOT_PAGED) parts.push_back("NOT_PAGED");
    if (chars & SECTION_MEM_SHARED) parts.push_back("SHARED");
    if (chars & SECTION_MEM_EXECUTE) parts.push_back("EXECUTE");
    if (chars & SECTION_MEM_READ) parts.push_back("READ");
    if (chars & SECTION_MEM_WRITE) parts.push_back("WRITE");
    return join(parts, " | ");
}

// Parse Exports
Result<void> PEParser::parse_exports(Context& ctx, BinaryAnalysisResult& result) {
    if (ctx.directories[DIRECTORY_EXPORT].size == 0) return Result<void>::ok();

    const std::byte* exp_ptr = rva_to_raw(ctx, ctx.directories[DIRECTORY_EXPORT].virtual_address);
    if (!exp_ptr) {
        ctx.warnings.push_back("Export directory not in any section");
        return Result<void>::ok();
    }

    const ExportDirectory* exp_dir = reinterpret_cast<const ExportDirectory*>(exp_ptr);

    ExportInfo export_info;
    export_info.library_name = read_string(ctx, exp_dir->name_rva);
    export_info.ordinal_base = exp_dir->ordinal_base;
    export_info.number_of_functions = exp_dir->number_of_functions;
    export_info.number_of_names = exp_dir->number_of_names;

    if (exp_dir->number_of_functions > 0 && exp_dir->address_of_functions != 0) {
        const uint32_t* func_rvas = reinterpret_cast<const uint32_t*>(rva_to_raw(ctx, exp_dir->address_of_functions));
        const uint32_t* name_rvas = exp_dir->number_of_names > 0 ? reinterpret_cast<const uint32_t*>(rva_to_raw(ctx, exp_dir->address_of_names)) : nullptr;
        const uint16_t* ordinals = exp_dir->number_of_names > 0 ? reinterpret_cast<const uint16_t*>(rva_to_raw(ctx, exp_dir->address_of_name_ordinals)) : nullptr;

        for (uint32_t i = 0; i < exp_dir->number_of_functions; ++i) {
            uint32_t func_rva = func_rvas[i];
            if (func_rva == 0) continue;

            SymbolInfo sym;
            sym.address = rva_to_va(ctx, func_rva);
            sym.type = SymbolType::Function;
            sym.binding = SymbolBinding::Global;
            sym.visibility = SymbolVisibility::Default;
            sym.is_exported = true;

            // Find name if available
            if (name_rvas && ordinals) {
                for (uint32_t n = 0; n < exp_dir->number_of_names; ++n) {
                    if (ordinals[n] == i) {
                        sym.name = read_string(ctx, name_rvas[n]);
                        break;
                    }
                }
            }

            if (sym.name.empty()) {
                sym.name = export_info.library_name + "_export_" + std::to_string(exp_dir->ordinal_base + i);
            }

            export_info.functions.push_back(sym);
            result.symbols.push_back(sym);
        }
    }

    result.exports.push_back(std::move(export_info));
    return Result<void>::ok();
}

// Parse Imports
Result<void> PEParser::parse_imports(Context& ctx, BinaryAnalysisResult& result) {
    if (ctx.directories[DIRECTORY_IMPORT].size == 0) return Result<void>::ok();

    const std::byte* imp_ptr = rva_to_raw(ctx, ctx.directories[DIRECTORY_IMPORT].virtual_address);
    if (!imp_ptr) {
        ctx.warnings.push_back("Import directory not in any section");
        return Result<void>::ok();
    }

    const ImportDescriptor* desc = reinterpret_cast<const ImportDescriptor*>(imp_ptr);

    while (desc->name_rva != 0 || desc->first_thunk != 0) {
        ImportInfo import;
        import.library_name = read_string(ctx, desc->name_rva);

        // Parse Original First Thunk (INT) or First Thunk (IAT)
        const uint64_t* thunk_ptr = nullptr;
        if (desc->original_first_thunk != 0) {
            thunk_ptr = reinterpret_cast<const uint64_t*>(rva_to_raw(ctx, desc->original_first_thunk));
        } else if (desc->first_thunk != 0) {
            thunk_ptr = reinterpret_cast<const uint64_t*>(rva_to_raw(ctx, desc->first_thunk));
        }

        if (thunk_ptr) {
            for (size_t i = 0; ; ++i) {
                uint64_t thunk = thunk_ptr[i];
                if (thunk == 0) break;

                SymbolInfo sym;
                sym.type = SymbolType::Function;
                sym.binding = SymbolBinding::Global;
                sym.is_imported = true;
                sym.import_library = import.library_name;

                if (ctx.is_64bit) {
                    if (thunk & 0x8000000000000000ULL) {
                        // Ordinal import
                        sym.import_ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                        sym.name = import.library_name + "_ordinal_" + std::to_string(sym.import_ordinal);
                    } else {
                        // Name import
                        const std::byte* hint_name = rva_to_raw(ctx, static_cast<uint32_t>(thunk));
                        if (hint_name) {
                            // Skip hint (2 bytes)
                            sym.name = read_string_at(hint_name + 2);
                        }
                    }
                    sym.address = rva_to_va(ctx, static_cast<uint32_t>(desc->first_thunk + i * 8));
                } else {
                    if (thunk & 0x80000000) {
                        sym.import_ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                        sym.name = import.library_name + "_ordinal_" + std::to_string(sym.import_ordinal);
                    } else {
                        const std::byte* hint_name = rva_to_raw(ctx, static_cast<uint32_t>(thunk));
                        if (hint_name) {
                            sym.name = read_string_at(hint_name + 2);
                        }
                    }
                    sym.address = rva_to_va(ctx, static_cast<uint32_t>(desc->first_thunk + i * 4));
                }

                import.functions.push_back(sym);
                result.symbols.push_back(sym);
            }
        }

        result.imports.push_back(std::move(import));
        ++desc;
    }

    return Result<void>::ok();
}

// Parse Relocations
Result<void> PEParser::parse_relocations(Context& ctx, BinaryAnalysisResult& result) {
    if (ctx.directories[DIRECTORY_BASERELOC].size == 0) return Result<void>::ok();

    const std::byte* reloc_ptr = rva_to_raw(ctx, ctx.directories[DIRECTORY_BASERELOC].virtual_address);
    if (!reloc_ptr) return Result<void>::ok();

    Size reloc_size = ctx.directories[DIRECTORY_BASERELOC].size;
    const std::byte* end = reloc_ptr + reloc_size;

    while (reloc_ptr + sizeof(BaseRelocationBlock) <= end) {
        const BaseRelocationBlock* block = reinterpret_cast<const BaseRelocationBlock*>(reloc_ptr);
        if (block->block_size < sizeof(BaseRelocationBlock)) break;

        uint32_t page_rva = block->page_rva;
        uint32_t block_size = block->block_size;
        uint32_t entry_count = static_cast<uint32_t>((block_size - sizeof(BaseRelocationBlock)) / 2);

        const uint16_t* entries = reinterpret_cast<const uint16_t*>(reloc_ptr + sizeof(BaseRelocationBlock));

        for (uint32_t i = 0; i < entry_count; ++i) {
            uint16_t entry = entries[i];
            uint16_t type = entry >> 12;
            uint16_t offset = entry & 0xFFF;

            RelocationInfo reloc;
            reloc.virtual_address = ctx.image_base + page_rva + offset;
            reloc.offset = page_rva + offset;

            switch (type) {
                case 0: reloc.kind = RelocationKind::Absolute; break;      // ABSOLUTE
                case 1: reloc.kind = RelocationKind::Relative; break;      // HIGH
                case 2: reloc.kind = RelocationKind::Relative; break;      // LOW
                case 3: reloc.kind = RelocationKind::Relative; break;      // HIGHLOW (32-bit)
                case 4: reloc.kind = RelocationKind::Relative; break;      // HIGHADJ
                case 5: reloc.kind = RelocationKind::Relative; break;      // MIPS_JMPADDR
                case 6: reloc.kind = RelocationKind::Relative; break;      // MIPS_JMPADDR16
                case 7: reloc.kind = RelocationKind::Relative; break;      // MIPS_JMPADDR16
                case 8: reloc.kind = RelocationKind::Relative; break;      // MIPS_JMPADDR16
                case 9: reloc.kind = RelocationKind::Relative; break;      // MIPS_JMPADDR16
                case 10: reloc.kind = RelocationKind::Relative; break;     // DIR64 (64-bit)
                default: reloc.kind = RelocationKind::Unknown; break;
            }

            result.relocations.push_back(reloc);
        }

        reloc_ptr += block_size;
    }

    return Result<void>::ok();
}

// Parse Debug
Result<void> PEParser::parse_debug(Context& ctx, BinaryAnalysisResult& result) {
    if (ctx.directories[DIRECTORY_DEBUG].size == 0) return Result<void>::ok();

    const std::byte* debug_ptr = rva_to_raw(ctx, ctx.directories[DIRECTORY_DEBUG].virtual_address);
    if (!debug_ptr) return Result<void>::ok();

    Size debug_size = ctx.directories[DIRECTORY_DEBUG].size;
    Size entry_size = sizeof(DebugDirectory);
    Size count = debug_size / entry_size;

    for (Size i = 0; i < count; ++i) {
        const DebugDirectory* dbg = reinterpret_cast<const DebugDirectory*>(debug_ptr + i * entry_size);

        result.debug_info.has_debug_symbols = true;

        switch (dbg->type) {
            case 1: result.debug_info.debug_type = "coff"; break;
            case 2: result.debug_info.debug_type = "codeview"; break; // PDB
            case 3: result.debug_info.debug_type = "fpo"; break;
            case 4: result.debug_info.debug_type = "misra"; break;
            case 5: result.debug_info.debug_type = "excop"; break;
            case 6: result.debug_info.debug_type = "fixup"; break;
            case 7: result.debug_info.debug_type = "omap_to_src"; break;
            case 8: result.debug_info.debug_type = "omap_from_src"; break;
            case 9: result.debug_info.debug_type = "borland"; break;
            case 10: result.debug_info.debug_type = "clsid"; break;
            case 11: result.debug_info.debug_type = "vba"; break;
            case 12: result.debug_info.debug_type = "repro"; break; // Reproducible build
            case 13: result.debug_info.debug_type = "pgo"; break;
            case 14: result.debug_info.debug_type = "ils"; break;
            case 15: result.debug_info.debug_type = "spgo"; break;
            default: result.debug_info.debug_type = "unknown"; break;
        }

        // For CodeView (PDB), try to read the PDB info
        if (dbg->type == 2 && dbg->pointer_to_raw_data < ctx.size) {
            const std::byte* pdb_ptr = ctx.base + dbg->pointer_to_raw_data;
            // CodeView RSDS signature: 'RSDS' + GUID + Age + PDB path
            if (pdb_ptr + 24 < ctx.base + ctx.size) {
                uint32_t sig = read_u32(pdb_ptr);
                if (sig == 0x53445352) { // 'RSDS'
                    // Extract GUID
                    // For now just note it
                    result.debug_info.debug_directory = "PDB (CodeView RSDS)";
                } else if (sig == 0x3031424E) { // 'NB10'
                    result.debug_info.debug_directory = "PDB (CodeView NB10)";
                }
            }
        }
    }

    return Result<void>::ok();
}

// Parse TLS
Result<void> PEParser::parse_tls(Context& /*ctx*/, BinaryAnalysisResult& /*result*/) {
    // TLS parsing for completeness - callbacks are interesting for analysis
    return Result<void>::ok();
}

// Parse Load Config
Result<void> PEParser::parse_load_config(Context& /*ctx*/, BinaryAnalysisResult& /*result*/) {
    // Contains security cookie, SEH handlers, CFG info - valuable for analysis
    return Result<void>::ok();
}

// Parse Resources
Result<void> PEParser::parse_resources(Context& /*ctx*/, BinaryAnalysisResult& /*result*/) {
    // Resource directory parsing - complex, skip for now
    return Result<void>::ok();
}

// Discover Functions
Result<void> PEParser::discover_functions(Context& ctx, BinaryAnalysisResult& result) {
    // 1. Functions from exports (high confidence)
    for (const auto& exp : result.exports) {
        for (const auto& sym : exp.functions) {
            FunctionInfo fn;
            fn.address = sym.address;
            fn.name = sym.name;
            fn.architecture = result.architecture;
            fn.confidence = ConfidenceLevel::Confirmed;
            fn.source = FunctionSource::ExportTable;
            fn.has_symbol = true;
            fn.is_exported = true;
            fn.section_name = "unknown"; // Would need section lookup
            result.functions.push_back(fn);
        }
    }

    // 2. Functions from imports (thunks)
    for (const auto& imp : result.imports) {
        for (const auto& sym : imp.functions) {
            FunctionInfo fn;
            fn.address = sym.address;
            fn.name = sym.name;
            fn.architecture = result.architecture;
            fn.confidence = ConfidenceLevel::High;
            fn.source = FunctionSource::ImportThunk;
            fn.has_symbol = true;
            fn.is_imported = true;
            fn.is_thunk = true;
            result.functions.push_back(fn);
        }
    }

    // 3. Entry point
    if (result.entry_point != 0) {
        FunctionInfo fn;
        fn.address = result.entry_point;
        fn.name = "entry_point";
        fn.architecture = result.architecture;
        fn.confidence = ConfidenceLevel::Confirmed;
        fn.source = FunctionSource::EntryPoint;
        result.functions.push_back(fn);
    }

    // 4. Functions from debug symbols (if available)
    // Would require PDB parsing - skipped for now

    // 5. Heuristic: scan executable sections for function prologues
    // This is a simplified version - real implementation would use disassembly
    for (const auto& sec : result.sections) {
        if (sec.is_executable() && sec.raw_size > 0 && sec.file_offset < ctx.size) {
            // Could add heuristic discovery here
        }
    }

    return Result<void>::ok();
}

} // namespace fortress::pe