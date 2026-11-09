// FORTRESS Mach-O Parser Implementation

#include <fortress/binary/formats/macho/macho_parser.h>
#include <fortress/core/hash.h>
#include <fortress/core/string_utils.h>
#include <algorithm>
#include <cstring>

namespace fortress::macho {

// Helper: read typed value
template<typename T>
static T read_value(const std::byte* ptr) {
    T val;
    std::memcpy(&val, ptr, sizeof(T));
    return val;
}

// Byte swap
static uint32_t bswap32(uint32_t x) { return (x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24); }
static uint64_t bswap64(uint64_t x) { return (x >> 56) | ((x >> 40) & 0xFF00) | ((x >> 24) & 0xFF0000) | ((x >> 8) & 0xFF000000) | ((x << 8) & 0xFF00000000) | ((x << 24) & 0xFF0000000000) | ((x << 40) & 0xFF000000000000) | (x << 56); }

template<typename T>
static T maybe_bswap(T val, bool swap) {
    if (!swap) return val;
    if constexpr (sizeof(T) == 4) return bswap32(val);
    else if constexpr (sizeof(T) == 8) return bswap64(val);
    return val;
}

// Parse entry
Result<BinaryAnalysisResult> MachOParser::parse(const FileMapping& mapping) {
    return parse(mapping.data());
}

Result<BinaryAnalysisResult> MachOParser::parse(std::span<const std::byte> data) {
    BinaryAnalysisResult result;
    result.format = BinaryFormat::MachO;
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
        result.limitations.push_back("Mach-O parsing completed");
        if (err) {
            result.errors.push_back(err.to_string());
            return err;
        }
        result.valid_format = true;
        return result;
    };

    // Compute hashes
    result.hashes = compute_all_hashes(data).value_or(MultiHashResult{});

    // Check for fat binary
    if (ctx.size >= sizeof(FatHeader)) {
        uint32_t magic = read_value<uint32_t>(ctx.base);
        if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
            ctx.is_fat = true;
            ctx.is_little_endian = (magic == FAT_MAGIC);
            auto fat_result = parse_fat_header(ctx);
            if (!fat_result) return finish(fat_result.error());

            fat_result = parse_fat_archs(ctx);
            if (!fat_result) return finish(fat_result.error());

            // Select best architecture (prefer 64-bit, then ARM64, then x64)
            auto select_result = select_architecture(ctx);
            if (!select_result) return finish(select_result.error());
        }
    }

    // Validate header
    auto hdr_result = validate_header(ctx);
    if (!hdr_result) return finish(hdr_result.error());

    // Parse load commands
    auto lc_result = parse_load_commands(ctx);
    if (!lc_result) return finish(lc_result.error());

    // Parse segments
    auto seg_result = parse_segments(ctx);
    if (!seg_result) return finish(seg_result.error());

    // Parse sections
    auto sec_result = parse_sections(ctx);
    if (!sec_result) return finish(sec_result.error());

    // Parse symbols
    parse_symbols(ctx);

    // Parse dynamic libraries
    parse_dynamic_libraries(ctx);

    // Parse function starts
    parse_function_starts(ctx);

    // Parse UUID
    parse_uuid(ctx);

    // Parse entry point
    parse_entry_point(ctx);

    // Parse code signature
    parse_code_signature(ctx);

    // Parse build version
    parse_build_version(ctx);

    // Discover functions
    discover_functions(ctx);

    // Statistics
    ctx.result->total_sections = ctx.result->sections.size();
    ctx.result->total_symbols = ctx.result->symbols.size();
    ctx.result->total_functions = ctx.result->functions.size();
    ctx.result->confirmed_functions = 0;
    ctx.result->estimated_functions = 0;
    for (const auto& fn : ctx.result->functions) {
        if (fn.confidence >= ConfidenceLevel::High) ctx.result->confirmed_functions++;
        else ctx.result->estimated_functions++;
    }

    for (const auto& sym : ctx.result->symbols) {
        if (sym.is_imported) ctx.result->total_imports++;
        if (sym.is_exported) ctx.result->total_exports++;
    }

    return finish(Error::success());
}

// Fat Header
Result<void> MachOParser::parse_fat_header(Context& ctx) {
    if (ctx.size < sizeof(FatHeader)) {
        return Error::truncated("Fat header truncated");
    }

    const FatHeader* fat = reinterpret_cast<const FatHeader*>(ctx.base);
    uint32_t nfat_arch = maybe_bswap(fat->nfat_arch, !ctx.is_little_endian);

    if (nfat_arch == 0 || nfat_arch > 20) {
        return Error::invalid_format("Invalid number of fat architectures");
    }

    if (ctx.size < sizeof(FatHeader) + nfat_arch * sizeof(FatArch)) {
        return Error::truncated("Fat architectures truncated");
    }

    return Result<void>::ok();
}

// Fat Architectures
Result<void> MachOParser::parse_fat_archs(Context& ctx) {
    const FatHeader* fat = reinterpret_cast<const FatHeader*>(ctx.base);
    uint32_t nfat_arch = maybe_bswap(fat->nfat_arch, !ctx.is_little_endian);

    const FatArch* archs = reinterpret_cast<const FatArch*>(ctx.base + sizeof(FatHeader));

    struct FatArchInfo {
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t offset;
        uint32_t size;
        uint32_t align;
        Architecture arch;
    };

    std::vector<FatArchInfo> arch_infos;
    for (uint32_t i = 0; i < nfat_arch; ++i) {
        FatArchInfo info;
        info.cputype = maybe_bswap(archs[i].cputype, !ctx.is_little_endian);
        info.cpusubtype = maybe_bswap(archs[i].cpusubtype, !ctx.is_little_endian);
        info.offset = maybe_bswap(archs[i].offset, !ctx.is_little_endian);
        info.size = maybe_bswap(archs[i].size, !ctx.is_little_endian);
        info.align = maybe_bswap(archs[i].align, !ctx.is_little_endian);
        info.arch = cputype_to_architecture(info.cputype, info.cpusubtype);
        arch_infos.push_back(info);

        // Store in warnings for reference
        ctx.warnings.push_back("Fat architecture: " + std::to_string(info.cputype) + " offset=0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&info.offset), 4)));
    }

    return Result<void>::ok();
}

// Select Architecture
Result<void> MachOParser::select_architecture(Context& ctx, Architecture target) {
    if (!ctx.is_fat) return Result<void>::ok();

    // For now, just use the first one
    // In production, would select based on target/preference
    const FatHeader* fat = reinterpret_cast<const FatHeader*>(ctx.base);
    uint32_t nfat_arch = maybe_bswap(fat->nfat_arch, !ctx.is_little_endian);
    const FatArch* archs = reinterpret_cast<const FatArch*>(ctx.base + sizeof(FatHeader));

    // Prefer 64-bit, then ARM64, then x64
    int best_idx = -1;
    Architecture best_arch = Architecture::Unknown;

    for (uint32_t i = 0; i < nfat_arch; ++i) {
        uint32_t cputype = maybe_bswap(archs[i].cputype, !ctx.is_little_endian);
        uint32_t cpusubtype = maybe_bswap(archs[i].cpusubtype, !ctx.is_little_endian);
        Architecture arch = cputype_to_architecture(cputype, cpusubtype);

        if (target != Architecture::Unknown && arch == target) {
            best_idx = static_cast<int>(i);
            break;
        }

        // Prefer 64-bit
        bool is_64 = (cputype & 0x01000000u) != 0;
        if (is_64 && (best_arch == Architecture::Unknown || (best_arch != Architecture::ARM64 && best_arch != Architecture::X64))) {
            best_idx = static_cast<int>(i);
            best_arch = arch;
        } else if (!is_64 && best_idx == -1) {
            best_idx = static_cast<int>(i);
            best_arch = arch;
        }
    }

    if (best_idx == -1) {
        return Error::unsupported_arch("No suitable architecture in fat binary");
    }

    uint32_t offset = maybe_bswap(archs[static_cast<size_t>(best_idx)].offset, !ctx.is_little_endian);
    uint32_t size = maybe_bswap(archs[static_cast<size_t>(best_idx)].size, !ctx.is_little_endian);

    if (offset + size > ctx.size) {
        return Error::truncated("Selected architecture extends beyond file");
    }

    ctx.fat_offset = offset;
    ctx.base = ctx.base + offset;
    ctx.size = size;

    return Result<void>::ok();
}

// Validate Header
Result<void> MachOParser::validate_header(Context& ctx) {
    if (ctx.size < sizeof(uint32_t)) {
        return Error::truncated("File too small for Mach-O header");
    }

    uint32_t magic = read_value<uint32_t>(ctx.base);
    bool swapped = false;

    if (magic == MH_MAGIC || magic == MH_MAGIC_64) {
        ctx.is_little_endian = true;
    } else if (magic == MH_CIGAM || magic == MH_CIGAM_64) {
        ctx.is_little_endian = false;
        swapped = true;
    } else {
        return Error::invalid_format("Invalid Mach-O magic: 0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&magic), 4)));
    }

    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        ctx.is_64bit = false;
        if (ctx.size < sizeof(MachHeader)) {
            return Error::truncated("Mach-O header truncated");
        }
        ctx.header = reinterpret_cast<const MachHeader*>(ctx.base);
    } else {
        ctx.is_64bit = true;
        if (ctx.size < sizeof(MachHeader64)) {
            return Error::truncated("Mach-O 64-bit header truncated");
        }
        ctx.header64 = reinterpret_cast<const MachHeader64*>(ctx.base);
    }

    // Swap if needed
    if (swapped) {
        // Would need to swap header fields - for now assume little endian
        ctx.warnings.push_back("Big-endian Mach-O detected, limited support");
    }

    // Parse header info
    if (ctx.is_64bit) {
        ctx.result->architecture = cputype_to_architecture(ctx.header64->cputype, ctx.header64->cpusubtype);
        ctx.result->is_64bit = true;
        ctx.result->is_32bit = false;
        ctx.result->endianness = ctx.is_little_endian ? Endianness::Little : Endianness::Big;
        ctx.result->os_abi = "macos";
        ctx.result->machine_type = cputype_to_string(ctx.header64->cputype, ctx.header64->cpusubtype);
        ctx.result->entry_point = 0; // Will be set from LC_MAIN or LC_UNIXTHREAD
    } else {
        ctx.result->architecture = cputype_to_architecture(ctx.header->cputype, ctx.header->cpusubtype);
        ctx.result->is_64bit = false;
        ctx.result->is_32bit = true;
        ctx.result->endianness = ctx.is_little_endian ? Endianness::Little : Endianness::Big;
        ctx.result->os_abi = "macos";
        ctx.result->machine_type = cputype_to_string(ctx.header->cputype, ctx.header->cpusubtype);
        ctx.result->entry_point = 0;
    }

    return Result<void>::ok();
}

// Parse Load Commands
Result<void> MachOParser::parse_load_commands(Context& ctx) {
    const std::byte* lc_ptr = nullptr;
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;

    if (ctx.is_64bit) {
        lc_ptr = ctx.base + sizeof(MachHeader64);
        ncmds = ctx.header64->ncmds;
        sizeofcmds = ctx.header64->sizeofcmds;
    } else {
        lc_ptr = ctx.base + sizeof(MachHeader);
        ncmds = ctx.header->ncmds;
        sizeofcmds = ctx.header->sizeofcmds;
    }

    if (sizeofcmds > ctx.size) {
        ctx.warnings.push_back("Load commands size exceeds file size");
        sizeofcmds = static_cast<uint32_t>(ctx.size);
    }

    const std::byte* end = lc_ptr + sizeofcmds;
    ctx.load_commands = reinterpret_cast<const LoadCommand*>(lc_ptr);

    for (uint32_t i = 0; i < ncmds && lc_ptr < end; ++i) {
        // Read directly from byte stream to avoid struct layout issues
        uint32_t raw_cmd = read_value<uint32_t>(lc_ptr);
        uint32_t raw_cmdsize = read_value<uint32_t>(lc_ptr + 4);
        uint32_t cmd = maybe_bswap(raw_cmd, !ctx.is_little_endian);
        uint32_t cmdsize = maybe_bswap(raw_cmdsize, !ctx.is_little_endian);

        if (cmdsize < sizeof(LoadCommand) || lc_ptr + cmdsize > end) {
            ctx.warnings.push_back("Invalid load command size at index " + std::to_string(i));
            break;
        }

        switch (cmd & 0x7FFFFFFF) { // Ignore LC_REQ_DYLD bit
            case (LC_SEGMENT & 0x7FFFFFFF): {
                if (ctx.is_64bit) {
                    ctx.warnings.push_back("LC_SEGMENT in 64-bit Mach-O");
                } else {
                    ctx.segments32.push_back(reinterpret_cast<const SegmentCommand*>(lc_ptr));
                }
                break;
            }
            case (LC_SEGMENT_64 & 0x7FFFFFFF): {
                if (!ctx.is_64bit) {
                    ctx.warnings.push_back("LC_SEGMENT_64 in 32-bit Mach-O");
                } else {
                    ctx.segments64.push_back(reinterpret_cast<const SegmentCommand64*>(lc_ptr));
                }
                break;
            }
            case (LC_SYMTAB & 0x7FFFFFFF): {
                ctx.symtab = reinterpret_cast<const SymtabCommand*>(lc_ptr);
                break;
            }
            case (LC_DYSYMTAB & 0x7FFFFFFF): {
                ctx.dysymtab = reinterpret_cast<const DysymtabCommand*>(lc_ptr);
                break;
            }
            case (LC_LOAD_DYLIB & 0x7FFFFFFF):
            case (LC_ID_DYLIB & 0x7FFFFFFF):
            case (LC_LOAD_WEAK_DYLIB & 0x7FFFFFFF):
            case (LC_REEXPORT_DYLIB & 0x7FFFFFFF):
            case (LC_LOAD_UPWARD_DYLIB & 0x7FFFFFFF): {
                ctx.dylibs.push_back(reinterpret_cast<const DylibCommand*>(lc_ptr));
                break;
            }
            case (LC_LOAD_DYLINKER & 0x7FFFFFFF):
            case (LC_ID_DYLINKER & 0x7FFFFFFF): {
                // Dylinker info
                break;
            }
            case (LC_UUID & 0x7FFFFFFF): {
                ctx.uuid_cmd = reinterpret_cast<const UuidCommand*>(lc_ptr);
                break;
            }
            case (LC_MAIN & 0x7FFFFFFF): {
                ctx.warnings.push_back("Found LC_MAIN command");
                ctx.main_cmd = reinterpret_cast<const MainCommand*>(lc_ptr);
                break;
            }
            case (LC_UNIXTHREAD & 0x7FFFFFFF):
            case (LC_THREAD & 0x7FFFFFFF): {
                ctx.thread_cmd = reinterpret_cast<const ThreadCommand*>(lc_ptr);
                break;
            }
            case (LC_RPATH & 0x7FFFFFFF): {
                const DylibCommand* rpath = reinterpret_cast<const DylibCommand*>(lc_ptr);
                uint32_t name_off = maybe_bswap(rpath->dylib_name_offset, !ctx.is_little_endian);
                const std::byte* name_ptr = lc_ptr + name_off;
                ctx.rpaths.push_back(read_cstring(name_ptr));
                break;
            }
            case (LC_FUNCTION_STARTS & 0x7FFFFFFF): {
                ctx.func_starts = reinterpret_cast<const FunctionStartsCommand*>(lc_ptr);
                break;
            }
            case (LC_DATA_IN_CODE & 0x7FFFFFFF): {
                ctx.data_in_code = reinterpret_cast<const DataInCodeCommand*>(lc_ptr);
                break;
            }
            case (LC_CODE_SIGNATURE & 0x7FFFFFFF): {
                ctx.code_sig = reinterpret_cast<const LinkeditDataCommand*>(lc_ptr);
                break;
            }
            case (LC_DYLD_INFO & 0x7FFFFFFF): {
                ctx.dyld_info = reinterpret_cast<const LinkeditDataCommand*>(lc_ptr);
                break;
            }
            case (LC_DYLD_CHAINED_FIXUPS & 0x7FFFFFFF): {
                ctx.chained_fixups = reinterpret_cast<const LinkeditDataCommand*>(lc_ptr);
                break;
            }
            case (LC_BUILD_VERSION & 0x7FFFFFFF): {
                ctx.build_version = reinterpret_cast<const BuildVersionCommand*>(lc_ptr);
                break;
            }
            case (LC_SEGMENT_SPLIT_INFO & 0x7FFFFFFF):
            case (LC_LINKER_OPTION & 0x7FFFFFFF):
            case (LC_LINKER_OPTIMIZATION_HINT & 0x7FFFFFFF):
            case (LC_SOURCE_VERSION & 0x7FFFFFFF):
            case (LC_DYLIB_CODE_SIGN_DRS & 0x7FFFFFFF):
            case (LC_ENCRYPTION_INFO & 0x7FFFFFFF):
            case (LC_ENCRYPTION_INFO_64 & 0x7FFFFFFF):
            case (LC_VERSION_MIN_MACOSX & 0x7FFFFFFF):
            case (LC_VERSION_MIN_IPHONEOS & 0x7FFFFFFF):
            case (LC_VERSION_MIN_TVOS & 0x7FFFFFFF):
            case (LC_VERSION_MIN_WATCHOS & 0x7FFFFFFF):
            case (LC_NOTE & 0x7FFFFFFF):
            case (LC_DYLD_EXPORTS_TRIE & 0x7FFFFFFF):
            case (LC_DYLD_ENVIRONMENT & 0x7FFFFFFF):
            case (LC_ROUTINES & 0x7FFFFFFF):
            case (LC_ROUTINES_64 & 0x7FFFFFFF):
            case (LC_PREBOUND_DYLIB & 0x7FFFFFFF):
            case LC_TWOLEVEL_HINTS:
            case LC_PREBIND_CKSUM:
            case LC_SUB_FRAMEWORK:
            case LC_SUB_UMBRELLA:
            case LC_SUB_CLIENT:
            case LC_SUB_LIBRARY:
            case LC_IDENT:
            case LC_PREPAGE:
            case (LC_LOADFVMLIB & 0x7FFFFFFF):
            case (LC_IDFVMLIB & 0x7FFFFFFF):
            case (LC_FVMFILE & 0x7FFFFFFF):
            default:
                // Ignore unknown
                break;
        }

        lc_ptr += cmdsize;
    }

    return Result<void>::ok();
}

// Parse Segments
Result<void> MachOParser::parse_segments(Context& /*ctx*/) {
    // Already collected in parse_load_commands
    return Result<void>::ok();
}

// Parse Sections
Result<void> MachOParser::parse_sections(Context& ctx) {
    if (ctx.is_64bit) {
        for (const auto* seg : ctx.segments64) {
            if (seg->nsects == 0) continue;
            const Section64* sects = reinterpret_cast<const Section64*>(
                reinterpret_cast<const std::byte*>(seg) + sizeof(SegmentCommand64)
            );

            for (uint32_t i = 0; i < seg->nsects; ++i) {
                const auto& sect = sects[i];
                SectionInfo info;
                info.name = segment_name(sect.sectname) + "," + segment_name(sect.segname);
                info.virtual_address = sect.addr;
                info.virtual_size = sect.size;
                info.raw_size = (sect.flags & S_ZEROFILL) ? 0 : sect.size;
                info.file_offset = (sect.flags & S_ZEROFILL) ? INVALID_OFFSET : sect.offset;
                info.alignment = 1ull << sect.align;
                info.permissions = section_flags_to_permissions(sect.flags, sect.flags & 0xFF);
                info.characteristics = section_type_to_string(sect.flags & 0xFF);

                if (!(sect.flags & S_ZEROFILL) && sect.size > 0 && sect.offset < ctx.size) {
                    auto data = std::span<const std::byte>(ctx.base + sect.offset, sect.size);
                    info.entropy = calculate_entropy(data);
                }

                ctx.sections64.push_back(&sect);
                ctx.result->sections.push_back(std::move(info));
            }
        }
    } else {
        for (const auto* seg : ctx.segments32) {
            if (seg->nsects == 0) continue;
            const Section* sects = reinterpret_cast<const Section*>(
                reinterpret_cast<const std::byte*>(seg) + sizeof(SegmentCommand)
            );

            for (uint32_t i = 0; i < seg->nsects; ++i) {
                const auto& sect = sects[i];
                SectionInfo info;
                info.name = segment_name(sect.sectname) + "," + segment_name(sect.segname);
                info.virtual_address = sect.addr;
                info.virtual_size = sect.size;
                info.raw_size = (sect.flags & S_ZEROFILL) ? 0 : sect.size;
                info.file_offset = (sect.flags & S_ZEROFILL) ? INVALID_OFFSET : sect.offset;
                info.alignment = 1ull << sect.align;
                info.permissions = section_flags_to_permissions(sect.flags, sect.flags & 0xFF);
                info.characteristics = section_type_to_string(sect.flags & 0xFF);

                if (!(sect.flags & S_ZEROFILL) && sect.size > 0 && sect.offset < ctx.size) {
                    auto data = std::span<const std::byte>(ctx.base + sect.offset, sect.size);
                    info.entropy = calculate_entropy(data);
                }

                ctx.sections32.push_back(&sect);
                ctx.result->sections.push_back(std::move(info));
            }
        }
    }

    return Result<void>::ok();
}

// Parse Symbols
Result<void> MachOParser::parse_symbols(Context& ctx) {
    if (!ctx.symtab) return Result<void>::ok();

    uint32_t symoff = maybe_bswap(ctx.symtab->symoff, !ctx.is_little_endian);
    uint32_t nsyms = maybe_bswap(ctx.symtab->nsyms, !ctx.is_little_endian);
    uint32_t stroff = maybe_bswap(ctx.symtab->stroff, !ctx.is_little_endian);
    uint32_t strsize = maybe_bswap(ctx.symtab->strsize, !ctx.is_little_endian);

    if (symoff + nsyms * (ctx.is_64bit ? sizeof(Nlist64) : sizeof(Nlist)) > ctx.size ||
        stroff + strsize > ctx.size) {
        ctx.warnings.push_back("Symbol table truncated");
        return Result<void>::ok();
    }

    ctx.symtab_data = ctx.base + symoff;
    ctx.strtab_data = ctx.base + stroff;

    // Indirect symbol table (for imports/exports)
    if (ctx.dysymtab) {
        uint32_t indirectoff = maybe_bswap(ctx.dysymtab->indirectsymoff, !ctx.is_little_endian);
        if (indirectoff < ctx.size) {
            ctx.indirect_symtab = ctx.base + indirectoff;
        }
    }

    Size sym_size = ctx.is_64bit ? sizeof(Nlist64) : sizeof(Nlist);

    for (uint32_t i = 0; i < nsyms; ++i) {
        SymbolInfo sym;
        if (ctx.is_64bit) {
            const auto* n = reinterpret_cast<const Nlist64*>(ctx.symtab_data + i * sym_size);
            uint32_t strx = maybe_bswap(n->n_strx, !ctx.is_little_endian);
            uint64_t value = maybe_bswap(n->n_value, !ctx.is_little_endian);

            if (strx < strsize) {
                sym.name = read_string(ctx, ctx.strtab_data, strx);
            }
            sym.address = value;
            sym.section_index = n->n_sect;

            uint8_t type = n->n_type & N_TYPE;
            if (type == N_SECT) {
                sym.type = SymbolType::Function; // Assume function in section
            } else if (type == N_ABS) {
                sym.type = SymbolType::Data;
            } else if (type == N_UNDF) {
                sym.type = SymbolType::Function;
                sym.is_imported = true;
            }

            if (n->n_type & N_EXT) {
                sym.binding = SymbolBinding::Global;
            } else {
                sym.binding = SymbolBinding::Local;
            }

            // Check if it's an external reference
            if (ctx.dysymtab && (n->n_type & N_TYPE) == N_UNDF && (n->n_type & N_EXT)) {
                sym.is_imported = true;
            }
        } else {
            const auto* n = reinterpret_cast<const Nlist*>(ctx.symtab_data + i * sym_size);
            uint32_t strx = maybe_bswap(n->n_strx, !ctx.is_little_endian);
            uint32_t value = maybe_bswap(n->n_value, !ctx.is_little_endian);

            if (strx < strsize) {
                sym.name = read_string(ctx, ctx.strtab_data, strx);
            }
            sym.address = value;
            sym.section_index = n->n_sect;

            uint8_t type = n->n_type & N_TYPE;
            if (type == N_SECT) {
                sym.type = SymbolType::Function;
            } else if (type == N_ABS) {
                sym.type = SymbolType::Data;
            } else if (type == N_UNDF) {
                sym.type = SymbolType::Function;
                sym.is_imported = true;
            }

            if (n->n_type & N_EXT) {
                sym.binding = SymbolBinding::Global;
            } else {
                sym.binding = SymbolBinding::Local;
            }

            if (ctx.dysymtab && (n->n_type & N_TYPE) == N_UNDF && (n->n_type & N_EXT)) {
                sym.is_imported = true;
            }
        }

        if (!sym.name.empty() && sym.name[0] != '\0') {
            sym.is_exported = (sym.binding == SymbolBinding::Global) && !sym.is_imported;
            ctx.result->symbols.push_back(sym);
        }
    }

    return Result<void>::ok();
}

// Parse Dynamic Libraries
Result<void> MachOParser::parse_dynamic_libraries(Context& ctx) {
    for (const auto* dylib : ctx.dylibs) {
        ImportInfo imp;
        uint32_t name_off = maybe_bswap(dylib->dylib_name_offset, !ctx.is_little_endian);
        const std::byte* name_ptr = reinterpret_cast<const std::byte*>(dylib) + name_off;
        imp.library_name = read_cstring(name_ptr);

        // Would need to parse imports from dyld info or indirect symbol table
        ctx.result->imports.push_back(std::move(imp));
    }

    return Result<void>::ok();
}

// Parse Function Starts
Result<void> MachOParser::parse_function_starts(Context& ctx) {
    if (!ctx.func_starts) return Result<void>::ok();

    uint32_t dataoff = maybe_bswap(ctx.func_starts->dataoff, !ctx.is_little_endian);
    uint32_t datasize = maybe_bswap(ctx.func_starts->datasize, !ctx.is_little_endian);

    if (dataoff + datasize > ctx.size) return Result<void>::ok();

    const std::byte* data = ctx.base + dataoff;
    const std::byte* end = data + datasize;

    // Function starts are ULEB128 encoded offsets
    uint64_t addr = ctx.result->entry_point != 0 ? ctx.result->entry_point : 0;
    // Find __TEXT segment base
    for (const auto* seg : ctx.segments64) {
        if (std::string_view(seg->segname, 16).find("__TEXT") == 0) {
            addr = seg->vmaddr;
            break;
        }
    }
    for (const auto* seg : ctx.segments32) {
        if (std::string_view(seg->segname, 16).find("__TEXT") == 0) {
            addr = seg->vmaddr;
            break;
        }
    }

    while (data < end) {
        uint64_t offset = 0;
        int shift = 0;
        while (data < end) {
            uint8_t byte = static_cast<uint8_t>(*data++);
            offset |= uint64_t(byte & 0x7F) << shift;
            if ((byte & 0x80) == 0) break;
            shift += 7;
            if (shift > 63) break;
        }
        if (offset == 0) break;

        addr += offset;

        FunctionInfo fn;
        fn.address = addr;
        fn.name = "func_" + to_hex(std::string_view(reinterpret_cast<const char*>(&addr), 8));
        fn.architecture = ctx.result->architecture;
        fn.confidence = ConfidenceLevel::Medium;
        fn.source = FunctionSource::Heuristic;
        fn.section_name = "__text";
        ctx.result->functions.push_back(fn);
    }

    return Result<void>::ok();
}

// Parse UUID
Result<void> MachOParser::parse_uuid(Context& ctx) {
    if (!ctx.uuid_cmd) return Result<void>::ok();

    std::string uuid;
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) uuid += "-";
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02X", ctx.uuid_cmd->uuid[i]);
        uuid += buf;
    }
    ctx.result->debug_info.build_id = uuid;
    ctx.result->debug_info.has_debug_symbols = true;

    return Result<void>::ok();
}

// Parse Entry Point
Result<void> MachOParser::parse_entry_point(Context& ctx) {
    if (ctx.main_cmd) {
        uint64_t entryoff = maybe_bswap(ctx.main_cmd->entryoff, !ctx.is_little_endian);
        // Entry is offset from start of __TEXT
        for (const auto* seg : ctx.segments64) {
            std::string_view segname(seg->segname, 16);
            if (segname.find("__TEXT") == 0) {
                ctx.result->entry_point = seg->vmaddr + entryoff;
                ctx.result->entry_point_offset = seg->fileoff + entryoff;
                // Set image_base to __TEXT segment base for address conversion
                ctx.result->image_base = seg->vmaddr;
                break;
            }
        }
        for (const auto* seg : ctx.segments32) {
            std::string_view segname(seg->segname, 16);
            if (segname.find("__TEXT") == 0) {
                ctx.result->entry_point = seg->vmaddr + entryoff;
                ctx.result->entry_point_offset = seg->fileoff + entryoff;
                // Set image_base to __TEXT segment base for address conversion
                ctx.result->image_base = seg->vmaddr;
                break;
            }
        }
    } else if (ctx.thread_cmd) {
        // Would need to parse thread state for entry point
        ctx.warnings.push_back("LC_UNIXTHREAD entry point parsing not implemented");
    }

    return Result<void>::ok();
}

// Parse Code Signature
Result<void> MachOParser::parse_code_signature(Context& ctx) {
    if (!ctx.code_sig) return Result<void>::ok();
    ctx.result->debug_info.debug_type = "code_signature";
    return Result<void>::ok();
}

// Parse Build Version
Result<void> MachOParser::parse_build_version(Context& ctx) {
    if (!ctx.build_version) return Result<void>::ok();
    // Contains platform, minos, sdk versions
    return Result<void>::ok();
}

// Discover Functions
Result<void> MachOParser::discover_functions(Context& ctx) {
    // 1. Functions from symbol table
    for (const auto& sym : ctx.result->symbols) {
        if (sym.type == SymbolType::Function && sym.address != 0) {
            FunctionInfo fn;
            fn.address = sym.address;
            fn.name = sym.name;
            fn.architecture = ctx.result->architecture;
            fn.confidence = sym.binding == SymbolBinding::Global ? ConfidenceLevel::Confirmed : ConfidenceLevel::High;
            fn.source = sym.is_imported ? FunctionSource::ImportThunk : FunctionSource::SymbolTable;
            fn.has_symbol = true;
            fn.is_exported = sym.is_exported;
            fn.is_imported = sym.is_imported;

            if (sym.section_index > 0 && sym.section_index < ctx.result->sections.size()) {
                fn.section_name = ctx.result->sections[sym.section_index].name;
            }

            ctx.result->functions.push_back(fn);
        }
    }

    // 2. Entry point
    if (ctx.result->entry_point != 0) {
        // Check if there's already a function at the entry point address
        bool has_entry_func = false;
        for (auto& fn : ctx.result->functions) {
            if (fn.address == ctx.result->entry_point) {
                has_entry_func = true;
                // Upgrade source to EntryPoint if it was from symbol table
                if (fn.source == FunctionSource::SymbolTable || fn.source == FunctionSource::ImportThunk) {
                    fn.source = FunctionSource::EntryPoint;
                    fn.confidence = ConfidenceLevel::Confirmed;
                    fn.name = "main";
                }
                break;
            }
        }
        if (!has_entry_func) {
            FunctionInfo fn;
            fn.address = ctx.result->entry_point;
            fn.name = "main";
            fn.architecture = ctx.result->architecture;
            fn.confidence = ConfidenceLevel::Confirmed;
            fn.source = FunctionSource::EntryPoint;
            ctx.result->functions.push_back(fn);
        }
    }

    return Result<void>::ok();
}

// Helpers
const std::byte* MachOParser::offset_to_ptr(Context& ctx, uint64_t offset) const {
    if (offset >= ctx.size) return nullptr;
    return ctx.base + offset;
}

const std::byte* MachOParser::vaddr_to_ptr(Context& ctx, uint64_t vaddr) const {
    for (const auto* seg : ctx.segments64) {
        if (vaddr >= seg->vmaddr && vaddr < seg->vmaddr + seg->vmsize) {
            uint64_t offset = vaddr - seg->vmaddr;
            if (offset < seg->filesize && seg->fileoff + offset < ctx.size) {
                return ctx.base + seg->fileoff + offset;
            }
        }
    }
    for (const auto* seg : ctx.segments32) {
        if (vaddr >= seg->vmaddr && vaddr < seg->vmaddr + seg->vmsize) {
            uint64_t offset = vaddr - seg->vmaddr;
            if (offset < seg->filesize && seg->fileoff + offset < ctx.size) {
                return ctx.base + seg->fileoff + offset;
            }
        }
    }
    return nullptr;
}

std::string MachOParser::read_string(Context& ctx, const std::byte* strtab, uint32_t offset) const {
    if (!strtab || offset == 0) return "";
    const std::byte* ptr = strtab + offset;
    const std::byte* end = ctx.base + ctx.size;
    while (ptr < end && *ptr != std::byte{0}) ++ptr;
    return std::string(reinterpret_cast<const char*>(strtab + offset), static_cast<size_t>(ptr - (strtab + offset)));
}

std::string MachOParser::read_cstring(const std::byte* ptr, Size max_len) const {
    std::string result;
    for (Size i = 0; i < max_len; ++i) {
        char c = static_cast<char>(ptr[i]);
        if (c == '\0') break;
        result.push_back(c);
    }
    return result;
}

std::string MachOParser::segment_name(const char* name) const {
    std::string result;
    for (int i = 0; i < 16 && name[i]; ++i) {
        if (name[i] != '\0') result.push_back(name[i]);
    }
    return result;
}

SectionPermission MachOParser::section_flags_to_permissions(uint32_t flags, uint32_t type) const {
    SectionPermission perms = SectionPermission::None;
    if (flags & S_ATTR_PURE_INSTRUCTIONS) perms = perms | SectionPermission::Execute;
    if (flags & S_ATTR_SOME_INSTRUCTIONS) perms = perms | SectionPermission::Execute;
    if (!(flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))) {
        // Data section
        perms = perms | SectionPermission::Read;
        if (type != S_ZEROFILL && type != S_GB_ZEROFILL) {
            perms = perms | SectionPermission::Write;
        }
    }
    return perms;
}

std::string MachOParser::section_type_to_string(uint32_t type) const {
    switch (type) {
        case S_REGULAR: return "REGULAR";
        case S_ZEROFILL: return "ZEROFILL";
        case S_CSTRING_LITERALS: return "CSTRING_LITERALS";
        case S_4BYTE_LITERALS: return "4BYTE_LITERALS";
        case S_8BYTE_LITERALS: return "8BYTE_LITERALS";
        case S_LITERAL_POINTERS: return "LITERAL_POINTERS";
        case S_NON_LAZY_SYMBOL_POINTERS: return "NON_LAZY_SYMBOL_POINTERS";
        case S_LAZY_SYMBOL_POINTERS: return "LAZY_SYMBOL_POINTERS";
        case S_SYMBOL_STUBS: return "SYMBOL_STUBS";
        case S_MOD_INIT_FUNC_POINTERS: return "MOD_INIT_FUNC_POINTERS";
        case S_MOD_TERM_FUNC_POINTERS: return "MOD_TERM_FUNC_POINTERS";
        case S_COALESCED: return "COALESCED";
        case S_GB_ZEROFILL: return "GB_ZEROFILL";
        case S_INTERPOSING: return "INTERPOSING";
        case S_16BYTE_LITERALS: return "16BYTE_LITERALS";
        case S_DTRACE_DOF: return "DTRACE_DOF";
        case S_LAZY_DYLIB_SYMBOL_POINTERS: return "LAZY_DYLIB_SYMBOL_POINTERS";
        case S_THREAD_LOCAL_REGULAR: return "THREAD_LOCAL_REGULAR";
        case S_THREAD_LOCAL_ZEROFILL: return "THREAD_LOCAL_ZEROFILL";
        case S_THREAD_LOCAL_VARIABLES: return "THREAD_LOCAL_VARIABLES";
        case S_THREAD_LOCAL_VARIABLE_POINTERS: return "THREAD_LOCAL_VARIABLE_POINTERS";
        case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: return "THREAD_LOCAL_INIT_FUNCTION_POINTERS";
        default: return "0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&type), 4));
    }
}

} // namespace fortress::macho