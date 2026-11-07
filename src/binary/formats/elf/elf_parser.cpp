// FORTRESS ELF Parser Implementation

#include <fortress/binary/formats/elf/elf_parser.h>
#include <fortress/core/hash.h>
#include <fortress/core/string_utils.h>
#include <algorithm>
#include <cstring>

namespace fortress::elf {

// Helper: read typed value
template<typename T>
static T read_value(const std::byte* ptr) {
    T val;
    std::memcpy(&val, ptr, sizeof(T));
    return val;
}

// Byte swap helpers
static uint16_t bswap16(uint16_t x) { return (x >> 8) | (x << 8); }
static uint32_t bswap32(uint32_t x) { return (x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24); }
static uint64_t bswap64(uint64_t x) { return (x >> 56) | ((x >> 40) & 0xFF00) | ((x >> 24) & 0xFF0000) | ((x >> 8) & 0xFF000000) | ((x << 8) & 0xFF00000000) | ((x << 24) & 0xFF0000000000) | ((x << 40) & 0xFF000000000000) | (x << 56); }

template<typename T>
static T maybe_bswap(T val, bool swap) {
    if (!swap) return val;
    if constexpr (sizeof(T) == 2) return bswap16(val);
    else if constexpr (sizeof(T) == 4) return bswap32(val);
    else if constexpr (sizeof(T) == 8) return bswap64(val);
    return val;
}

// Parse entry
Result<BinaryAnalysisResult> ELFParser::parse(const FileMapping& mapping) {
    return parse(mapping.data());
}

Result<BinaryAnalysisResult> ELFParser::parse(std::span<const std::byte> data) {
    BinaryAnalysisResult result;
    result.format = BinaryFormat::ELF;
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
        result.limitations.push_back("ELF parsing completed");
        if (err) {
            result.errors.push_back(err.to_string());
            return err;
        }
        result.valid_format = true;
        return result;
    };

    // Compute hashes
    result.hashes = compute_all_hashes(data).value_or(MultiHashResult{});

    // Validate and parse header
    auto hdr_result = validate_header(ctx);
    if (!hdr_result) return finish(hdr_result.error());

    // Parse program headers
    auto ph_result = parse_program_headers(ctx);
    if (!ph_result) return finish(ph_result.error());

    // Parse section headers
    auto sh_result = parse_section_headers(ctx);
    if (!sh_result) return finish(sh_result.error());

    // Parse sections
    auto sec_result = parse_sections(ctx);
    if (!sec_result) return finish(sec_result.error());

    // Parse symbols
    parse_symbols(ctx);

    // Parse dynamic section
    parse_dynamic(ctx);

    // Parse relocations
    parse_relocations(ctx);

    // Parse notes (build ID, etc.)
    parse_notes(ctx);

    // Discover functions
    discover_functions(ctx);

    // Statistics
    result.total_sections = result.sections.size();
    result.total_symbols = result.symbols.size();
    result.total_relocations = result.relocations.size();
    result.total_functions = result.functions.size();
    result.confirmed_functions = 0;
    result.estimated_functions = 0;
    for (const auto& fn : result.functions) {
        if (fn.confidence >= ConfidenceLevel::High) result.confirmed_functions++;
        else result.estimated_functions++;
    }

    // Count imports/exports from dynamic symbols
    for (const auto& sym : result.symbols) {
        if (sym.is_imported) result.total_imports++;
        if (sym.is_exported) result.total_exports++;
    }

    return finish(Error::success());
}

// Validate Header
Result<void> ELFParser::validate_header(Context& ctx) {
    if (ctx.size < 16) {
        return Error::truncated("File too small for ELF identification");
    }

    // Check magic
    uint32_t magic = read_value<uint32_t>(ctx.base);
    if (magic != ELF_MAGIC) {
        return Error::invalid_format("Invalid ELF magic");
    }

    // Parse identification
    ctx.ei_class = ctx.base[4];
    ctx.ei_data = ctx.base[5];
    ctx.ei_osabi = ctx.base[7];

    ctx.is_64bit = (ctx.ei_class == ELFCLASS64);
    ctx.is_little_endian = (ctx.ei_data == ELFDATA2LSB);

    // Check endianness matches host for simplicity
    // In production, we'd handle both

    // Check class
    if (ctx.ei_class != ELFCLASS32 && ctx.ei_class != ELFCLASS64) {
        return Error::unsupported_arch("Unsupported ELF class: " + std::to_string(ctx.ei_class));
    }

    Size ehdr_size = ctx.is_64bit ? sizeof(Ehdr64) : sizeof(Ehdr32);
    if (ctx.size < ehdr_size) {
        return Error::truncated("ELF header truncated");
    }

    if (ctx.is_64bit) {
        ctx.ehdr64 = reinterpret_cast<const Ehdr64*>(ctx.base);
        ctx.phnum = ctx.ehdr64->e_phnum;
        ctx.shnum = ctx.ehdr64->e_shnum;
        ctx.shstrndx = ctx.ehdr64->e_shstrndx;

        result.architecture = machine_to_architecture(ctx.ehdr64->e_machine);
        result.is_64bit = true;
        result.is_32bit = false;
        result.endianness = ctx.is_little_endian ? Endianness::Little : Endianness::Big;
        result.os_abi = osabi_to_string(ctx.ei_osabi);
        result.machine_type = machine_to_string(ctx.ehdr64->e_machine);
        result.entry_point = ctx.ehdr64->e_entry;
    } else {
        ctx.ehdr32 = reinterpret_cast<const Ehdr32*>(ctx.base);
        ctx.phnum = ctx.ehdr32->e_phnum;
        ctx.shnum = ctx.ehdr32->e_shnum;
        ctx.shstrndx = ctx.ehdr32->e_shstrndx;

        result.architecture = machine_to_architecture(ctx.ehdr32->e_machine);
        result.is_64bit = false;
        result.is_32bit = true;
        result.endianness = ctx.is_little_endian ? Endianness::Little : Endianness::Big;
        result.os_abi = osabi_to_string(ctx.ei_osabi);
        result.machine_type = machine_to_string(ctx.ehdr32->e_machine);
        result.entry_point = ctx.ehdr32->e_entry;
    }

    if (ctx.phnum > 0) {
        Size phoff = ctx.is_64bit ? ctx.ehdr64->e_phoff : ctx.ehdr32->e_phoff;
        Size phentsize = ctx.is_64bit ? ctx.ehdr64->e_phentsize : ctx.ehdr32->e_phentsize;
        if (phoff + ctx.phnum * phentsize > ctx.size) {
            return Error::truncated("Program headers truncated");
        }
    }

    if (ctx.shnum > 0) {
        Size shoff = ctx.is_64bit ? ctx.ehdr64->e_shoff : ctx.ehdr32->e_shoff;
        Size shentsize = ctx.is_64bit ? ctx.ehdr64->e_shentsize : ctx.ehdr32->e_shentsize;
        if (shoff + ctx.shnum * shentsize > ctx.size) {
            ctx.warnings.push_back("Section headers truncated or beyond file end");
        }
    }

    return Result<void>::ok();
}

// Parse Program Headers
Result<void> ELFParser::parse_program_headers(Context& ctx) {
    if (ctx.phnum == 0) return Result<void>::ok();

    if (ctx.is_64bit) {
        ctx.phdrs64 = reinterpret_cast<const Phdr64*>(offset_to_ptr(ctx, ctx.ehdr64->e_phoff));
    } else {
        ctx.phdrs32 = reinterpret_cast<const Phdr32*>(offset_to_ptr(ctx, ctx.ehdr32->e_phoff));
    }
    return Result<void>::ok();
}

// Parse Section Headers
Result<void> ELFParser::parse_section_headers(Context& ctx) {
    if (ctx.shnum == 0) return Result<void>::ok();

    Size shoff = ctx.is_64bit ? ctx.ehdr64->e_shoff : ctx.ehdr32->e_shoff;
    Size shentsize = ctx.is_64bit ? ctx.ehdr64->e_shentsize : ctx.ehdr32->e_shentsize;

    if (shoff + ctx.shnum * shentsize > ctx.size) {
        ctx.warnings.push_back("Section headers extend beyond file end");
        return Result<void>::ok();
    }

    if (ctx.is_64bit) {
        ctx.shdrs64 = reinterpret_cast<const Shdr64*>(offset_to_ptr(ctx, shoff));
    } else {
        ctx.shdrs32 = reinterpret_cast<const Shdr32*>(offset_to_ptr(ctx, shoff));
    }

    // Get section header string table
    if (ctx.shstrndx < ctx.shnum) {
        if (ctx.is_64bit) {
            const auto& shstr_shdr = ctx.shdrs64[ctx.shstrndx];
            ctx.shstrtab = offset_to_ptr(ctx, shstr_shdr.sh_offset);
        } else {
            const auto& shstr_shdr = ctx.shdrs32[ctx.shstrndx];
            ctx.shstrtab = offset_to_ptr(ctx, shstr_shdr.sh_offset);
        }
    }

    return Result<void>::ok();
}

// Parse Sections
Result<void> ELFParser::parse_sections(Context& ctx) {
    if (ctx.shnum == 0) return Result<void>::ok();

    for (uint16_t i = 0; i < ctx.shnum; ++i) {
        SectionInfo info;

        if (ctx.is_64bit) {
            const auto& shdr = ctx.shdrs64[i];
            info.name = read_string(ctx, ctx.shstrtab, shdr.sh_name);
            info.virtual_address = shdr.sh_addr;
            info.virtual_size = shdr.sh_size;
            info.raw_size = (shdr.sh_type == SHT_NOBITS) ? 0 : shdr.sh_size;
            info.file_offset = (shdr.sh_type == SHT_NOBITS) ? INVALID_OFFSET : shdr.sh_offset;
            info.alignment = shdr.sh_addralign;
            info.permissions = section_flags_to_permissions(shdr.sh_flags);
            info.characteristics = section_flags_to_string(shdr.sh_flags) + " | " + section_type_to_string(shdr.sh_type);

            if (shdr.sh_type != SHT_NOBITS && shdr.sh_size > 0 && shdr.sh_offset < ctx.size) {
                auto data = std::span<const std::byte>(offset_to_ptr(ctx, shdr.sh_offset), shdr.sh_size);
                info.entropy = calculate_entropy(data);
            }
        } else {
            const auto& shdr = ctx.shdrs32[i];
            info.name = read_string(ctx, ctx.shstrtab, shdr.sh_name);
            info.virtual_address = shdr.sh_addr;
            info.virtual_size = shdr.sh_size;
            info.raw_size = (shdr.sh_type == SHT_NOBITS) ? 0 : shdr.sh_size;
            info.file_offset = (shdr.sh_type == SHT_NOBITS) ? INVALID_OFFSET : shdr.sh_offset;
            info.alignment = shdr.sh_addralign;
            info.permissions = section_flags_to_permissions(shdr.sh_flags);
            info.characteristics = section_flags_to_string(shdr.sh_flags) + " | " + section_type_to_string(shdr.sh_type);

            if (shdr.sh_type != SHT_NOBITS && shdr.sh_size > 0 && shdr.sh_offset < ctx.size) {
                auto data = std::span<const std::byte>(offset_to_ptr(ctx, shdr.sh_offset), shdr.sh_size);
                info.entropy = calculate_entropy(data);
            }
        }

        result->sections.push_back(std::move(info));
    }

    return Result<void>::ok();
}

// Parse Symbols
Result<void> ELFParser::parse_symbols(Context& ctx) {
    // Find symbol tables
    std::vector<uint16_t> symtab_indices;
    std::vector<uint16_t> strtab_indices;

    for (uint16_t i = 0; i < ctx.shnum; ++i) {
        uint32_t type = ctx.is_64bit ? ctx.shdrs64[i].sh_type : ctx.shdrs32[i].sh_type;
        if (type == SHT_SYMTAB || type == SHT_DYNSYM) {
            symtab_indices.push_back(i);
            uint32_t link = ctx.is_64bit ? ctx.shdrs64[i].sh_link : ctx.shdrs32[i].sh_link;
            strtab_indices.push_back(link);
        }
    }

    for (size_t idx = 0; idx < symtab_indices.size(); ++idx) {
        uint16_t sym_idx = symtab_indices[idx];
        uint16_t str_idx = strtab_indices[idx];

        bool is_dynsym = (ctx.is_64bit ? ctx.shdrs64[sym_idx].sh_type : ctx.shdrs32[sym_idx].sh_type) == SHT_DYNSYM;

        const std::byte* strtab = nullptr;
        if (str_idx < ctx.shnum) {
            if (ctx.is_64bit) strtab = offset_to_ptr(ctx, ctx.shdrs64[str_idx].sh_offset);
            else strtab = offset_to_ptr(ctx, ctx.shdrs32[str_idx].sh_offset);
        }

        if (!strtab) continue;

        const std::byte* symtab = nullptr;
        Size symtab_size = 0;
        Size sym_size = ctx.is_64bit ? sizeof(Sym64) : sizeof(Sym32);

        if (ctx.is_64bit) {
            symtab = offset_to_ptr(ctx, ctx.shdrs64[sym_idx].sh_offset);
            symtab_size = ctx.shdrs64[sym_idx].sh_size;
        } else {
            symtab = offset_to_ptr(ctx, ctx.shdrs32[sym_idx].sh_offset);
            symtab_size = ctx.shdrs32[sym_idx].sh_size;
        }

        Size count = symtab_size / sym_size;
        for (Size i = 0; i < count; ++i) {
            SymbolInfo sym;
            if (ctx.is_64bit) {
                const auto* s = reinterpret_cast<const Sym64*>(symtab + i * sym_size);
                sym.name = read_string(ctx, strtab, s->st_name);
                sym.address = s->st_value;
                sym.size = s->st_size;
                sym.type = symbol_type(s->st_info);
                sym.binding = symbol_binding(s->st_info);
                sym.visibility = symbol_visibility(s->st_other);
                sym.section_index = s->st_shndx;
            } else {
                const auto* s = reinterpret_cast<const Sym32*>(symtab + i * sym_size);
                sym.name = read_string(ctx, strtab, s->st_name);
                sym.address = s->st_value;
                sym.size = s->st_size;
                sym.type = symbol_type(s->st_info);
                sym.binding = symbol_binding(s->st_info);
                sym.visibility = symbol_visibility(s->st_other);
                sym.section_index = s->st_shndx;
            }

            if (sym.name.empty()) continue;
            if (sym.type == SymbolType::File) continue;

            sym.is_exported = (sym.binding == SymbolBinding::Global || sym.binding == SymbolBinding::Weak) && !is_dynsym;
            sym.is_imported = is_dynsym && (sym.binding == SymbolBinding::Global || sym.binding == SymbolBinding::Weak) && sym.section_index == 0;

            result->symbols.push_back(sym);
        }
    }

    return Result<void>::ok();
}

// Parse Dynamic Section
Result<void> ELFParser::parse_dynamic(Context& ctx) {
    // Find dynamic section
    for (uint16_t i = 0; i < ctx.shnum; ++i) {
        uint32_t type = ctx.is_64bit ? ctx.shdrs64[i].sh_type : ctx.shdrs32[i].sh_type;
        if (type == SHT_DYNAMIC) {
            const std::byte* dyn_ptr = nullptr;
            Size dyn_size = 0;
            Size dyn_ent = ctx.is_64bit ? sizeof(Dyn64) : sizeof(Dyn32);

            if (ctx.is_64bit) {
                dyn_ptr = offset_to_ptr(ctx, ctx.shdrs64[i].sh_offset);
                dyn_size = ctx.shdrs64[i].sh_size;
            } else {
                dyn_ptr = offset_to_ptr(ctx, ctx.shdrs32[i].sh_offset);
                dyn_size = ctx.shdrs32[i].sh_size;
            }

            Size count = dyn_size / dyn_ent;
            std::string soname;
            std::vector<std::string> needed;
            uint64_t strtab_addr = 0, strtab_size = 0;
            uint64_t symtab_addr = 0, syment = 0;
            uint64_t rel_addr = 0, rel_size = 0, rel_ent = 0;
            uint64_t rela_addr = 0, rela_size = 0, rela_ent = 0;
            uint64_t pltrel_addr = 0, pltrel_size = 0;
            bool bind_now = false;

            for (Size j = 0; j < count; ++j) {
                int64_t tag = 0;
                uint64_t val = 0;

                if (ctx.is_64bit) {
                    const auto* d = reinterpret_cast<const Dyn64*>(dyn_ptr + j * dyn_ent);
                    tag = d->d_tag;
                    val = d->d_val;
                } else {
                    const auto* d = reinterpret_cast<const Dyn32*>(dyn_ptr + j * dyn_ent);
                    tag = d->d_tag;
                    val = d->d_val;
                }

                switch (tag) {
                    case DT_NEEDED:
                        if (val < 0x10000) { // String table index
                            // Will resolve later
                        }
                        break;
                    case DT_STRTAB: strtab_addr = val; break;
                    case DT_STRSZ: strtab_size = val; break;
                    case DT_SYMTAB: symtab_addr = val; break;
                    case DT_SYMENT: syment = val; break;
                    case DT_REL: rel_addr = val; break;
                    case DT_RELSZ: rel_size = val; break;
                    case DT_RELENT: rel_ent = val; break;
                    case DT_RELA: rela_addr = val; break;
                    case DT_RELASZ: rela_size = val; break;
                    case DT_RELAENT: rela_ent = val; break;
                    case DT_JMPREL: pltrel_addr = val; break;
                    case DT_BIND_NOW: bind_now = true; break;
                    case DT_SONAME: soname = "soname"; break; // Would need strtab
                    case DT_RUNPATH: case DT_RPATH: break;
                    case DT_GNU_HASH: break;
                    case DT_VERSYM: break;
                    case DT_VERDEF: break;
                    case DT_VERNEED: break;
                    case DT_NULL: j = count; break;
                }
            }

            // Parse DT_NEEDED libraries
            // This requires string table - simplified for now
            break;
        }
    }

    return Result<void>::ok();
}

// Parse Relocations
Result<void> ELFParser::parse_relocations(Context& ctx) {
    for (uint16_t i = 0; i < ctx.shnum; ++i) {
        uint32_t type = ctx.is_64bit ? ctx.shdrs64[i].sh_type : ctx.shdrs32[i].sh_type;
        if (type != SHT_REL && type != SHT_RELA) continue;

        uint32_t link = ctx.is_64bit ? ctx.shdrs64[i].sh_link : ctx.shdrs32[i].sh_link;
        uint32_t info = ctx.is_64bit ? ctx.shdrs64[i].sh_info : ctx.shdrs32[i].sh_info;

        const std::byte* rel_ptr = nullptr;
        Size rel_size = 0;
        Size rel_ent = ctx.is_64bit ? (type == SHT_REL ? sizeof(Rel64) : sizeof(Rela64)) : (type == SHT_REL ? sizeof(Rel32) : sizeof(Rela32));

        if (ctx.is_64bit) {
            rel_ptr = offset_to_ptr(ctx, ctx.shdrs64[i].sh_offset);
            rel_size = ctx.shdrs64[i].sh_size;
        } else {
            rel_ptr = offset_to_ptr(ctx, ctx.shdrs32[i].sh_offset);
            rel_size = ctx.shdrs32[i].sh_size;
        }

        Size count = rel_size / rel_ent;
        for (Size j = 0; j < count; ++j) {
            RelocationInfo reloc;
            if (type == SHT_REL) {
                if (ctx.is_64bit) {
                    const auto* r = reinterpret_cast<const Rel64*>(rel_ptr + j * rel_ent);
                    reloc.virtual_address = r->r_offset;
                    reloc.offset = r->r_offset;
                    uint32_t sym = ELF64_R_SYM(r->r_info);
                    uint32_t rtype = ELF64_R_TYPE(r->r_info);
                    reloc.kind = RelocationKind::Relative; // Simplified
                    reloc.symbol_index = sym;
                    // Type would be architecture-specific
                } else {
                    const auto* r = reinterpret_cast<const Rel32*>(rel_ptr + j * rel_ent);
                    reloc.virtual_address = r->r_offset;
                    reloc.offset = r->r_offset;
                    uint32_t sym = ELF32_R_SYM(r->r_info);
                    uint32_t rtype = ELF32_R_TYPE(r->r_info);
                    reloc.kind = RelocationKind::Relative;
                    reloc.symbol_index = sym;
                }
            } else { // SHT_RELA
                if (ctx.is_64bit) {
                    const auto* r = reinterpret_cast<const Rela64*>(rel_ptr + j * rel_ent);
                    reloc.virtual_address = r->r_offset;
                    reloc.offset = r->r_offset;
                    uint32_t sym = ELF64_R_SYM(r->r_info);
                    uint32_t rtype = ELF64_R_TYPE(r->r_info);
                    reloc.kind = RelocationKind::Relative;
                    reloc.symbol_index = sym;
                    reloc.addend = r->r_addend;
                } else {
                    const auto* r = reinterpret_cast<const Rela32*>(rel_ptr + j * rel_ent);
                    reloc.virtual_address = r->r_offset;
                    reloc.offset = r->r_offset;
                    uint32_t sym = ELF32_R_SYM(r->r_info);
                    uint32_t rtype = ELF32_R_TYPE(r->r_info);
                    reloc.kind = RelocationKind::Relative;
                    reloc.symbol_index = sym;
                    reloc.addend = r->r_addend;
                }
            }

            // Resolve symbol name if possible
            if (reloc.symbol_index > 0 && reloc.symbol_index < result->symbols.size()) {
                reloc.symbol_name = result->symbols[reloc.symbol_index].name;
            }

            // Find containing section
            if (info < result->sections.size()) {
                reloc.section_name = result->sections[info].name;
            }

            result->relocations.push_back(reloc);
        }
    }

    return Result<void>::ok();
}

// Parse Notes (Build ID)
Result<void> ELFParser::parse_notes(Context& ctx) {
    for (uint16_t i = 0; i < ctx.shnum; ++i) {
        uint32_t type = ctx.is_64bit ? ctx.shdrs64[i].sh_type : ctx.shdrs32[i].sh_type;
        if (type != SHT_NOTE) continue;

        const std::byte* note_ptr = nullptr;
        Size note_size = 0;

        if (ctx.is_64bit) {
            note_ptr = offset_to_ptr(ctx, ctx.shdrs64[i].sh_offset);
            note_size = ctx.shdrs64[i].sh_size;
        } else {
            note_ptr = offset_to_ptr(ctx, ctx.shdrs32[i].sh_offset);
            note_size = ctx.shdrs32[i].sh_size;
        }

        const std::byte* end = note_ptr + note_size;
        while (note_ptr + sizeof(Note) <= end) {
            const Note* note = reinterpret_cast<const Note*>(note_ptr);
            Size namesz = (note->n_namesz + 3) & ~3;
            Size descsz = (note->n_descsz + 3) & ~3;

            if (note_ptr + sizeof(Note) + namesz + descsz > end) break;

            const char* name = reinterpret_cast<const char*>(note_ptr + sizeof(Note));

            if (note->n_type == NT_GNU_BUILD_ID && std::strncmp(name, "GNU", 4) == 0) {
                const std::byte* desc = note_ptr + sizeof(Note) + namesz;
                result->debug_info.build_id = to_hex({reinterpret_cast<const char*>(desc), static_cast<size_t>(note->n_descsz)});
                result->debug_info.has_debug_symbols = true;
            }

            note_ptr += sizeof(Note) + namesz + descsz;
        }
    }

    return Result<void>::ok();
}

// Discover Functions
Result<void> ELFParser::discover_functions(Context& ctx) {
    // 1. Functions from symbol table (STT_FUNC)
    for (const auto& sym : result->symbols) {
        if (sym.type == SymbolType::Function && sym.address != 0) {
            FunctionInfo fn;
            fn.address = sym.address;
            fn.name = sym.name;
            fn.architecture = result->architecture;
            fn.confidence = sym.binding == SymbolBinding::Global ? ConfidenceLevel::Confirmed : ConfidenceLevel::High;
            fn.source = sym.is_imported ? FunctionSource::ImportThunk : FunctionSource::SymbolTable;
            fn.has_symbol = true;
            fn.is_exported = sym.is_exported;
            fn.is_imported = sym.is_imported;

            if (sym.section_index > 0 && sym.section_index < result->sections.size()) {
                fn.section_name = result->sections[sym.section_index].name;
            }

            result->functions.push_back(fn);
        }
    }

    // 2. Entry point
    if (result->entry_point != 0) {
        FunctionInfo fn;
        fn.address = result->entry_point;
        fn.name = "_start";
        fn.architecture = result->architecture;
        fn.confidence = ConfidenceLevel::Confirmed;
        fn.source = FunctionSource::EntryPoint;
        result->functions.push_back(fn);
    }

    // 3. Init/fini arrays (from dynamic)
    // Would need dynamic section parsing

    return Result<void>::ok();
}

// Helpers
const std::byte* ELFParser::offset_to_ptr(Context& ctx, uint64_t offset) const {
    if (offset >= ctx.size) return nullptr;
    return ctx.base + offset;
}

const std::byte* ELFParser::vaddr_to_ptr(Context& ctx, uint64_t vaddr) const {
    // Find segment containing vaddr
    for (uint16_t i = 0; i < ctx.phnum; ++i) {
        uint64_t p_vaddr, p_offset, p_filesz, p_memsz;
        if (ctx.is_64bit) {
            p_vaddr = ctx.phdrs64[i].p_vaddr;
            p_offset = ctx.phdrs64[i].p_offset;
            p_filesz = ctx.phdrs64[i].p_filesz;
            p_memsz = ctx.phdrs64[i].p_memsz;
        } else {
            p_vaddr = ctx.phdrs32[i].p_vaddr;
            p_offset = ctx.phdrs32[i].p_offset;
            p_filesz = ctx.phdrs32[i].p_filesz;
            p_memsz = ctx.phdrs32[i].p_memsz;
        }

        if (vaddr >= p_vaddr && vaddr < p_vaddr + p_memsz) {
            uint64_t offset_in_seg = vaddr - p_vaddr;
            if (offset_in_seg < p_filesz && p_offset + offset_in_seg < ctx.size) {
                return ctx.base + p_offset + offset_in_seg;
            }
        }
    }
    return nullptr;
}

std::string ELFParser::read_string(Context& ctx, const std::byte* strtab, uint32_t offset) const {
    if (!strtab || offset == 0) return "";
    const std::byte* ptr = strtab + offset;
    // Find null terminator
    const std::byte* end = ctx.base + ctx.size;
    while (ptr < end && *ptr != std::byte{0}) ++ptr;
    return std::string(reinterpret_cast<const char*>(strtab + offset), ptr - (strtab + offset));
}

SectionPermission ELFParser::section_flags_to_permissions(uint64_t flags) const {
    SectionPermission perms = SectionPermission::None;
    if (flags & SHF_READ) perms = perms | SectionPermission::Read;
    if (flags & SHF_WRITE) perms = perms | SectionPermission::Write;
    if (flags & SHF_EXECINSTR) perms = perms | SectionPermission::Execute;
    return perms;
}

std::string ELFParser::section_flags_to_string(uint64_t flags) const {
    std::vector<std::string> parts;
    if (flags & SHF_WRITE) parts.push_back("WRITE");
    if (flags & SHF_ALLOC) parts.push_back("ALLOC");
    if (flags & SHF_EXECINSTR) parts.push_back("EXECINSTR");
    if (flags & SHF_MERGE) parts.push_back("MERGE");
    if (flags & SHF_STRINGS) parts.push_back("STRINGS");
    if (flags & SHF_INFO_LINK) parts.push_back("INFO_LINK");
    if (flags & SHF_LINK_ORDER) parts.push_back("LINK_ORDER");
    if (flags & SHF_GROUP) parts.push_back("GROUP");
    if (flags & SHF_TLS) parts.push_back("TLS");
    if (flags & SHF_COMPRESSED) parts.push_back("COMPRESSED");
    return join(parts, " | ");
}

std::string ELFParser::section_type_to_string(uint32_t type) const {
    switch (type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_SHLIB: return "SHLIB";
        case SHT_DYNSYM: return "DYNSYM";
        case SHT_INIT_ARRAY: return "INIT_ARRAY";
        case SHT_FINI_ARRAY: return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP: return "GROUP";
        case SHT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";
        case SHT_GNU_ATTRIBUTES: return "GNU_ATTRIBUTES";
        case SHT_GNU_HASH: return "GNU_HASH";
        case SHT_GNU_VERDEF: return "GNU_VERDEF";
        case SHT_GNU_VERNEED: return "GNU_VERNEED";
        case SHT_GNU_VERSYM: return "GNU_VERSYM";
        default: return "0x" + to_hex(std::string_view(reinterpret_cast<const char*>(&type), 4));
    }
}

SymbolBinding ELFParser::symbol_binding(uint8_t info) const {
    switch (ELF_ST_BIND(info)) {
        case STB_LOCAL: return SymbolBinding::Local;
        case STB_GLOBAL: return SymbolBinding::Global;
        case STB_WEAK: return SymbolBinding::Weak;
        case STB_GNU_UNIQUE: return SymbolBinding::Unique;
        default: return SymbolBinding::Local;
    }
}

SymbolType ELFParser::symbol_type(uint8_t info) const {
    switch (ELF_ST_TYPE(info)) {
        case STT_NOTYPE: return SymbolType::Unknown;
        case STT_FUNC: return SymbolType::Function;
        case STT_SECTION: return SymbolType::Section;
        case STT_FILE: return SymbolType::File;
        case STT_COMMON: return SymbolType::Data;
        case STT_TLS: return SymbolType::TLS;
        case STT_GNU_IFUNC: return SymbolType::IFunc;
        default: return SymbolType::Unknown;
    }
}

SymbolVisibility ELFParser::symbol_visibility(uint8_t other) const {
    switch (ELF_ST_VISIBILITY(other)) {
        case STV_DEFAULT: return SymbolVisibility::Default;
        case STV_INTERNAL: return SymbolVisibility::Internal;
        case STV_HIDDEN: return SymbolVisibility::Hidden;
        case STV_PROTECTED: return SymbolVisibility::Protected;
        default: return SymbolVisibility::Default;
    }
}

} // namespace fortress::elf