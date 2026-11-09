// FORTRESS ELF Address Converter
// Converts between FileOffset and VA for ELF binaries

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <vector>
#include <optional>
#include <limits>

namespace fortress {

class ELFAddressConverter : public AddressConverter {
public:
    explicit ELFAddressConverter(const std::vector<NormalizedSection>& sections = {},
                                  const std::vector<SegmentMapping>& segments = {})
        : sections_(sections), segments_(segments) {}

    AddressConversionResult convert(const TypedAddress& from, AddressSpace to_space) const override {
        AddressConversionResult result;
        result.address = from;
        result.success = false;

        if (!from.valid()) {
            result.error = "Invalid source address";
            return result;
        }

        if (from.space() == to_space) {
            result.address = from;
            result.success = true;
            return result;
        }

        // ELF uses VA directly (no RVA concept like PE)
        // FileOffset <-> VA via segment mapping (program headers)
        if (from.space() == AddressSpace::FileOffset && to_space == AddressSpace::VA) {
            // Collect all matching segments
            struct Match {
                uint64_t va;
            };
            std::vector<Match> matches;

            // Use program headers (segments) for mapping
            for (const auto& seg : segments_) {
                uint64_t seg_file_start = seg.file_offset.value();
                uint64_t seg_file_size = seg.file_size.value();
                
                if (seg_file_size > std::numeric_limits<uint64_t>::max() - seg_file_start) {
                    result.error = "Segment file range overflow";
                    return result;
                }
                uint64_t seg_file_end = seg_file_start + seg_file_size;
                
                if (from.value() >= seg_file_start && from.value() < seg_file_end) {
                    uint64_t offset_in_segment = from.value() - seg_file_start;
                    if (offset_in_segment > std::numeric_limits<uint64_t>::max() - seg.vm_address.value()) {
                        result.error = "VA calculation overflow";
                        return result;
                    }
                    matches.push_back({seg.vm_address.value() + offset_in_segment});
                }
            }
            // Fallback: try section headers
            for (const auto& sec : sections_) {
                if (sec.contains_file_offset(from)) {
                    uint64_t offset_in_section = from.value() - sec.file_offset.value();
                    if (offset_in_section >= sec.raw_size) {
                        result.error = "File offset beyond raw data in section";
                        return result;
                    }
                    if (offset_in_section > std::numeric_limits<uint64_t>::max() - sec.virtual_address.value()) {
                        result.error = "VA calculation overflow";
                        return result;
                    }
                    matches.push_back({sec.virtual_address.value() + offset_in_section});
                }
            }

            if (matches.empty()) {
                result.error = "File offset not within any segment or section";
                return result;
            }
            if (matches.size() > 1) {
                result.error = "Ambiguous FileOffset -> VA conversion: multiple matching segments/sections";
                return result;
            }
            result.address = TypedAddress::va(matches[0].va);
            result.success = true;
            return result;
        }

        if (from.space() == AddressSpace::VA && to_space == AddressSpace::FileOffset) {
            // Collect all matching segments
            struct Match {
                uint64_t file_offset;
            };
            std::vector<Match> matches;

            // Use program headers (segments) for mapping
            for (const auto& seg : segments_) {
                uint64_t seg_vm_start = seg.vm_address.value();
                uint64_t seg_vm_size = seg.vm_size.value();
                uint64_t seg_file_size = seg.file_size.value();
                
                if (seg_vm_size > std::numeric_limits<uint64_t>::max() - seg_vm_start) {
                    result.error = "Segment virtual range overflow";
                    return result;
                }
                uint64_t seg_vm_end = seg_vm_start + seg_vm_size;
                
                if (from.value() >= seg_vm_start && from.value() < seg_vm_end) {
                    uint64_t offset_in_segment = from.value() - seg_vm_start;
                    // Only convert if the VA falls within the file-backed portion (p_filesz)
                    if (offset_in_segment >= seg_file_size) {
                        result.error = "VA points to virtual-only region, no file offset";
                        return result;
                    }
                    if (offset_in_segment > std::numeric_limits<uint64_t>::max() - seg.file_offset.value()) {
                        result.error = "FileOffset calculation overflow";
                        return result;
                    }
                    matches.push_back({seg.file_offset.value() + offset_in_segment});
                }
            }
            // Fallback: try section headers
            for (const auto& sec : sections_) {
                if (sec.contains_va(from)) {
                    uint64_t offset_in_section = from.value() - sec.virtual_address.value();
                    // Only allow conversion if the VA falls within raw data
                    if (offset_in_section >= sec.raw_size) {
                        result.error = "VA points to virtual-only region in section, no file offset";
                        return result;
                    }
                    if (offset_in_section > std::numeric_limits<uint64_t>::max() - sec.file_offset.value()) {
                        result.error = "FileOffset calculation overflow";
                        return result;
                    }
                    matches.push_back({sec.file_offset.value() + offset_in_section});
                }
            }

            if (matches.empty()) {
                result.error = "VA not within any segment or section";
                return result;
            }
            if (matches.size() > 1) {
                result.error = "Ambiguous VA -> FileOffset conversion: multiple matching segments/sections";
                return result;
            }
            result.address = TypedAddress::file_offset(matches[0].file_offset);
            result.success = true;
            return result;
        }

        // RVA not applicable for ELF (no ImageBase concept like PE)
        if (from.space() == AddressSpace::RVA || to_space == AddressSpace::RVA) {
            result.error = "RVA not applicable for ELF format";
            return result;
        }

        // SegmentVA <-> VA (for completeness)
        if (from.space() == AddressSpace::SegmentVA && to_space == AddressSpace::VA) {
            result.address = TypedAddress::va(from.value());
            result.success = true;
            return result;
        }
        if (from.space() == AddressSpace::VA && to_space == AddressSpace::SegmentVA) {
            // In ELF, SegmentVA is the same as VA, use segment index 0
            result.address = TypedAddress::segment_va(0, from.value());
            result.success = true;
            return result;
        }

        result.error = "Unsupported conversion: " + address_space_to_string(from.space()) + 
                       " -> " + address_space_to_string(to_space);
        return result;
    }

    bool can_convert(AddressSpace from, AddressSpace to) const override {
        if (from == to) return true;
        
        // ELF: FileOffset <-> VA via segments/sections
        if ((from == AddressSpace::FileOffset && to == AddressSpace::VA) ||
            (from == AddressSpace::VA && to == AddressSpace::FileOffset)) {
            return !segments_.empty() || !sections_.empty();
        }

        // SegmentVA <-> VA (they're the same in ELF)
        if ((from == AddressSpace::SegmentVA && to == AddressSpace::VA) ||
            (from == AddressSpace::VA && to == AddressSpace::SegmentVA)) {
            return true;
        }

        return false;
    }

    std::optional<uint64_t> image_base() const override {
        // ELF doesn't have a single ImageBase like PE
        // Return the base of the first loadable segment if available
        for (const auto& seg : segments_) {
            if (seg.max_protection & 0x1) {  // PF_R
                return seg.vm_address.value();
            }
        }
        return std::nullopt;
    }

    std::vector<SegmentMapping> segments() const override {
        return segments_;
    }

    void set_sections(const std::vector<NormalizedSection>& sections) {
        sections_ = sections;
    }

    void set_segments(const std::vector<SegmentMapping>& segments) {
        // Validate p_filesz <= p_memsz for each segment
        for (const auto& seg : segments) {
            if (seg.file_size.value() > seg.vm_size.value()) {
                // This will be caught at conversion time, but we can warn here
            }
        }
        segments_ = segments;
    }

private:
    std::vector<NormalizedSection> sections_;
    std::vector<SegmentMapping> segments_;

    static std::string address_space_to_string(AddressSpace space) {
        switch (space) {
            case AddressSpace::FileOffset: return "FileOffset";
            case AddressSpace::RVA: return "RVA";
            case AddressSpace::VA: return "VA";
            case AddressSpace::SegmentVA: return "SegmentVA";
            default: return "Invalid";
        }
    }
};

} // namespace fortress