// FORTRESS ELF Address Converter
// Converts between FileOffset and VA for ELF binaries

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <vector>
#include <optional>

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
            // Use program headers (segments) for mapping
            for (const auto& seg : segments_) {
                if (from.value() >= seg.file_offset.value() && 
                    from.value() < seg.file_offset.value() + seg.file_size.value()) {
                    uint64_t offset_in_segment = from.value() - seg.file_offset.value();
                    result.address = TypedAddress::va(seg.vm_address.value() + offset_in_segment);
                    result.success = true;
                    return result;
                }
            }
            // Fallback: try section headers
            for (const auto& sec : sections_) {
                if (sec.contains_file_offset(from)) {
                    uint64_t offset_in_section = from.value() - sec.file_offset.value();
                    result.address = TypedAddress::va(sec.virtual_address.value() + offset_in_section);
                    result.success = true;
                    return result;
                }
            }
            result.error = "File offset not within any segment or section";
            return result;
        }

        if (from.space() == AddressSpace::VA && to_space == AddressSpace::FileOffset) {
            // Use program headers (segments) for mapping
            for (const auto& seg : segments_) {
                if (from.value() >= seg.vm_address.value() && 
                    from.value() < seg.vm_address.value() + seg.vm_size.value()) {
                    uint64_t offset_in_segment = from.value() - seg.vm_address.value();
                    result.address = TypedAddress::file_offset(seg.file_offset.value() + offset_in_segment);
                    result.success = true;
                    return result;
                }
            }
            // Fallback: try section headers
            for (const auto& sec : sections_) {
                if (sec.contains_va(from)) {
                    uint64_t offset_in_section = from.value() - sec.virtual_address.value();
                    result.address = TypedAddress::file_offset(sec.file_offset.value() + offset_in_section);
                    result.success = true;
                    return result;
                }
            }
            result.error = "VA not within any segment or section";
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
            result.address = TypedAddress::segment_va(from.value());
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