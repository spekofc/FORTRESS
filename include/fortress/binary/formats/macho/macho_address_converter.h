// FORTRESS Mach-O Address Converter
// Converts between FileOffset, VA, and SegmentVA for Mach-O binaries

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <vector>
#include <optional>

namespace fortress {

class MachOAddressConverter : public AddressConverter {
public:
    explicit MachOAddressConverter(const std::vector<NormalizedSection>& sections = {},
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

        // Mach-O uses VA directly (like ELF)
        // FileOffset <-> VA via segment mapping (load commands)
        if (from.space() == AddressSpace::FileOffset && to_space == AddressSpace::VA) {
            for (const auto& seg : segments_) {
                if (from.value() >= seg.file_offset.value() && 
                    from.value() < seg.file_offset.value() + seg.file_size.value()) {
                    uint64_t offset_in_segment = from.value() - seg.file_offset.value();
                    result.address = TypedAddress::va(seg.vm_address.value() + offset_in_segment);
                    result.success = true;
                    return result;
                }
            }
            // Fallback: try section mapping
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
            for (const auto& seg : segments_) {
                if (from.value() >= seg.vm_address.value() && 
                    from.value() < seg.vm_address.value() + seg.vm_size.value()) {
                    uint64_t offset_in_segment = from.value() - seg.vm_address.value();
                    result.address = TypedAddress::file_offset(seg.file_offset.value() + offset_in_segment);
                    result.success = true;
                    return result;
                }
            }
            // Fallback: try section mapping
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

        // VA <-> SegmentVA (Mach-O specific: addresses within a segment)
        if (from.space() == AddressSpace::VA && to_space == AddressSpace::SegmentVA) {
            // Find which segment contains this VA
            for (const auto& seg : segments_) {
                if (from.value() >= seg.vm_address.value() && 
                    from.value() < seg.vm_address.value() + seg.vm_size.value()) {
                    // Return offset within segment
                    result.address = TypedAddress::segment_va(from.value() - seg.vm_address.value());
                    result.success = true;
                    return result;
                }
            }
            result.error = "VA not within any segment";
            return result;
        }

        if (from.space() == AddressSpace::SegmentVA && to_space == AddressSpace::VA) {
            // This is ambiguous without knowing the segment base
            // We'd need the segment base to convert
            result.error = "SegmentVA -> VA requires segment base (ambiguous)";
            return result;
        }

        // RVA not applicable for Mach-O
        if (from.space() == AddressSpace::RVA || to_space == AddressSpace::RVA) {
            result.error = "RVA not applicable for Mach-O format";
            return result;
        }

        result.error = "Unsupported conversion: " + address_space_to_string(from.space()) + 
                       " -> " + address_space_to_string(to_space);
        return result;
    }

    bool can_convert(AddressSpace from, AddressSpace to) const override {
        if (from == to) return true;
        
        // Mach-O: FileOffset <-> VA via segments/sections
        if ((from == AddressSpace::FileOffset && to == AddressSpace::VA) ||
            (from == AddressSpace::VA && to == AddressSpace::FileOffset)) {
            return !segments_.empty() || !sections_.empty();
        }

        // VA -> SegmentVA (but not reverse without segment context)
        if (from == AddressSpace::VA && to == AddressSpace::SegmentVA) {
            return !segments_.empty();
        }

        return false;
    }

    std::optional<uint64_t> image_base() const override {
        // Mach-O doesn't have ImageBase; return __TEXT segment base if available
        for (const auto& seg : segments_) {
            if (seg.segment_name == "__TEXT") {
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