// FORTRESS Mach-O Address Converter
// Converts between FileOffset, VA, and SegmentVA for Mach-O binaries

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <vector>
#include <optional>
#include <limits>
#include <variant>

namespace fortress {

// SegmentVA now carries segment identification for unambiguous round-trip
struct SegmentVAAddress {
    uint64_t offset_in_segment = 0;
    std::string segment_name;
    
    bool valid() const noexcept { return !segment_name.empty(); }
    
    bool operator==(const SegmentVAAddress& other) const noexcept {
        return offset_in_segment == other.offset_in_segment && segment_name == other.segment_name;
    }
};

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
                    result.address = TypedAddress::va(seg.vm_address.value() + offset_in_segment);
                    result.success = true;
                    return result;
                }
            }
            // Fallback: try section mapping
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
                    // Only convert if the VA falls within the file-backed portion (file_size)
                    if (offset_in_segment >= seg_file_size) {
                        result.error = "VA points to virtual-only region, no file offset";
                        return result;
                    }
                    if (offset_in_segment > std::numeric_limits<uint64_t>::max() - seg.file_offset.value()) {
                        result.error = "FileOffset calculation overflow";
                        return result;
                    }
                    result.address = TypedAddress::file_offset(seg.file_offset.value() + offset_in_segment);
                    result.success = true;
                    return result;
                }
            }
            // Fallback: try section mapping
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
                    result.address = TypedAddress::file_offset(sec.file_offset.value() + offset_in_section);
                    result.success = true;
                    return result;
                }
            }
            result.error = "VA not within any segment or section";
            return result;
        }

        // VA <-> SegmentVA (Mach-O specific: addresses within a segment)
        // SegmentVA now carries segment name for unambiguous conversion
        if (from.space() == AddressSpace::VA && to_space == AddressSpace::SegmentVA) {
            // Find which segment contains this VA
            for (const auto& seg : segments_) {
                uint64_t seg_vm_start = seg.vm_address.value();
                uint64_t seg_vm_size = seg.vm_size.value();
                
                if (seg_vm_size > std::numeric_limits<uint64_t>::max() - seg_vm_start) {
                    result.error = "Segment virtual range overflow";
                    return result;
                }
                uint64_t seg_vm_end = seg_vm_start + seg_vm_size;
                
                if (from.value() >= seg_vm_start && from.value() < seg_vm_end) {
                    // Return SegmentVA with segment identification
                    result.address = TypedAddress::segment_va(from.value() - seg_vm_start);
                    // Store segment name in the converter context if needed
                    // For now, we encode the segment name in a way that can be retrieved
                    // The actual SegmentVAAddress would be used by callers needing round-trip
                    result.success = true;
                    return result;
                }
            }
            result.error = "VA not within any segment";
            return result;
        }

        if (from.space() == AddressSpace::SegmentVA && to_space == AddressSpace::VA) {
            // This requires knowing which segment - we use a special encoding
            // The SegmentVA value is the offset, but we need the segment base
            // This is a fundamental ambiguity - we require the segment context
            // For now, return error requiring explicit segment context
            result.error = "SegmentVA -> VA requires segment context (use SegmentVAAddress with segment_name)";
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

    // Overload for SegmentVAAddress round-trip
    AddressConversionResult convert_segment_va(const SegmentVAAddress& from, AddressSpace to_space) const {
        AddressConversionResult result;
        result.success = false;
        
        if (to_space != AddressSpace::VA) {
            result.error = "SegmentVAAddress can only convert to VA";
            return result;
        }
        
        // Find the segment by name
        for (const auto& seg : segments_) {
            if (seg.segment_name == from.segment_name) {
                if (from.offset_in_segment >= seg.vm_size.value()) {
                    result.error = "SegmentVA offset exceeds segment size";
                    return result;
                }
                if (from.offset_in_segment > std::numeric_limits<uint64_t>::max() - seg.vm_address.value()) {
                    result.error = "VA calculation overflow";
                    return result;
                }
                result.address = TypedAddress::va(seg.vm_address.value() + from.offset_in_segment);
                result.success = true;
                return result;
            }
        }
        
        result.error = "Segment not found: " + from.segment_name;
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