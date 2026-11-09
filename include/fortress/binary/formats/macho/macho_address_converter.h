// FORTRESS Mach-O Address Converter
// Converts between FileOffset, VA, and SegmentVA for Mach-O binaries

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <vector>
#include <optional>
#include <limits>

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
            // Collect all matching segments
            struct Match {
                uint64_t va;
                uint64_t file_offset;
            };
            std::vector<Match> matches;

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
                    matches.push_back({seg.vm_address.value() + offset_in_segment, seg.file_offset.value() + offset_in_segment});
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
                    matches.push_back({sec.virtual_address.value(), sec.file_offset.value() + offset_in_section});
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
                    matches.push_back({seg.file_offset.value() + offset_in_segment});
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

        // VA <-> SegmentVA (Mach-O specific: addresses within a segment)
        if (from.space() == AddressSpace::VA && to_space == AddressSpace::SegmentVA) {
            // Find which segment contains this VA
            size_t matching_segment = segments_.size();
            
            for (size_t i = 0; i < segments_.size(); ++i) {
                const auto& seg = segments_[i];
                uint64_t seg_vm_start = seg.vm_address.value();
                uint64_t seg_vm_size = seg.vm_size.value();
                
                if (seg_vm_size > std::numeric_limits<uint64_t>::max() - seg_vm_start) {
                    result.error = "Segment virtual range overflow";
                    return result;
                }
                uint64_t seg_vm_end = seg_vm_start + seg_vm_size;
                
                if (from.value() >= seg_vm_start && from.value() < seg_vm_end) {
                    if (matching_segment != segments_.size()) {
                        result.error = "Ambiguous VA -> SegmentVA conversion: VA falls in multiple segments";
                        return result;
                    }
                    matching_segment = i;
                    // offset_in_segment will be computed in make_segment_va
                }
            }
            
            if (matching_segment == segments_.size()) {
                result.error = "VA not within any segment";
                return result;
            }
            
            // Return SegmentVA with segment index encoded
            auto seg_va_result = TypedAddress::make_segment_va(static_cast<uint16_t>(matching_segment), 
                                                                from.value() - segments_[matching_segment].vm_address.value());
            if (!seg_va_result) {
                result.error = seg_va_result.error().to_string();
                return result;
            }
            result.address = seg_va_result.value();
            result.success = true;
            return result;
        }

        if (from.space() == AddressSpace::SegmentVA && to_space == AddressSpace::VA) {
            // Decode segment index and offset from SegmentVA
            uint16_t segment_index = from.segment_index();
            uint64_t offset_in_segment = from.segment_offset();
            
            if (segment_index >= segments_.size()) {
                result.error = "Invalid segment index: " + std::to_string(segment_index);
                return result;
            }
            
            const auto& seg = segments_[segment_index];
            if (offset_in_segment >= seg.vm_size.value()) {
                result.error = "SegmentVA offset exceeds segment size";
                return result;
            }
            if (offset_in_segment > std::numeric_limits<uint64_t>::max() - segments_[segment_index].vm_address.value()) {
                result.error = "VA calculation overflow";
                return result;
            }
            result.address = TypedAddress::va(segments_[segment_index].vm_address.value() + offset_in_segment);
            result.success = true;
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

        // VA <-> SegmentVA (bidirectional now)
        if ((from == AddressSpace::VA && to == AddressSpace::SegmentVA) ||
            (from == AddressSpace::SegmentVA && to == AddressSpace::VA)) {
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