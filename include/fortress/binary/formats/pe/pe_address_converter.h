// FORTRESS PE Address Converter
// Converts between FileOffset, RVA, and VA for PE binaries

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <vector>
#include <optional>
#include <limits>

namespace fortress {

class PEAddressConverter : public AddressConverter {
public:
    explicit PEAddressConverter(uint64_t image_base, 
                                 const std::vector<NormalizedSection>& sections = {})
        : image_base_(image_base), sections_(sections) {}

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

        // RVA <-> VA (using image_base) with overflow check
        if (from.space() == AddressSpace::RVA && to_space == AddressSpace::VA) {
            if (image_base_ == 0) {
                result.error = "Image base not set";
                return result;
            }
            if (from.value() > std::numeric_limits<uint64_t>::max() - image_base_) {
                result.error = "RVA + ImageBase overflow";
                return result;
            }
            result.address = TypedAddress::va(from.value() + image_base_);
            result.success = true;
            return result;
        }

        if (from.space() == AddressSpace::VA && to_space == AddressSpace::RVA) {
            if (image_base_ == 0) {
                result.error = "Image base not set";
                return result;
            }
            if (from.value() < image_base_) {
                result.error = "VA below image base";
                return result;
            }
            result.address = TypedAddress::rva(from.value() - image_base_);
            result.success = true;
            return result;
        }

        // FileOffset <-> RVA (using section mapping)
        if (from.space() == AddressSpace::FileOffset && to_space == AddressSpace::RVA) {
            for (const auto& sec : sections_) {
                if (sec.contains_file_offset(from)) {
                    uint64_t offset_in_section = from.value() - sec.file_offset.value();
                    // Check if offset exceeds raw_size (file-backed data)
                    if (offset_in_section >= sec.raw_size) {
                        result.error = "File offset beyond raw data in section";
                        return result;
                    }
                    if (offset_in_section > std::numeric_limits<uint64_t>::max() - sec.rva.value()) {
                        result.error = "RVA calculation overflow";
                        return result;
                    }
                    result.address = TypedAddress::rva(sec.rva.value() + offset_in_section);
                    result.success = true;
                    return result;
                }
            }
            result.error = "File offset not within any section";
            return result;
        }

        if (from.space() == AddressSpace::RVA && to_space == AddressSpace::FileOffset) {
            for (const auto& sec : sections_) {
                // Check if RVA falls within this section's virtual range
                if (from.value() >= sec.rva.value() && 
                    from.value() < sec.rva.value() + sec.virtual_size) {
                    uint64_t offset_in_section = from.value() - sec.rva.value();
                    // Only allow conversion if the data is file-backed
                    if (offset_in_section >= sec.raw_size) {
                        result.error = "RVA points to virtual-only region (BSS/zero-filled), no file offset";
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
            result.error = "RVA not within any section";
            return result;
        }

        // FileOffset <-> VA (via RVA)
        if (from.space() == AddressSpace::FileOffset && to_space == AddressSpace::VA) {
            auto rva_result = convert(from, AddressSpace::RVA);
            if (!rva_result.success) return rva_result;
            return convert(rva_result.address, AddressSpace::VA);
        }

        if (from.space() == AddressSpace::VA && to_space == AddressSpace::FileOffset) {
            auto rva_result = convert(from, AddressSpace::RVA);
            if (!rva_result.success) return rva_result;
            return convert(rva_result.address, AddressSpace::FileOffset);
        }

        result.error = "Unsupported conversion: " + address_space_to_string(from.space()) + 
                       " -> " + address_space_to_string(to_space);
        return result;
    }

    bool can_convert(AddressSpace from, AddressSpace to) const override {
        if (from == to) return true;
        
        // RVA <-> VA always possible if image_base is set
        if ((from == AddressSpace::RVA && to == AddressSpace::VA) ||
            (from == AddressSpace::VA && to == AddressSpace::RVA)) {
            return image_base_ != 0;
        }

        // FileOffset <-> RVA possible if sections are mapped
        if ((from == AddressSpace::FileOffset && to == AddressSpace::RVA) ||
            (from == AddressSpace::RVA && to == AddressSpace::FileOffset)) {
            return !sections_.empty();
        }

        // FileOffset <-> VA possible if both above are possible
        if ((from == AddressSpace::FileOffset && to == AddressSpace::VA) ||
            (from == AddressSpace::VA && to == AddressSpace::FileOffset)) {
            return image_base_ != 0 && !sections_.empty();
        }

        return false;
    }

    std::optional<uint64_t> image_base() const override {
        return image_base_ != 0 ? std::optional<uint64_t>(image_base_) : std::nullopt;
    }

    std::vector<SegmentMapping> segments() const override {
        std::vector<SegmentMapping> result;
        for (const auto& sec : sections_) {
            SegmentMapping mapping;
            mapping.segment_name = sec.segment_name.empty() ? sec.name : sec.segment_name;
            mapping.vm_address = sec.virtual_address;
            mapping.vm_size = TypedAddress::va(sec.virtual_size);
            mapping.file_offset = sec.file_offset;
            mapping.file_size = TypedAddress::file_offset(sec.raw_size);
            result.push_back(mapping);
        }
        return result;
    }

    void set_sections(const std::vector<NormalizedSection>& sections) {
        sections_ = sections;
    }

    void set_image_base(uint64_t base) {
        image_base_ = base;
    }

private:
    uint64_t image_base_ = 0;
    std::vector<NormalizedSection> sections_;

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