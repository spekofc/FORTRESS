// FORTRESS String Analyzer Implementation
// String extraction and analysis with XREF integration

#include <fortress/binary/analysis/string_analyzer.h>
#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/xref.h>
#include <fortress/core/types.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <cctype>

namespace fortress {

// ============================================================================
// StringAnalyzer Implementation
// ============================================================================

StringAnalyzer::StringAnalyzer(const StringAnalyzerConfig& config)
    : config_(config), result_(), stats_() {}

Result<StringAnalysisResult> StringAnalyzer::analyze_strings(const BinaryAnalysisResult& analysis) {
    return analyze_strings(analysis, nullptr, nullptr);
}

Result<StringAnalysisResult> StringAnalyzer::analyze_strings(const BinaryAnalysisResult& analysis,
                                                             const XRefDatabase* xref_db,
                                                             const std::vector<FunctionInfo>* functions) {
    // Reset state
    result_ = StringAnalysisResult{};
    result_.config = config_;
    stats_ = StringAnalyzerStats{};
    result_.strings.clear();
    
    // Extract strings from each enabled encoding
    if (config_.extract_ascii) {
        auto res = extract_ascii_strings(analysis);
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    if (config_.extract_utf8) {
        auto res = extract_utf8_strings(analysis);
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    if (config_.extract_utf16_le) {
        auto res = extract_utf16_strings(analysis, true);
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    if (config_.extract_utf16_be) {
        auto res = extract_utf16_strings(analysis, false);
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    if (config_.extract_pascal) {
        auto res = extract_pascal_strings(analysis);
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    // Integrate XREFs if provided
    if (xref_db) {
        auto res = integrate_xrefs(xref_db, functions);
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    // Deduplicate if enabled
    if (config_.deduplicate) {
        auto res = deduplicate_strings();
        if (!res) return Result<StringAnalysisResult>::err(res.error());
    }
    
    // Calculate confidence for each string
    for (auto& str : result_.strings) {
        calculate_confidence(str);
    }
    
    // Filter by reference type if requested
    if (config_.only_referenced) {
        result_.strings.erase(
            std::remove_if(result_.strings.begin(), result_.strings.end(),
                [](const StringInfo& s) { 
                    return s.ref_type == StringReferenceType::No_Reference; 
                }),
            result_.strings.end());
    }
    
    // Update stats
    stats_.total_strings = result_.strings.size();
    for (const auto& str : result_.strings) {
        stats_.total_bytes += str.byte_length;
        switch (str.encoding) {
            case StringEncoding::ASCII: stats_.ascii_strings++; break;
            case StringEncoding::UTF8: stats_.utf8_strings++; break;
            case StringEncoding::UTF16_LE: stats_.utf16_le_strings++; break;
            case StringEncoding::UTF16_BE: stats_.utf16_be_strings++; break;
            default: break;
        }
        if (str.type == StringType::Pascal_String) stats_.pascal_strings++;
        
        if (str.ref_type != StringReferenceType::No_Reference) {
            stats_.referenced_strings++;
        } else {
            stats_.unreferenced_strings++;
        }
    }
    result_.stats = stats_;
    
    return Result<StringAnalysisResult>::ok(result_);
}

// ============================================================================
// Query Methods
// ============================================================================

Result<StringQueryResult> StringAnalyzer::query_by_content(const std::string& pattern,
                                                            bool case_sensitive,
                                                            size_t limit,
                                                            size_t offset) const {
    StringQueryResult result;
    
    for (const auto& str : result_.strings) {
        if (result.strings.size() >= offset + limit) break;
        
        bool match = false;
        if (case_sensitive) {
            match = str.content.find(pattern) != std::string::npos;
        } else {
            std::string lower_content = str.content;
            std::string lower_pattern = pattern;
            std::transform(lower_content.begin(), lower_content.end(), lower_content.begin(), ::tolower);
            std::transform(lower_pattern.begin(), lower_pattern.end(), lower_pattern.begin(), ::tolower);
            match = lower_content.find(lower_pattern) != std::string::npos;
        }
        
        if (match && result.strings.size() >= offset) {
            result.strings.push_back(str);
        }
    }
    
    result.total_count = result.strings.size();
    result.truncated = result.strings.size() >= limit;
    return Result<StringQueryResult>::ok(result);
}

Result<StringQueryResult> StringAnalyzer::query_by_address(TypedAddress address,
                                                            size_t limit) const {
    StringQueryResult result;
    
    for (const auto& str : result_.strings) {
        if (str.address == address) {
            result.strings.push_back(str);
            break;
        }
        if (result.strings.size() >= limit) break;
    }
    
    result.total_count = result.strings.size();
    return Result<StringQueryResult>::ok(result);
}

Result<StringQueryResult> StringAnalyzer::query_by_encoding(StringEncoding encoding,
                                                             size_t limit,
                                                             size_t offset) const {
    StringQueryResult result;
    
    for (const auto& str : result_.strings) {
        if (str.encoding == encoding) {
            if (result.strings.size() >= offset + limit) break;
            if (result.strings.size() >= offset) {
                result.strings.push_back(str);
            }
        }
    }
    
    result.total_count = result.strings.size();
    result.truncated = result.strings.size() >= limit;
    return Result<StringQueryResult>::ok(result);
}

Result<StringQueryResult> StringAnalyzer::query_by_reference_type(StringReferenceType ref_type,
                                                                   size_t limit,
                                                                   size_t offset) const {
    StringQueryResult result;
    
    for (const auto& str : result_.strings) {
        if (str.ref_type == ref_type) {
            if (result.strings.size() >= offset + limit) break;
            if (result.strings.size() >= offset) {
                result.strings.push_back(str);
            }
        }
    }
    
    result.total_count = result.strings.size();
    result.truncated = result.strings.size() >= limit;
    return Result<StringQueryResult>::ok(result);
}

Result<StringQueryResult> StringAnalyzer::query_by_section(const std::string& section_name,
                                                            size_t limit,
                                                            size_t offset) const {
    StringQueryResult result;
    
    for (const auto& str : result_.strings) {
        if (str.section_name == section_name) {
            if (result.strings.size() >= offset + limit) break;
            if (result.strings.size() >= offset) {
                result.strings.push_back(str);
            }
        }
    }
    
    result.total_count = result.strings.size();
    result.truncated = result.strings.size() >= limit;
    return Result<StringQueryResult>::ok(result);
}

Result<StringQueryResult> StringAnalyzer::query_referenced_only(size_t limit,
                                                                 size_t offset) const {
    return query_by_reference_type(StringReferenceType::Code_Reference, limit, offset);
}

Result<StringQueryResult> StringAnalyzer::query_unreferenced_only(size_t limit,
                                                                   size_t offset) const {
    return query_by_reference_type(StringReferenceType::No_Reference, limit, offset);
}

Result<StringQueryResult> StringAnalyzer::get_all_strings(size_t limit,
                                                           size_t offset) const {
    StringQueryResult result;
    
    for (size_t i = offset; i < result_.strings.size() && result.strings.size() < limit; ++i) {
        result.strings.push_back(result_.strings[i]);
    }
    
    result.total_count = result_.strings.size();
    result.truncated = (offset + limit) < result_.strings.size();
    return Result<StringQueryResult>::ok(result);
}

// ============================================================================
// Export
// ============================================================================

Result<std::string> StringAnalyzer::export_json(bool pretty) const {
    std::ostringstream oss;
    if (pretty) {
        oss << "{\n";
        oss << "  \"strings\": [\n";
        for (size_t i = 0; i < result_.strings.size(); ++i) {
            const auto& s = result_.strings[i];
            oss << "    {\n";
            oss << "      \"address\": \"" << std::hex << s.address.value() << "\",\n";
            oss << "      \"file_offset\": " << std::dec << s.file_offset << ",\n";
            oss << "      \"encoding\": " << static_cast<int>(s.encoding) << ",\n";
            oss << "      \"type\": " << static_cast<int>(s.type) << ",\n";
            oss << "      \"content\": \"" << s.content << "\",\n";
            oss << "      \"length\": " << s.length << ",\n";
            oss << "      \"byte_length\": " << s.byte_length << ",\n";
            oss << "      \"null_terminated\": " << (s.null_terminated ? "true" : "false") << ",\n";
            oss << "      \"ref_type\": " << static_cast<int>(s.ref_type) << ",\n";
            oss << "      \"section\": \"" << s.section_name << "\",\n";
            oss << "      \"confidence\": " << static_cast<int>(s.confidence) << ",\n";
            oss << "      \"confidence_breakdown\": \"" << s.confidence_breakdown << "\"\n";
            oss << "    }" << (i + 1 < result_.strings.size() ? "," : "") << "\n";
        }
        oss << "  ],\n";
        oss << "  \"stats\": {\n";
        oss << "    \"total_strings\": " << stats_.total_strings << ",\n";
        oss << "    \"ascii_strings\": " << stats_.ascii_strings << ",\n";
        oss << "    \"utf8_strings\": " << stats_.utf8_strings << ",\n";
        oss << "    \"utf16_le_strings\": " << stats_.utf16_le_strings << ",\n";
        oss << "    \"utf16_be_strings\": " << stats_.utf16_be_strings << ",\n";
        oss << "    \"pascal_strings\": " << stats_.pascal_strings << ",\n";
        oss << "    \"referenced_strings\": " << stats_.referenced_strings << ",\n";
        oss << "    \"unreferenced_strings\": " << stats_.unreferenced_strings << ",\n";
        oss << "    \"duplicated_strings\": " << stats_.duplicated_strings << ",\n";
        oss << "    \"total_bytes\": " << stats_.total_bytes << "\n";
        oss << "  }\n";
        oss << "}\n";
    } else {
        // Compact JSON
        oss << "{\"strings\":[";
        for (size_t i = 0; i < result_.strings.size(); ++i) {
            const auto& s = result_.strings[i];
            oss << "{\"address\":\"" << std::hex << s.address.value() << "\",";
            oss << "\"file_offset\":" << std::dec << s.file_offset << ",";
            oss << "\"encoding\":" << static_cast<int>(s.encoding) << ",";
            oss << "\"type\":" << static_cast<int>(s.type) << ",";
            oss << "\"content\":\"" << s.content << "\",";
            oss << "\"length\":" << s.length << ",";
            oss << "\"byte_length\":" << s.byte_length << ",";
            oss << "\"null_terminated\":" << (s.null_terminated ? "true" : "false") << ",";
            oss << "\"ref_type\":" << static_cast<int>(s.ref_type) << ",";
            oss << "\"section\":\"" << s.section_name << "\",";
            oss << "\"confidence\":" << static_cast<int>(s.confidence) << ",";
            oss << "\"confidence_breakdown\":\"" << s.confidence_breakdown << "\"}";
            if (i + 1 < result_.strings.size()) oss << ",";
        }
        oss << "],\"stats\":{";
        oss << "\"total_strings\":" << stats_.total_strings << ",";
        oss << "\"ascii_strings\":" << stats_.ascii_strings << ",";
        oss << "\"utf8_strings\":" << stats_.utf8_strings << ",";
        oss << "\"utf16_le_strings\":" << stats_.utf16_le_strings << ",";
        oss << "\"utf16_be_strings\":" << stats_.utf16_be_strings << ",";
        oss << "\"pascal_strings\":" << stats_.pascal_strings << ",";
        oss << "\"referenced_strings\":" << stats_.referenced_strings << ",";
        oss << "\"unreferenced_strings\":" << stats_.unreferenced_strings << ",";
        oss << "\"duplicated_strings\":" << stats_.duplicated_strings << ",";
        oss << "\"total_bytes\":" << stats_.total_bytes;
        oss << "}}";
    }
    return Result<std::string>::ok(oss.str());
}

Result<std::string> StringAnalyzer::export_json(const StringQueryResult& query, bool pretty) const {
    std::ostringstream oss;
    if (pretty) {
        oss << "{\n";
        oss << "  \"strings\": [\n";
        for (size_t i = 0; i < query.strings.size(); ++i) {
            const auto& s = query.strings[i];
            oss << "    {\n";
            oss << "      \"address\": \"" << std::hex << s.address.value() << "\",\n";
            oss << "      \"file_offset\": " << std::dec << s.file_offset << ",\n";
            oss << "      \"encoding\": " << static_cast<int>(s.encoding) << ",\n";
            oss << "      \"type\": " << static_cast<int>(s.type) << ",\n";
            oss << "      \"content\": \"" << s.content << "\",\n";
            oss << "      \"length\": " << s.length << ",\n";
            oss << "      \"byte_length\": " << s.byte_length << ",\n";
            oss << "      \"null_terminated\": " << (s.null_terminated ? "true" : "false") << ",\n";
            oss << "      \"ref_type\": " << static_cast<int>(s.ref_type) << ",\n";
            oss << "      \"section\": \"" << s.section_name << "\",\n";
            oss << "      \"confidence\": " << static_cast<int>(s.confidence) << ",\n";
            oss << "      \"confidence_breakdown\": \"" << s.confidence_breakdown << "\"\n";
            oss << "    }" << (i + 1 < query.strings.size() ? "," : "") << "\n";
        }
        oss << "  ],\n";
        oss << "  \"total_count\": " << query.total_count << ",\n";
        oss << "  \"truncated\": " << (query.truncated ? "true" : "false") << "\n";
        oss << "}\n";
    } else {
        oss << "{\"strings\":[";
        for (size_t i = 0; i < query.strings.size(); ++i) {
            const auto& s = query.strings[i];
            oss << "{\"address\":\"" << std::hex << s.address.value() << "\",";
            oss << "\"file_offset\":" << std::dec << s.file_offset << ",";
            oss << "\"encoding\":" << static_cast<int>(s.encoding) << ",";
            oss << "\"type\":" << static_cast<int>(s.type) << ",";
            oss << "\"content\":\"" << s.content << "\",";
            oss << "\"length\":" << s.length << ",";
            oss << "\"byte_length\":" << s.byte_length << ",";
            oss << "\"null_terminated\":" << (s.null_terminated ? "true" : "false") << ",";
            oss << "\"ref_type\":" << static_cast<int>(s.ref_type) << ",";
            oss << "\"section\":\"" << s.section_name << "\",";
            oss << "\"confidence\":" << static_cast<int>(s.confidence) << ",";
            oss << "\"confidence_breakdown\":\"" << s.confidence_breakdown << "\"}";
            if (i + 1 < query.strings.size()) oss << ",";
        }
        oss << "],\"total_count\":" << query.total_count << ",\"truncated\":" 
            << (query.truncated ? "true" : "false") << "}";
    }
    return Result<std::string>::ok(oss.str());
}

// ============================================================================
// Internal Extraction Methods
// ============================================================================

std::vector<uint8_t> StringAnalyzer::extract_section_bytes(const BinaryAnalysisResult& /*analysis*/,
                                                           const SectionInfo& /*section*/) const {
    // In a real implementation, this would read from the binary file
    // For now, return empty - the actual bytes would come from the binary parser
    return {};
}

Result<void> StringAnalyzer::extract_ascii_strings(const BinaryAnalysisResult& analysis) {
    for (const auto& section : analysis.sections) {
        if (!is_section_targeted(section.name) || is_section_excluded(section.name)) {
            continue;
        }
        
        // Only analyze readable sections
        if (!has_permission(section.permissions, SectionPermission::Read)) continue;
        
        // Get section bytes - in real implementation, read from binary
        auto section_bytes = extract_section_bytes(analysis, section);
        if (section_bytes.empty()) {
            continue;
        }
        
        size_t i = 0;
        while (i < section_bytes.size()) {
            size_t length = 0;
            bool null_terminated = false;
            if (is_valid_ascii(section_bytes, length)) {
                if (length >= config_.min_length && length <= config_.max_length) {
                    std::vector<uint8_t> str_bytes(section_bytes.begin() + i, 
                                                   section_bytes.begin() + i + length);
                    
                    StringInfo str;
                    str.address = TypedAddress::va(section.virtual_address + i);
                    str.file_offset = section.file_offset + i;
                    str.encoding = StringEncoding::ASCII;
                    str.type = StringType::ASCII_String;
                    str.raw_bytes = str_bytes;
                    str.byte_length = length;
                    str.length = length;
                    str.content = decode_ascii(str_bytes);
                    null_terminated = (i + length < section_bytes.size() && section_bytes[i + length] == 0);
                    str.null_terminated = null_terminated;
                    str.section_name = section.name;
                    
                    result_.strings.push_back(str);
                }
                i += length + (null_terminated ? 1 : 0);
            } else {
                i++;
            }
        }
    }
    return Result<void>::ok();
}

Result<void> StringAnalyzer::extract_utf8_strings(const BinaryAnalysisResult& analysis) {
    for (const auto& section : analysis.sections) {
        if (!is_section_targeted(section.name) || is_section_excluded(section.name)) {
            continue;
        }
        if (!has_permission(section.permissions, SectionPermission::Read)) continue;
        
        auto section_bytes = extract_section_bytes(analysis, section);
        if (section_bytes.empty()) continue;
        
        size_t i = 0;
        while (i < section_bytes.size()) {
            size_t length = 0;
            bool null_terminated = false;
            if (is_valid_utf8(section_bytes, length)) {
                if (length >= config_.min_length && length <= config_.max_length) {
                    std::vector<uint8_t> str_bytes(section_bytes.begin() + i, 
                                                   section_bytes.begin() + i + length);
                    
                    StringInfo str;
                    str.address = TypedAddress::va(section.virtual_address + i);
                    str.file_offset = section.file_offset + i;
                    str.encoding = StringEncoding::UTF8;
                    str.type = StringType::UTF8_String;
                    str.raw_bytes = str_bytes;
                    str.byte_length = length;
                    str.content = decode_utf8(str_bytes);
                    str.length = 0;
                    for (size_t j = 0; j < str_bytes.size();) {
                        uint8_t c = str_bytes[j];
                        if ((c & 0x80) == 0x00) j += 1;
                        else if ((c & 0xE0) == 0xC0) j += 2;
                        else if ((c & 0xF0) == 0xE0) j += 3;
                        else if ((c & 0xF8) == 0xF0) j += 4;
                        else j += 1;
                        str.length++;
                    }
                    null_terminated = (i + length < section_bytes.size() && section_bytes[i + length] == 0);
                    str.null_terminated = null_terminated;
                    str.section_name = section.name;
                    
                    result_.strings.push_back(str);
                }
                i += length + (null_terminated ? 1 : 0);
            } else {
                i++;
            }
        }
    }
    return Result<void>::ok();
}

Result<void> StringAnalyzer::extract_utf16_strings(const BinaryAnalysisResult& analysis, 
                                                    bool little_endian) {
    for (const auto& section : analysis.sections) {
        if (!is_section_targeted(section.name) || is_section_excluded(section.name)) {
            continue;
        }
        if (!has_permission(section.permissions, SectionPermission::Read)) continue;
        
        auto section_bytes = extract_section_bytes(analysis, section);
        if (section_bytes.empty()) continue;
        
        if (section_bytes.size() < 2) continue;
        
        size_t i = 0;
        while (i + 1 < section_bytes.size()) {
            size_t length = 0;
            bool null_terminated = false;
            if (little_endian ? is_valid_utf16_le(section_bytes, length) 
                              : is_valid_utf16_be(section_bytes, length)) {
                if (length >= config_.min_length && length <= config_.max_length) {
                    std::vector<uint8_t> str_bytes(section_bytes.begin() + i, 
                                                   section_bytes.begin() + i + length);
                    
                    StringInfo str;
                    str.address = TypedAddress::va(section.virtual_address + i);
                    str.file_offset = section.file_offset + i;
                    str.encoding = little_endian ? StringEncoding::UTF16_LE : StringEncoding::UTF16_BE;
                    str.type = little_endian ? StringType::UTF16_LE_String : StringType::UTF16_BE_String;
                    str.raw_bytes = str_bytes;
                    str.byte_length = length;
                    str.content = little_endian ? decode_utf16_le(str_bytes) : decode_utf16_be(str_bytes);
                    str.length = length / 2;
                    null_terminated = (i + length + 1 < section_bytes.size() && 
                                           section_bytes[i + length] == 0 && 
                                           section_bytes[i + length + 1] == 0);
                    str.null_terminated = null_terminated;
                    str.section_name = section.name;
                    
                    result_.strings.push_back(str);
                }
                i += length + (null_terminated ? 2 : 0);
            } else {
                i += 2;
            }
        }
    }
    return Result<void>::ok();
}

Result<void> StringAnalyzer::extract_pascal_strings(const BinaryAnalysisResult& analysis) {
    for (const auto& section : analysis.sections) {
        if (!is_section_targeted(section.name) || is_section_excluded(section.name)) {
            continue;
        }
        if (!has_permission(section.permissions, SectionPermission::Read)) continue;
        
        auto section_bytes = extract_section_bytes(analysis, section);
        if (section_bytes.empty()) continue;
        
        size_t i = 0;
        while (i < section_bytes.size()) {
            uint8_t length_byte = section_bytes[i];
            size_t length = length_byte;
            
            if (length >= config_.min_length && length <= config_.max_length && 
                i + 1 + length <= section_bytes.size()) {
                
                bool valid = true;
                for (size_t j = 1; j <= length; ++j) {
                    if (section_bytes[i + j] < 0x20 || section_bytes[i + j] > 0x7E) {
                        valid = false;
                        break;
                    }
                }
                
                if (valid) {
                    std::vector<uint8_t> str_bytes(section_bytes.begin() + i + 1, 
                                                   section_bytes.begin() + i + 1 + length);
                    
                    StringInfo str;
                    str.address = TypedAddress::va(section.virtual_address + i);
                    str.file_offset = section.file_offset + i;
                    str.encoding = StringEncoding::ASCII;
                    str.type = StringType::Pascal_String;
                    str.raw_bytes = str_bytes;
                    str.byte_length = length + 1;
                    str.length = length;
                    str.content = decode_ascii(str_bytes);
                    str.null_terminated = false;
                    str.section_name = section.name;
                    
                    result_.strings.push_back(str);
                    
                    i += 1 + length;
                    continue;
                }
            }
            i++;
        }
    }
    return Result<void>::ok();
}

// ============================================================================
// Validation Methods
// ============================================================================

bool StringAnalyzer::is_valid_ascii(const std::vector<uint8_t>& bytes, size_t& length) {
    length = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t c = bytes[i];
        if (c >= 0x20 && c <= 0x7E) {
            length++;
        } else if (c == 0) {
            return length >= config_.min_length;
        } else {
            return false;
        }
    }
    return length >= config_.min_length;
}

bool StringAnalyzer::is_valid_utf8(const std::vector<uint8_t>& bytes, size_t& length) {
    length = 0;
    size_t i = 0;
    while (i < bytes.size()) {
        uint8_t c = bytes[i];
        if ((c & 0x80) == 0x00) {
            if (c >= 0x20 || c == '\t' || c == '\n' || c == '\r') {
                length++;
                i++;
            } else if (c == 0) {
                return length >= config_.min_length;
            } else {
                return false;
            }
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= bytes.size()) return false;
            if ((bytes[i + 1] & 0xC0) != 0x80) return false;
            length += 2;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= bytes.size()) return false;
            if ((bytes[i + 1] & 0xC0) != 0x80) return false;
            if ((bytes[i + 2] & 0xC0) != 0x80) return false;
            length += 3;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= bytes.size()) return false;
            if ((bytes[i + 1] & 0xC0) != 0x80) return false;
            if ((bytes[i + 2] & 0xC0) != 0x80) return false;
            if ((bytes[i + 3] & 0xC0) != 0x80) return false;
            length += 4;
            i += 4;
        } else {
            return false;
        }
        
        if (length > config_.max_length) return false;
    }
    return length >= config_.min_length;
}

bool StringAnalyzer::is_valid_utf16_le(const std::vector<uint8_t>& bytes, size_t& length) {
    length = 0;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        uint16_t c = bytes[i] | (bytes[i + 1] << 8);
        if (c == 0) {
            return length >= config_.min_length * 2;
        }
        if ((c >= 0x20 && c <= 0xD7FF) || (c >= 0xE000 && c <= 0xFFFD)) {
            length += 2;
        } else if (c == 0x0009 || c == 0x000A || c == 0x000D) {
            length += 2;
        } else {
            return false;
        }
        if (length > config_.max_length * 2) return false;
    }
    return length >= config_.min_length * 2;
}

bool StringAnalyzer::is_valid_utf16_be(const std::vector<uint8_t>& bytes, size_t& length) {
    length = 0;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        uint16_t c = (bytes[i] << 8) | bytes[i + 1];
        if (c == 0) {
            return length >= config_.min_length * 2;
        }
        if ((c >= 0x20 && c <= 0xD7FF) || (c >= 0xE000 && c <= 0xFFFD)) {
            length += 2;
        } else if (c == 0x0009 || c == 0x000A || c == 0x000D) {
            length += 2;
        } else {
            return false;
        }
        if (length > config_.max_length * 2) return false;
    }
    return length >= config_.min_length * 2;
}

// ============================================================================
// Decoding Methods
// ============================================================================

std::string StringAnalyzer::decode_ascii(const std::vector<uint8_t>& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string StringAnalyzer::decode_utf8(const std::vector<uint8_t>& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string StringAnalyzer::decode_utf16_le(const std::vector<uint8_t>& bytes) {
    std::string result;
    result.reserve(bytes.size() / 2);
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        uint16_t c = bytes[i] | (bytes[i + 1] << 8);
        if (c == 0) break;
        if (c <= 0x7F) {
            result.push_back(static_cast<char>(c));
        } else if (c <= 0x7FF) {
            result.push_back(static_cast<char>(0xC0 | (c >> 6)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (c >> 12)));
            result.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return result;
}

std::string StringAnalyzer::decode_utf16_be(const std::vector<uint8_t>& bytes) {
    std::string result;
    result.reserve(bytes.size() / 2);
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        uint16_t c = (bytes[i] << 8) | bytes[i + 1];
        if (c == 0) break;
        if (c <= 0x7F) {
            result.push_back(static_cast<char>(c));
        } else if (c <= 0x7FF) {
            result.push_back(static_cast<char>(0xC0 | (c >> 6)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xE0 | (c >> 12)));
            result.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return result;
}

// ============================================================================
// XREF Integration
// ============================================================================

Result<void> StringAnalyzer::integrate_xrefs(const XRefDatabase* xref_db,
                                              const std::vector<FunctionInfo>* functions) {
    for (auto& str : result_.strings) {
        classify_references(str, xref_db, functions);
    }
    return Result<void>::ok();
}

void StringAnalyzer::classify_references(StringInfo& str, const XRefDatabase* xref_db,
                                         const std::vector<FunctionInfo>* functions) {
    auto xrefs = xref_db->get_xrefs_to(str.address);
    
    bool has_code_ref = false;
    bool has_data_ref = false;
    
    for (const auto& xref : xrefs.references) {
        if (xref.type == XRefType::CodeToData) {
            has_code_ref = true;
            str.code_refs.push_back(xref.from_address);
        } else if (xref.type == XRefType::DataToData) {
            has_data_ref = true;
            str.data_refs.push_back(xref.from_address);
        }
    }
    
    if (has_code_ref) {
        str.ref_type = StringReferenceType::Code_Reference;
    } else if (has_data_ref) {
        str.ref_type = StringReferenceType::Data_Reference;
    } else {
        str.ref_type = StringReferenceType::No_Reference;
    }
    
    if (functions) {
        for (const auto& func : *functions) {
            if (func.name == str.content) {
                if (func.is_exported) {
                    str.ref_type = StringReferenceType::Export_Reference;
                } else {
                    str.ref_type = StringReferenceType::Import_Reference;
                }
                break;
            }
        }
    }
}

// ============================================================================
// Deduplication
// ============================================================================

Result<void> StringAnalyzer::deduplicate_strings() {
    std::unordered_map<std::string, std::vector<size_t>> content_map;
    
    for (size_t i = 0; i < result_.strings.size(); ++i) {
        content_map[result_.strings[i].content].push_back(i);
    }
    
    std::vector<bool> to_remove(result_.strings.size(), false);
    
    for (const auto& [content, indices] : content_map) {
        if (indices.size() > 1) {
            stats_.duplicated_strings += indices.size() - 1;
            for (size_t j = 1; j < indices.size(); ++j) {
                to_remove[indices[j]] = true;
            }
        }
    }
    
    std::vector<StringInfo> deduped;
    deduped.reserve(result_.strings.size() - stats_.duplicated_strings);
    for (size_t i = 0; i < result_.strings.size(); ++i) {
        if (!to_remove[i]) {
            deduped.push_back(result_.strings[i]);
        }
    }
    
    result_.strings = std::move(deduped);
    return Result<void>::ok();
}

// ============================================================================
// Confidence Scoring
// ============================================================================

void StringAnalyzer::calculate_confidence(StringInfo& str) {
    int confidence = 30;
    std::ostringstream ss;
    ss << "Base: 30";
    
    if (str.length >= 20) {
        confidence += 20;
        ss << "; LengthBonus: +20 (>=20 chars)";
    } else if (str.length >= 10) {
        confidence += 10;
        ss << "; LengthBonus: +10 (>=10 chars)";
    }
    
    if (str.null_terminated) {
        confidence += 15;
        ss << "; NullTermBonus: +15";
    }
    
    switch (str.ref_type) {
        case StringReferenceType::Code_Reference:
            confidence += 25;
            ss << "; CodeRefBonus: +25";
            break;
        case StringReferenceType::Data_Reference:
            confidence += 15;
            ss << "; DataRefBonus: +15";
            break;
        case StringReferenceType::Import_Reference:
            confidence += 20;
            ss << "; ImportRefBonus: +20";
            break;
        case StringReferenceType::Export_Reference:
            confidence += 30;
            ss << "; ExportRefBonus: +30";
            break;
        default:
            break;
    }
    
    if (str.section_name == ".rdata" || str.section_name == ".rodata" || 
        str.section_name == "__cstring" || str.section_name == "__const") {
        confidence += 10;
        ss << "; SectionBonus: +10 (read-only data)";
    } else if (str.section_name == ".data") {
        confidence += 5;
        ss << "; SectionBonus: +5 (.data)";
    }
    
    if (str.encoding == StringEncoding::ASCII && 
        std::all_of(str.content.begin(), str.content.end(), 
                    [](char c) { return c >= 0x20 && c <= 0x7E; })) {
        confidence += 5;
        ss << "; ASCIIBonus: +5 (printable)";
    }
    
    if (str.length < 6) {
        confidence -= 10;
        ss << "; ShortPenalty: -10";
    }
    
    str.confidence_breakdown = ss.str();
    str.confidence = static_cast<ConfidenceLevel>(std::clamp(confidence, 0, 100));
}

// ============================================================================
// Section Utilities
// ============================================================================

std::string StringAnalyzer::find_section_name(const BinaryAnalysisResult& analysis, 
                                               TypedAddress addr) const {
    for (const auto& section : analysis.sections) {
        uint64_t start = section.virtual_address;
        uint64_t end = start + section.virtual_size;
        if (addr.value() >= start && addr.value() < end) {
            return section.name;
        }
    }
    return "";
}

bool StringAnalyzer::is_section_targeted(const std::string& section_name) const {
    if (config_.target_sections.empty()) return true;
    return std::find(config_.target_sections.begin(), config_.target_sections.end(), section_name) 
           != config_.target_sections.end();
}

bool StringAnalyzer::is_section_excluded(const std::string& section_name) const {
    return std::find(config_.exclude_sections.begin(), config_.exclude_sections.end(), section_name) 
           != config_.exclude_sections.end();
}

} // namespace fortress