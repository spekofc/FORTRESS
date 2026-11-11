// FORTRESS String Analyzer
// String extraction and analysis with XREF integration

#pragma once

#include <fortress/binary/analysis/analysis_model.h>
#include <fortress/binary/analysis/xref.h>
#include <fortress/core/types.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <optional>

namespace fortress {

// ============================================================================
// String Analyzer Types
// ============================================================================

enum class StringEncoding : uint8_t {
    ASCII,
    UTF8,
    UTF16_LE,
    UTF16_BE,
    Unknown
};

enum class StringType : uint8_t {
    ASCII_String,
    UTF8_String,
    UTF16_LE_String,
    UTF16_BE_String,
    Pascal_String,      // Length-prefixed
    Wide_String,        // wchar_t style
    Unknown
};

enum class StringReferenceType : uint8_t {
    Code_Reference,     // Referenced by code (load, lea, etc.)
    Data_Reference,     // Referenced by data (pointer in data section)
    Import_Reference,   // Imported function/variable name
    Export_Reference,   // Exported symbol name
    No_Reference,       // Not referenced
    Unknown
};

struct StringInfo {
    TypedAddress address;
    size_t file_offset = 0;
    StringEncoding encoding = StringEncoding::ASCII;
    StringType type = StringType::ASCII_String;
    std::string content;           // Decoded content (UTF-8 normalized)
    std::vector<uint8_t> raw_bytes; // Original bytes
    size_t length = 0;             // Character count (not byte count)
    size_t byte_length = 0;        // Byte count
    bool null_terminated = false;
    StringReferenceType ref_type = StringReferenceType::No_Reference;
    std::vector<TypedAddress> code_refs;  // Addresses of instructions referencing this string
    std::vector<TypedAddress> data_refs;  // Addresses of data referencing this string
    std::string section_name;      // Section containing this string
    ConfidenceLevel confidence = ConfidenceLevel::Low;
    std::string confidence_breakdown;
};

struct StringAnalyzerConfig {
    size_t min_length = 4;              // Minimum string length (characters)
    size_t max_length = 8192;           // Maximum string length (characters)
    bool extract_ascii = true;           // Extract ASCII strings
    bool extract_utf8 = true;            // Extract UTF-8 strings
    bool extract_utf16_le = true;        // Extract UTF-16 LE strings
    bool extract_utf16_be = false;       // Extract UTF-16 BE strings
    bool extract_pascal = false;         // Extract Pascal-style (length-prefixed) strings
    bool require_null_terminator = false; // Require null terminator
    bool deduplicate = true;             // Deduplicate identical strings
    bool only_referenced = false;        // Only return strings with code/data references
    std::vector<std::string> target_sections; // Sections to analyze (empty = all)
    std::vector<std::string> exclude_sections; // Sections to skip
};

struct StringAnalyzerStats {
    size_t total_strings = 0;
    size_t ascii_strings = 0;
    size_t utf8_strings = 0;
    size_t utf16_le_strings = 0;
    size_t utf16_be_strings = 0;
    size_t pascal_strings = 0;
    size_t referenced_strings = 0;
    size_t unreferenced_strings = 0;
    size_t duplicated_strings = 0;
    size_t total_bytes = 0;
};

struct StringQueryResult {
    std::vector<StringInfo> strings;
    size_t total_count = 0;
    bool truncated = false;
};

struct StringAnalysisResult {
    std::vector<StringInfo> strings;
    StringAnalyzerStats stats;
    StringAnalyzerConfig config;
};

// ============================================================================
// String Analyzer
// ============================================================================

class StringAnalyzer {
public:
    explicit StringAnalyzer(const StringAnalyzerConfig& config = StringAnalyzerConfig());
    
    // Main analysis entry point
    Result<StringAnalysisResult> analyze_strings(const BinaryAnalysisResult& analysis);
    Result<StringAnalysisResult> analyze_strings(const BinaryAnalysisResult& analysis,
                                                 const XRefDatabase* xref_db,
                                                 const std::vector<FunctionInfo>* functions = nullptr);
    
    // Query methods
    Result<StringQueryResult> query_by_content(const std::string& pattern, 
                                               bool case_sensitive = true,
                                               size_t limit = 100,
                                               size_t offset = 0) const;
    
    Result<StringQueryResult> query_by_address(TypedAddress address,
                                               size_t limit = 100) const;
    
    Result<StringQueryResult> query_by_encoding(StringEncoding encoding,
                                               size_t limit = 100,
                                               size_t offset = 0) const;
    
    Result<StringQueryResult> query_by_reference_type(StringReferenceType ref_type,
                                                      size_t limit = 100,
                                                      size_t offset = 0) const;
    
    Result<StringQueryResult> query_by_section(const std::string& section_name,
                                               size_t limit = 100,
                                               size_t offset = 0) const;
    
    Result<StringQueryResult> query_referenced_only(size_t limit = 100,
                                                    size_t offset = 0) const;
    
    Result<StringQueryResult> query_unreferenced_only(size_t limit = 100,
                                                      size_t offset = 0) const;
    
    // Get all strings
    Result<StringQueryResult> get_all_strings(size_t limit = 100,
                                             size_t offset = 0) const;
    
    // Statistics
    StringAnalyzerStats get_stats() const { return stats_; }
    
    // Export
    Result<std::string> export_json(bool pretty = true) const;
    Result<std::string> export_json(const StringQueryResult& query, bool pretty = true) const;
    
    // Configuration
    const StringAnalyzerConfig& get_config() const { return config_; }
    void set_config(const StringAnalyzerConfig& config) { config_ = config; }
    
private:
    StringAnalyzerConfig config_;
    StringAnalysisResult result_;
    StringAnalyzerStats stats_;
    
    // Internal extraction methods
    Result<void> extract_ascii_strings(const BinaryAnalysisResult& analysis);
    Result<void> extract_utf8_strings(const BinaryAnalysisResult& analysis);
    Result<void> extract_utf16_strings(const BinaryAnalysisResult& analysis, bool little_endian);
    Result<void> extract_pascal_strings(const BinaryAnalysisResult& analysis);
    
    // Validation
    bool is_valid_ascii(const std::vector<uint8_t>& bytes, size_t& length);
    bool is_valid_utf8(const std::vector<uint8_t>& bytes, size_t& length);
    bool is_valid_utf16_le(const std::vector<uint8_t>& bytes, size_t& length);
    bool is_valid_utf16_be(const std::vector<uint8_t>& bytes, size_t& length);
    
    // Decoding
    std::string decode_ascii(const std::vector<uint8_t>& bytes);
    std::string decode_utf8(const std::vector<uint8_t>& bytes);
    std::string decode_utf16_le(const std::vector<uint8_t>& bytes);
    std::string decode_utf16_be(const std::vector<uint8_t>& bytes);
    
    // Reference integration
    Result<void> integrate_xrefs(const XRefDatabase* xref_db,
                                 const std::vector<FunctionInfo>* functions);
    void classify_references(StringInfo& str, const XRefDatabase* xref_db,
                            const std::vector<FunctionInfo>* functions);
    
    // Deduplication
    Result<void> deduplicate_strings();
    
    // Confidence scoring
    void calculate_confidence(StringInfo& str);
    
    // Section utilities
    std::string find_section_name(const BinaryAnalysisResult& analysis, TypedAddress addr) const;
    bool is_section_targeted(const std::string& section_name) const;
    bool is_section_excluded(const std::string& section_name) const;
    
    // Section data extraction
    std::vector<uint8_t> extract_section_bytes(const BinaryAnalysisResult& analysis,
                                               const SectionInfo& section) const;
};

// ============================================================================
// String Analyzer String Conversions
// ============================================================================

inline std::string to_string(StringEncoding enc) {
    switch (enc) {
        case StringEncoding::ASCII: return "ASCII";
        case StringEncoding::UTF8: return "UTF8";
        case StringEncoding::UTF16_LE: return "UTF16_LE";
        case StringEncoding::UTF16_BE: return "UTF16_BE";
        default: return "Unknown";
    }
}

inline std::string to_string(StringType type) {
    switch (type) {
        case StringType::ASCII_String: return "ASCII";
        case StringType::UTF8_String: return "UTF8";
        case StringType::UTF16_LE_String: return "UTF16_LE";
        case StringType::UTF16_BE_String: return "UTF16_BE";
        case StringType::Pascal_String: return "Pascal";
        case StringType::Wide_String: return "Wide";
        default: return "Unknown";
    }
}

inline std::string to_string(StringReferenceType ref) {
    switch (ref) {
        case StringReferenceType::Code_Reference: return "Code";
        case StringReferenceType::Data_Reference: return "Data";
        case StringReferenceType::Import_Reference: return "Import";
        case StringReferenceType::Export_Reference: return "Export";
        case StringReferenceType::No_Reference: return "None";
        default: return "Unknown";
    }
}

} // namespace fortress