// FORTRESS String Utilities

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <cctype>
#include <algorithm>
#include <cstdint>

namespace fortress {

// Trim whitespace
inline std::string_view ltrim(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
    return sv;
}
inline std::string_view rtrim(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
    return sv;
}
inline std::string_view trim(std::string_view sv) { return rtrim(ltrim(sv)); }

inline std::string ltrim_copy(std::string_view sv) { return std::string(ltrim(sv)); }
inline std::string rtrim_copy(std::string_view sv) { return std::string(rtrim(sv)); }
inline std::string trim_copy(std::string_view sv) { return std::string(trim(sv)); }

// Split string
inline std::vector<std::string_view> split(std::string_view sv, char delim, bool keep_empty = false) {
    std::vector<std::string_view> result;
    size_t start = 0;
    while (start <= sv.size()) {
        size_t pos = sv.find(delim, start);
        if (pos == std::string_view::npos) {
            if (keep_empty || start < sv.size()) result.emplace_back(sv.substr(start));
            break;
        }
        if (keep_empty || pos > start) result.emplace_back(sv.substr(start, pos - start));
        start = pos + 1;
    }
    return result;
}

inline std::vector<std::string> split_copy(std::string_view sv, char delim, bool keep_empty = false) {
    std::vector<std::string> result;
    for (auto part : split(sv, delim, keep_empty)) result.emplace_back(part);
    return result;
}

// Starts/ends with
inline bool starts_with(std::string_view sv, std::string_view prefix) { return sv.rfind(prefix, 0) == 0; }
inline bool ends_with(std::string_view sv, std::string_view suffix) { return sv.size() >= suffix.size() && sv.compare(sv.size() - suffix.size(), suffix.size(), suffix) == 0; }

// Case-insensitive compare
inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

// Case conversion
inline std::string to_lower(std::string_view sv) {
    std::string result(sv);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return std::tolower(c); });
    return result;
}
inline std::string to_upper(std::string_view sv) {
    std::string result(sv);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return std::toupper(c); });
    return result;
}

// Replace
inline std::string replace_all(std::string_view sv, std::string_view from, std::string_view to) {
    if (from.empty()) return std::string(sv);
    std::string result;
    result.reserve(sv.size());
    size_t pos = 0;
    while (pos < sv.size()) {
        size_t found = sv.find(from, pos);
        if (found == std::string_view::npos) {
            result.append(sv.substr(pos));
            break;
        }
        result.append(sv.substr(pos, found - pos));
        result.append(to);
        pos = found + from.size();
    }
    return result;
}

// Hex encoding/decoding
inline std::string to_hex(std::string_view data, bool uppercase = false) {
    static const char* lower = "0123456789abcdef";
    static const char* upper = "0123456789ABCDEF";
    const char* table = uppercase ? upper : lower;
    std::string result;
    result.reserve(data.size() * 2);
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t byte = static_cast<uint8_t>(static_cast<unsigned char>(data[i]));
        result.push_back(table[byte >> 4]);
        result.push_back(table[byte & 0xF]);
    }
    return result;
}

inline std::optional<std::string> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    std::string result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto val = [](char c) -> std::optional<uint8_t> {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return std::nullopt;
        };
        auto high = val(hex[i]);
        auto low = val(hex[i + 1]);
        if (!high || !low) return std::nullopt;
        result.push_back(static_cast<char>((*high << 4) | *low));
    }
    return result;
}

// Number formatting
inline std::string format_size(uint64_t bytes) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && unit < 4) { size /= 1024; ++unit; }
    char buf[32];
    std::snprintf(buf, sizeof(buf), unit == 0 ? "%.0f %s" : "%.2f %s", size, units[unit]);
    return buf;
}

inline std::string format_address(uint64_t addr, bool prefix = true) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), prefix ? "0x%016llX" : "%016llX", static_cast<unsigned long long>(addr));
    return buf;
}

// Join
template<typename Range>
std::string join(const Range& range, std::string_view delim) {
    std::string result;
    bool first = true;
    for (const auto& elem : range) {
        if (!first) result.append(delim);
        first = false;
        result.append(elem);
    }
    return result;
}

// Indent
inline std::string indent(std::string_view text, size_t spaces = 2) {
    std::string result;
    result.reserve(text.size() + (text.size() / 80) * spaces);
    std::string pad(spaces, ' ');
    bool at_line_start = true;
    for (char c : text) {
        if (at_line_start && c != '\n') result.append(pad);
        result.push_back(c);
        at_line_start = (c == '\n');
    }
    return result;
}

} // namespace fortress