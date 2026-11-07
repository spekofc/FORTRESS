// FORTRESS File Utilities
// Cross-platform file operations

#pragma once

#include <fortress/core/error.h>
#include <fortress/core/types.h>
#include <filesystem>
#include <vector>
#include <string>
#include <span>
#include <memory>

namespace fortress {

// File mapping for efficient large file access
class FileMapping {
public:
    FileMapping() = default;
    ~FileMapping();

    FileMapping(FileMapping&&) noexcept;
    FileMapping& operator=(FileMapping&&) noexcept;
    FileMapping(const FileMapping&) = delete;
    FileMapping& operator=(const FileMapping&) = delete;

    // Open and map a file read-only
    static Result<FileMapping> open_read_only(const std::filesystem::path& path);

    // Get mapped data
    std::span<const std::byte> data() const noexcept { return {static_cast<const std::byte*>(data_), size_}; }
    std::span<std::byte> mutable_data() noexcept { return {static_cast<std::byte*>(data_), size_}; }
    Size size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    const std::filesystem::path& path() const noexcept { return path_; }

    // Access as typed pointer
    template<typename T>
    const T* as() const noexcept {
        return reinterpret_cast<const T*>(data_);
    }

    template<typename T>
    T* mutable_as() noexcept {
        return reinterpret_cast<T*>(data_);
    }

    // Subspan
    std::span<const std::byte> subspan(Offset offset, Size count = INVALID_SIZE) const {
        if (offset >= size_) return {};
        Size actual = (count == INVALID_SIZE || offset + count > size_) ? size_ - offset : count;
        return data().subspan(offset, actual);
    }

    template<typename T>
    std::span<const T> subspan_as(Offset offset, Size count = INVALID_SIZE) const {
        auto span = subspan(offset, count * sizeof(T));
        return {reinterpret_cast<const T*>(span.data()), span.size() / sizeof(T)};
    }

private:
    FileMapping(void* data, Size size, std::filesystem::path path) noexcept
        : data_(data), size_(size), path_(std::move(path)) {}

    void* data_ = nullptr;
    Size size_ = 0;
    std::filesystem::path path_;
#ifdef _WIN32
    void* mapping_handle_ = nullptr;
    void* file_handle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

// File utilities
namespace file_utils {

// Check if file exists and is readable
bool exists(const std::filesystem::path& path) noexcept;
Result<void> check_readable(const std::filesystem::path& path);

// Get file size
Result<Size> file_size(const std::filesystem::path& path);

// Read entire file into memory
Result<std::vector<std::byte>> read_file(const std::filesystem::path& path);
Result<std::vector<std::byte>> read_file(const std::filesystem::path& path, Offset offset, Size max_size);

// Write data to file
Result<void> write_file(const std::filesystem::path& path, std::span<const std::byte> data, bool append = false);

// Memory map a file (preferred for large files)
Result<FileMapping> map_file_read_only(const std::filesystem::path& path);

// Temporary file management
class TempFile {
public:
    TempFile() = default;
    explicit TempFile(std::filesystem::path path) : path_(std::move(path)) {}
    ~TempFile() {
        if (!path_.empty()) {
            std::error_code ec;
            std::filesystem::remove(path_, ec);
        }
    }

    TempFile(TempFile&& other) noexcept : path_(std::move(other.path_)) { other.path_.clear(); }
    TempFile& operator=(TempFile&& other) noexcept {
        if (this != &other) {
            if (!path_.empty()) {
                std::error_code ec;
                std::filesystem::remove(path_, ec);
            }
            path_ = std::move(other.path_);
            other.path_.clear();
        }
        return *this;
    }

    const std::filesystem::path& path() const noexcept { return path_; }
    void release() { path_.clear(); }

private:
    std::filesystem::path path_;
};

Result<TempFile> create_temp_file(const std::string& prefix = "fortress_");

// Directory utilities
Result<void> create_directories(const std::filesystem::path& path);
bool is_directory(const std::filesystem::path& path) noexcept;
std::vector<std::filesystem::path> list_files(const std::filesystem::path& dir, const std::string& pattern = "");

// Path utilities
std::string normalize_path(const std::filesystem::path& path);
std::filesystem::path get_executable_path();
std::filesystem::path get_executable_directory();

} // namespace file_utils

} // namespace fortress