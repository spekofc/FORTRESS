// FORTRESS File Utilities Implementation

#include <fortress/core/file_utils.h>
#include <fortress/core/error.h>
#include <fstream>
#include <system_error>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fortress {

// FileMapping implementation
FileMapping::~FileMapping() {
    if (data_) {
#ifdef _WIN32
        if (mapping_handle_) UnmapViewOfFile(data_);
        if (mapping_handle_) CloseHandle(mapping_handle_);
        if (file_handle_) CloseHandle(file_handle_);
#else
        munmap(data_, size_);
        if (fd_ >= 0) close(fd_);
#endif
        data_ = nullptr;
        size_ = 0;
    }
}

FileMapping::FileMapping(FileMapping&& other) noexcept
    : data_(other.data_), size_(other.size_), path_(std::move(other.path_))
#ifdef _WIN32
    , mapping_handle_(other.mapping_handle_), file_handle_(other.file_handle_)
#else
    , fd_(other.fd_)
#endif
{
    other.data_ = nullptr;
    other.size_ = 0;
#ifdef _WIN32
    other.mapping_handle_ = nullptr;
    other.file_handle_ = nullptr;
#else
    other.fd_ = -1;
#endif
}

FileMapping& FileMapping::operator=(FileMapping&& other) noexcept {
    if (this != &other) {
        this->~FileMapping();
        data_ = other.data_;
        size_ = other.size_;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
        path_ = std::move(other.path_);
#pragma GCC diagnostic pop
#ifdef _WIN32
        mapping_handle_ = other.mapping_handle_;
        file_handle_ = other.file_handle_;
#else
        fd_ = other.fd_;
#endif
        other.data_ = nullptr;
        other.size_ = 0;
#ifdef _WIN32
        other.mapping_handle_ = nullptr;
        other.file_handle_ = nullptr;
#else
        other.fd_ = -1;
#endif
    }
    return *this;
}

Result<FileMapping> FileMapping::open_read_only(const std::filesystem::path& path) {
    auto size_result = file_utils::file_size(path);
    if (!size_result) return size_result.error();

    Size size = size_result.value();
    if (size == 0) {
        return Error::file_read_error("File is empty: " + path.string());
    }

#ifdef _WIN32
    HANDLE file_handle = CreateFileW(
        path.wstring().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (file_handle == INVALID_HANDLE_VALUE) {
        return Error::file_read_error("Failed to open file: " + path.string() + " (error: " + std::to_string(GetLastError()) + ")");
    }

    HANDLE mapping_handle = CreateFileMappingW(file_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping_handle) {
        CloseHandle(file_handle);
        return Error::file_mapping_error("Failed to create file mapping: " + path.string() + " (error: " + std::to_string(GetLastError()) + ")");
    }

    void* data = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (!data) {
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        return Error::file_mapping_error("Failed to map view of file: " + path.string() + " (error: " + std::to_string(GetLastError()) + ")");
    }

    return FileMapping(data, size, path);
#else
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return Error::file_read_error("Failed to open file: " + path.string() + " (errno: " + std::to_string(errno) + ")");
    }

    void* data = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        close(fd);
        return Error::file_mapping_error("Failed to mmap file: " + path.string() + " (errno: " + std::to_string(errno) + ")");
    }

    // Don't close fd until unmapped
    FileMapping result(data, size, path);
    result.fd_ = fd;
    return result;
#endif
}

// file_utils namespace implementation
namespace file_utils {

bool exists(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

Result<void> check_readable(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return Error::file_not_found(path.string());
    }
    if (!std::filesystem::is_regular_file(path, ec)) {
        return Error::invalid_argument("Not a regular file: " + path.string());
    }
    // Try to open for reading
    std::ifstream test(path, std::ios::binary);
    if (!test) {
        return Error::file_read_error("Cannot open for reading: " + path.string());
    }
    return Result<void>::ok();
}

Result<Size> file_size(const std::filesystem::path& path) {
    std::error_code ec;
    auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return Error::file_read_error("Failed to get file size: " + path.string() + " (" + ec.message() + ")");
    }
    return size;
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path) {
    auto size_result = file_utils::file_size(path);
    if (!size_result) return size_result.error();

    Size size = size_result.value();
    if (size == 0) {
        return std::vector<std::byte>{};
    }

    std::vector<std::byte> buffer(size);
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return Error::file_read_error("Failed to open file: " + path.string());
    }

    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
    if (!file) {
        return Error::file_read_error("Failed to read file: " + path.string());
    }

    return buffer;
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path, Offset offset, Size max_size) {
    auto size_result = file_utils::file_size(path);
    if (!size_result) return size_result.error();

    Size file_size = size_result.value();
    if (offset >= file_size) {
        return std::vector<std::byte>{};
    }

    Size to_read = (max_size == INVALID_SIZE || offset + max_size > file_size) ? file_size - offset : max_size;

    std::vector<std::byte> buffer(to_read);
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return Error::file_read_error("Failed to open file: " + path.string());
    }

    file.seekg(static_cast<std::streamoff>(offset));
    if (!file) {
        return Error::file_seek_error("Failed to seek in file: " + path.string());
    }

    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(to_read));
    if (!file && file.gcount() != static_cast<std::streamsize>(to_read)) {
        return Error::file_read_error("Failed to read file: " + path.string());
    }

    return buffer;
}

Result<void> write_file(const std::filesystem::path& path, std::span<const std::byte> data, bool append) {
    std::ofstream file(path, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
    if (!file) {
        return Error::file_write_error("Failed to open file for writing: " + path.string());
    }

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file) {
        return Error::file_write_error("Failed to write to file: " + path.string());
    }

    return Result<void>::ok();
}

Result<FileMapping> map_file_read_only(const std::filesystem::path& path) {
    return FileMapping::open_read_only(path);
}

Result<TempFile> create_temp_file(const std::string& prefix) {
    std::error_code ec;
    auto temp_dir = std::filesystem::temp_directory_path(ec);
    if (ec) {
        return Error::file_write_error("Failed to get temp directory: " + ec.message());
    }

    // Generate unique name
    std::string name = prefix + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".tmp";
    auto path = temp_dir / name;

    // Create empty file
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return Error::file_write_error("Failed to create temp file: " + path.string());
    }

    return TempFile(path);
}

Result<void> create_directories(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec) {
        return Error::file_write_error("Failed to create directories: " + path.string() + " (" + ec.message() + ")");
    }
    return Result<void>::ok();
}

bool is_directory(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    return std::filesystem::is_directory(path, ec);
}

std::vector<std::filesystem::path> list_files(const std::filesystem::path& dir, const std::string& pattern) {
    std::vector<std::filesystem::path> results;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) break;
        if (entry.is_regular_file()) {
            if (pattern.empty() || entry.path().filename().string().find(pattern) != std::string::npos) {
                results.push_back(entry.path());
            }
        }
    }
    return results;
}

std::string normalize_path(const std::filesystem::path& path) {
    return std::filesystem::weakly_canonical(path).string();
}

std::filesystem::path get_executable_path() {
    std::error_code ec;
    auto path = std::filesystem::canonical("/proc/self/exe", ec); // Linux
    if (ec) {
#ifdef _WIN32
        wchar_t buffer[MAX_PATH];
        GetModuleFileNameW(nullptr, buffer, MAX_PATH);
        return std::filesystem::path(buffer);
#else
        return std::filesystem::path();
#endif
    }
    return path;
}

std::filesystem::path get_executable_directory() {
    return get_executable_path().parent_path();
}

} // namespace file_utils

} // namespace fortress