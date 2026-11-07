// FORTRESS Hash Utilities
// Cryptographic and non-cryptographic hashing

#pragma once

#include <fortress/core/error.h>
#include <fortress/core/types.h>
#include <array>
#include <span>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <optional>

namespace fortress {

// Hash digest sizes
constexpr Size MD5_DIGEST_SIZE      = 16;
constexpr Size SHA1_DIGEST_SIZE     = 20;
constexpr Size SHA256_DIGEST_SIZE   = 32;
constexpr Size SHA384_DIGEST_SIZE   = 48;
constexpr Size SHA512_DIGEST_SIZE   = 64;
constexpr Size SHA3_256_DIGEST_SIZE = 32;
constexpr Size SHA3_512_DIGEST_SIZE = 64;
constexpr Size BLAKE2B_DIGEST_SIZE  = 64;
constexpr Size BLAKE3_DIGEST_SIZE   = 32;

// Maximum digest size
constexpr Size MAX_DIGEST_SIZE = 64;

// Digest size for algorithm (must be before Digest class)
constexpr Size digest_size_for_algorithm(HashAlgorithm algo) noexcept {
    switch (algo) {
        case HashAlgorithm::MD5:      return MD5_DIGEST_SIZE;
        case HashAlgorithm::SHA1:     return SHA1_DIGEST_SIZE;
        case HashAlgorithm::SHA256:   return SHA256_DIGEST_SIZE;
        case HashAlgorithm::SHA384:   return SHA384_DIGEST_SIZE;
        case HashAlgorithm::SHA512:   return SHA512_DIGEST_SIZE;
        case HashAlgorithm::SHA3_256: return SHA3_256_DIGEST_SIZE;
        case HashAlgorithm::SHA3_512: return SHA3_512_DIGEST_SIZE;
        case HashAlgorithm::BLAKE2b:  return BLAKE2B_DIGEST_SIZE;
        case HashAlgorithm::BLAKE3:   return BLAKE3_DIGEST_SIZE;
        default:                      return 0;
    }
}

// Hash digest container
class Digest {
public:
    Digest() = default;
    explicit Digest(HashAlgorithm algo) : algorithm_(algo) {}

    HashAlgorithm algorithm() const noexcept { return algorithm_; }
    void set_algorithm(HashAlgorithm algo) noexcept { algorithm_ = algo; }

    Size size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }

    const std::vector<std::byte>& bytes() const noexcept { return data_; }
    std::vector<std::byte>& mutable_bytes() noexcept { return data_; }

    std::span<const std::byte> span() const noexcept { return data_; }
    std::span<std::byte> mutable_span() noexcept { return data_; }

    // Resize to match algorithm
    void resize_for_algorithm() {
        data_.resize(digest_size_for_algorithm(algorithm_));
    }

    // Hex encoding
    std::string to_hex() const;
    static Result<Digest> from_hex(std::string_view hex, HashAlgorithm algo);

    // Comparison
    bool operator==(const Digest& other) const noexcept {
        return algorithm_ == other.algorithm_ && data_ == other.data_;
    }
    bool operator!=(const Digest& other) const noexcept { return !(*this == other); }

    // Constant-time comparison (for security-sensitive comparisons)
    bool constant_time_equal(const Digest& other) const noexcept;

private:
    HashAlgorithm algorithm_ = HashAlgorithm::None;
    std::vector<std::byte> data_;
};

// Hash context for incremental hashing
class HashContext {
public:
    virtual ~HashContext() = default;

    virtual Result<void> update(std::span<const std::byte> data) = 0;
    virtual Result<Digest> finalize() = 0;
    virtual void reset() = 0;
    virtual HashAlgorithm algorithm() const noexcept = 0;
};

// Create hash context for algorithm
Result<std::unique_ptr<HashContext>> create_hash_context(HashAlgorithm algo);

// One-shot hash functions
Result<Digest> hash_data(HashAlgorithm algo, std::span<const std::byte> data);
Result<Digest> hash_file(HashAlgorithm algo, const std::filesystem::path& path);
Result<Digest> hash_file_incremental(HashAlgorithm algo, const std::filesystem::path& path, Size chunk_size = 64 * 1024);

// Multi-hash computation (compute multiple hashes in one pass)
struct MultiHashResult {
    std::optional<Digest> md5;
    std::optional<Digest> sha1;
    std::optional<Digest> sha256;
    std::optional<Digest> sha384;
    std::optional<Digest> sha512;
    std::optional<Digest> sha3_256;
    std::optional<Digest> sha3_512;
    std::optional<Digest> blake2b;
    std::optional<Digest> blake3;
};

Result<MultiHashResult> compute_all_hashes(std::span<const std::byte> data);
Result<MultiHashResult> compute_all_hashes_file(const std::filesystem::path& path);

// Entropy calculation (Shannon entropy)
double calculate_entropy(std::span<const std::byte> data);
std::vector<double> calculate_entropy_per_block(std::span<const std::byte> data, Size block_size = 256);

// Checksums (non-cryptographic)
uint32_t crc32(std::span<const std::byte> data, uint32_t initial = 0);
uint32_t crc32c(std::span<const std::byte> data, uint32_t initial = 0);
uint64_t xxh64(std::span<const std::byte> data, uint64_t seed = 0);

// Format digest for display
std::string format_digest(const Digest& digest, bool uppercase = false, bool with_prefix = false);

} // namespace fortress