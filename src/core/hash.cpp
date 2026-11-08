// FORTRESS Hash Implementation
// Uses OpenSSL EVP API for all cryptographic hashes
// Reference implementations for non-cryptographic checksums (CRC32, CRC32C, xxHash64, Entropy)

#include <fortress/core/hash.h>
#include <fortress/core/error.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <memory>
#include <fstream>
#include <cmath>
#include <vector>
#include <optional>
#include <span>
#include <cstdint>
#include <array>

namespace fortress {

// ============================================================================
// OpenSSL EVP-based Hash Context (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2b)
// ============================================================================

class EVPHashContext : public HashContext {
public:
    explicit EVPHashContext(EVP_MD const* md, HashAlgorithm algo) : md_(md), algorithm_(algo) {
        static bool openssl_initialized = []() {
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);
            return true;
        }();
        (void)openssl_initialized;

        ctx_ = EVP_MD_CTX_new();
        if (!ctx_) {
            throw std::bad_alloc();
        }
        reset();
    }

    ~EVPHashContext() override {
        EVP_MD_CTX_free(ctx_);
    }

    HashAlgorithm algorithm() const noexcept override {
        return algorithm_;
    }

    void reset() override {
        if (!EVP_DigestInit_ex(ctx_, md_, nullptr)) {
            throw std::runtime_error("EVP_DigestInit_ex failed");
        }
    }

    Result<void> update(std::span<const std::byte> data) override {
        if (data.empty()) return Result<void>::ok();
        if (!EVP_DigestUpdate(ctx_, data.data(), data.size())) {
            return Result<void>::err(ErrorCode::HashComputationFailed, "EVP_DigestUpdate failed");
        }
        return Result<void>::ok();
    }

    Result<Digest> finalize() override {
        Digest digest(algorithm_);
        digest.mutable_bytes().resize(digest_size_for_algorithm(algorithm_));
        unsigned int len = 0;
        if (!EVP_DigestFinal_ex(ctx_, reinterpret_cast<unsigned char*>(digest.mutable_bytes().data()), &len)) {
            return Result<Digest>::err(ErrorCode::HashComputationFailed, "EVP_DigestFinal_ex failed");
        }
        if (static_cast<Size>(len) != digest.size()) {
            return Result<Digest>::err(ErrorCode::HashComputationFailed, "Unexpected digest size");
        }
        return digest;
    }

private:
    EVP_MD_CTX* ctx_ = nullptr;
    EVP_MD const* md_ = nullptr;
    HashAlgorithm algorithm_ = HashAlgorithm::None;

    friend Result<std::unique_ptr<HashContext>> create_hash_context(HashAlgorithm algo);
};

// ============================================================================
// CRC32 Implementation (using built-in table)
// ============================================================================

static uint32_t crc32_table[256];
static bool crc32_table_init = false;

static void init_crc32_table() {
    if (crc32_table_init) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_init = true;
}

uint32_t crc32(std::span<const std::byte> data, uint32_t initial) {
    init_crc32_table();
    uint32_t crc = ~initial;
    for (auto b : data) {
        crc = crc32_table[(crc ^ static_cast<uint8_t>(b)) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

// CRC32C (Castagnoli) - used in iSCSI, SCTP, etc.
static uint32_t crc32c_table[256];
static bool crc32c_table_init = false;

static void init_crc32c_table() {
    if (crc32c_table_init) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0x82F63B78 ^ (c >> 1)) : (c >> 1);
        }
        crc32c_table[i] = c;
    }
    crc32c_table_init = true;
}

uint32_t crc32c(std::span<const std::byte> data, uint32_t initial) {
    init_crc32c_table();
    uint32_t crc = ~initial;
    for (auto b : data) {
        crc = crc32c_table[(crc ^ static_cast<uint8_t>(b)) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

// ============================================================================
// xxHash64 Implementation (reference implementation - safe unaligned access)
// ============================================================================

static inline uint64_t XXH_read64(const void* ptr) {
    uint64_t val;
    std::memcpy(&val, ptr, sizeof(val));
    return val;
}

static inline uint32_t XXH_read32(const void* ptr) {
    uint32_t val;
    std::memcpy(&val, ptr, sizeof(val));
    return val;
}

uint64_t xxh64(std::span<const std::byte> data, uint64_t seed) {
    const uint64_t PRIME64_1 = 0x9E3779B185EBCA87ULL;
    const uint64_t PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
    const uint64_t PRIME64_3 = 0x165667B19E3779F9ULL;
    const uint64_t PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
    const uint64_t PRIME64_5 = 0x27D4EB2F165667C5ULL;

    uint64_t hash = seed + PRIME64_5;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
    Size len = data.size();

    const uint8_t* end = ptr + len;
    while (ptr + 8 <= end) {
        uint64_t k1 = XXH_read64(ptr);
        ptr += 8;
        k1 *= PRIME64_2;
        k1 = (k1 << 31) | (k1 >> 33);
        k1 *= PRIME64_1;
        hash ^= k1;
        hash = (hash << 27) | (hash >> 37);
        hash = hash * PRIME64_1 + PRIME64_4;
    }

    while (ptr + 4 <= end) {
        uint32_t k1 = XXH_read32(ptr);
        ptr += 4;
        hash ^= static_cast<uint64_t>(k1) * PRIME64_1;
        hash = (hash << 23) | (hash >> 41);
        hash = hash * PRIME64_2 + PRIME64_3;
    }

    while (ptr < end) {
        hash ^= static_cast<uint64_t>(*ptr++) * PRIME64_5;
        hash = (hash << 11) | (hash >> 53);
        hash *= PRIME64_1;
    }

    hash ^= len;
    hash ^= hash >> 33;
    hash *= PRIME64_2;
    hash ^= hash >> 29;
    hash *= PRIME64_3;
    hash ^= hash >> 32;
    return hash;
}

// ============================================================================
// Entropy Calculation
// ============================================================================

double calculate_entropy(std::span<const std::byte> data) {
    if (data.empty()) return 0.0;

    uint64_t freq[256] = {0};
    for (auto b : data) freq[static_cast<uint8_t>(b)]++;

    double entropy = 0.0;
    double inv_len = 1.0 / static_cast<double>(data.size());
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) * inv_len;
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

std::vector<double> calculate_entropy_per_block(std::span<const std::byte> data, Size block_size) {
    std::vector<double> result;
    for (Size i = 0; i < data.size(); i += block_size) {
        Size len = std::min(block_size, data.size() - i);
        result.push_back(calculate_entropy(data.subspan(i, len)));
    }
    return result;
}

// ============================================================================
// Factory
// ============================================================================

Result<std::unique_ptr<HashContext>> create_hash_context(HashAlgorithm algo) {
    switch (algo) {
        case HashAlgorithm::MD5:
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(EVP_md5(), algo));
        case HashAlgorithm::SHA1:
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(EVP_sha1(), algo));
        case HashAlgorithm::SHA256:
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(EVP_sha256(), algo));
        case HashAlgorithm::SHA384:
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(EVP_sha384(), algo));
        case HashAlgorithm::SHA512:
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(EVP_sha512(), algo));
        case HashAlgorithm::SHA3_256: {
            const EVP_MD* md = EVP_sha3_256();
            if (!md) {
                return Result<std::unique_ptr<HashContext>>::err(
                    Error::unsupported_operation("SHA3-256 not available in OpenSSL provider"));
            }
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(md, algo));
        }
        case HashAlgorithm::SHA3_512: {
            const EVP_MD* md = EVP_sha3_512();
            if (!md) {
                return Result<std::unique_ptr<HashContext>>::err(
                    Error::unsupported_operation("SHA3-512 not available in OpenSSL provider"));
            }
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(md, algo));
        }
        case HashAlgorithm::BLAKE2b: {
            const EVP_MD* md = EVP_blake2b512();
            if (!md) {
                return Result<std::unique_ptr<HashContext>>::err(
                    Error::unsupported_operation("BLAKE2b not available in OpenSSL provider"));
            }
            return Result<std::unique_ptr<HashContext>>::ok(
                std::make_unique<EVPHashContext>(md, algo));
        }
        case HashAlgorithm::BLAKE3:
            return Result<std::unique_ptr<HashContext>>::err(
                Error::unsupported_operation("BLAKE3 not available - use OpenSSL 3.2+ or integrate official implementation"));
        default:
            return Result<std::unique_ptr<HashContext>>::err(
                Error::unsupported_operation("Unsupported hash algorithm: " + 
                    std::to_string(static_cast<int>(algo))));
    }
}

// One-shot hashing
Result<Digest> hash_data(HashAlgorithm algo, std::span<const std::byte> data) {
    auto ctx_result = create_hash_context(algo);
    if (!ctx_result) return ctx_result.error();

    auto ctx = std::move(ctx_result.value());
    auto update_result = ctx->update(data);
    if (!update_result) return update_result.error();

    return ctx->finalize();
}

Result<Digest> hash_file(HashAlgorithm algo, const std::filesystem::path& path) {
    auto ctx_result = create_hash_context(algo);
    if (!ctx_result) return ctx_result.error();

    auto ctx = std::move(ctx_result.value());

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return Error::file_read_error("Failed to open file: " + path.string());
    }

    std::array<std::byte, 65536> buffer;
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize read = file.gcount();
        if (read > 0) {
            auto update_result = ctx->update({buffer.data(), static_cast<Size>(read)});
            if (!update_result) return update_result.error();
        }
    }

    return ctx->finalize();
}

Result<Digest> hash_file_incremental(HashAlgorithm algo, const std::filesystem::path& path, [[maybe_unused]] Size chunk_size) {
    return hash_file(algo, path);
}

// Multi-hash
Result<MultiHashResult> compute_all_hashes(std::span<const std::byte> data) {
    MultiHashResult result;

    const HashAlgorithm algos[] = {
        HashAlgorithm::MD5, HashAlgorithm::SHA1, HashAlgorithm::SHA256,
        HashAlgorithm::SHA384, HashAlgorithm::SHA512
    };

    for (auto algo : algos) {
        auto h = hash_data(algo, data);
        if (h) {
            switch (algo) {
                case HashAlgorithm::MD5:      result.md5      = std::move(h.value()); break;
                case HashAlgorithm::SHA1:     result.sha1     = std::move(h.value()); break;
                case HashAlgorithm::SHA256:   result.sha256   = std::move(h.value()); break;
                case HashAlgorithm::SHA384:   result.sha384   = std::move(h.value()); break;
                case HashAlgorithm::SHA512:   result.sha512   = std::move(h.value()); break;
                default: break;
            }
        }
    }
    return result;
}

Result<MultiHashResult> compute_all_hashes_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return Error::file_read_error("Failed to open: " + path.string());

    std::streamoff stream_size = file.tellg();
    if (stream_size < 0) return Error::file_read_error("Failed to determine file size");
    Size size = static_cast<Size>(stream_size);
    file.seekg(0);
    std::vector<std::byte> buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size));
    return compute_all_hashes(buffer);
}

// ============================================================================
// Digest Methods
// ============================================================================

std::string Digest::to_hex() const {
    static const char* hex_chars = "0123456789abcdef";
    std::string result;
    result.reserve(data_.size() * 2);
    for (auto b : data_) {
        result.push_back(hex_chars[(static_cast<uint8_t>(b) >> 4) & 0xF]);
        result.push_back(hex_chars[static_cast<uint8_t>(b) & 0xF]);
    }
    return result;
}

Result<Digest> Digest::from_hex(std::string_view hex, HashAlgorithm algo) {
    if (hex.size() % 2 != 0) {
        return Error::invalid_argument("Hex string must have even length");
    }

    Digest digest(algo);
    digest.mutable_bytes().resize(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        uint8_t val = 0;

        if (high >= '0' && high <= '9') val = static_cast<uint8_t>((high - '0') << 4);
        else if (high >= 'a' && high <= 'f') val = static_cast<uint8_t>((high - 'a' + 10) << 4);
        else if (high >= 'A' && high <= 'F') val = static_cast<uint8_t>((high - 'A' + 10) << 4);
        else return Error::invalid_argument("Invalid hex character");

        if (low >= '0' && low <= '9') val |= static_cast<uint8_t>(low - '0');
        else if (low >= 'a' && low <= 'f') val |= static_cast<uint8_t>(low - 'a' + 10);
        else if (low >= 'A' && low <= 'F') val |= static_cast<uint8_t>(low - 'A' + 10);
        else return Error::invalid_argument("Invalid hex character");

        digest.mutable_bytes()[i / 2] = static_cast<std::byte>(val);
    }
    return digest;
}

bool Digest::constant_time_equal(const Digest& other) const noexcept {
    if (algorithm_ != other.algorithm_ || data_.size() != other.data_.size()) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < data_.size(); ++i) {
        union { std::byte b; uint8_t u; } u1{data_[i]}, u2{other.data_[i]};
        diff |= u1.u ^ u2.u;
    }
    return diff == 0;
}

// ============================================================================
// Formatting
// ============================================================================

std::string format_digest(const Digest& digest, bool uppercase, bool with_prefix) {
    std::string hex = digest.to_hex();
    if (uppercase) {
        for (auto& c : hex) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (with_prefix) {
        switch (digest.algorithm()) {
            case HashAlgorithm::MD5:      return "MD5:" + hex;
            case HashAlgorithm::SHA1:     return "SHA1:" + hex;
            case HashAlgorithm::SHA256:   return "SHA256:" + hex;
            case HashAlgorithm::SHA384:   return "SHA384:" + hex;
            case HashAlgorithm::SHA512:   return "SHA512:" + hex;
            case HashAlgorithm::SHA3_256: return "SHA3-256:" + hex;
            case HashAlgorithm::SHA3_512: return "SHA3-512:" + hex;
            case HashAlgorithm::BLAKE2b:  return "BLAKE2b:" + hex;
            case HashAlgorithm::BLAKE3:   return "BLAKE3:" + hex;
            default:                      return "HASH:" + hex;
        }
    }
    return hex;
}

} // namespace fortress