// FORTRESS Core Tests

#include <fortress/core/error.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/hash.h>
#include <fortress/core/string_utils.h>
#include <fortress/core/types.h>
#include <gtest/gtest.h>

using namespace fortress;
using namespace fortress::file_utils;

TEST(CoreTypes, ArchitectureString) {
    EXPECT_EQ(to_string(Architecture::X86), "x86");
    EXPECT_EQ(to_string(Architecture::X64), "x64");
    EXPECT_EQ(to_string(Architecture::ARM64), "arm64");
    EXPECT_EQ(to_string(Architecture::Unknown), "unknown");

    EXPECT_EQ(architecture_from_string("x86"), Architecture::X86);
    EXPECT_EQ(architecture_from_string("x64"), Architecture::X64);
    EXPECT_EQ(architecture_from_string("amd64"), Architecture::X64);
    EXPECT_EQ(architecture_from_string("arm64"), Architecture::ARM64);
    EXPECT_EQ(architecture_from_string("aarch64"), Architecture::ARM64);
    EXPECT_EQ(architecture_from_string("unknown"), Architecture::Unknown);
}

TEST(CoreTypes, BinaryFormatString) {
    EXPECT_EQ(to_string(BinaryFormat::PE), "PE");
    EXPECT_EQ(to_string(BinaryFormat::ELF), "ELF");
    EXPECT_EQ(to_string(BinaryFormat::MachO), "Mach-O");
    EXPECT_EQ(to_string(BinaryFormat::Unknown), "unknown");
}

TEST(CoreTypes, Permissions) {
    SectionPermission p = SectionPermission::Read | SectionPermission::Write;
    EXPECT_TRUE(has_permission(p, SectionPermission::Read));
    EXPECT_TRUE(has_permission(p, SectionPermission::Write));
    EXPECT_FALSE(has_permission(p, SectionPermission::Execute));

    SectionPermission all = SectionPermission::All;
    EXPECT_TRUE(has_permission(all, SectionPermission::Read));
    EXPECT_TRUE(has_permission(all, SectionPermission::Write));
    EXPECT_TRUE(has_permission(all, SectionPermission::Execute));
}

TEST(CoreError, Basic) {
    Error err = Error::invalid_argument("test message");
    EXPECT_TRUE(err);
    EXPECT_EQ(err.code(), ErrorCode::InvalidArgument);
    EXPECT_EQ(err.message(), "test message");

    Error success = Error::success();
    EXPECT_FALSE(success);
    EXPECT_EQ(success.code(), ErrorCode::Success);
}

TEST(CoreError, Context) {
    Error err = Error::file_not_found("test.bin").with_context("loading config");
    EXPECT_TRUE(err.has_context());
    // "test.bin" is in the message, "loading config" is in the context
    EXPECT_TRUE(err.message().find("test.bin") != std::string::npos);
    EXPECT_TRUE(err.context().find("loading config") != std::string::npos);
}

TEST(CoreError, Result) {
    Result<int> ok = Result<int>::ok(42);
    EXPECT_TRUE(ok);
    EXPECT_EQ(ok.value(), 42);

    Result<int> err = Result<int>::err(Error::invalid_argument("bad"));
    EXPECT_FALSE(err);
    EXPECT_EQ(err.error().code(), ErrorCode::InvalidArgument);
}

TEST(CoreStringUtils, Trim) {
    EXPECT_EQ(trim_copy("  hello  "), "hello");
    EXPECT_EQ(trim_copy("\t\nhello\r\n"), "hello");
    EXPECT_EQ(trim_copy(""), "");
    EXPECT_EQ(trim_copy("no_space"), "no_space");
}

TEST(CoreStringUtils, Split) {
    auto parts = split_copy("a,b,c", ',');
    ASSERT_EQ(parts.size(), 3);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");

    auto empty = split_copy("", ',');
    EXPECT_TRUE(empty.empty());
}

TEST(CoreStringUtils, Hex) {
    std::string data = "\x01\x02\xFF\xFE";
    EXPECT_EQ(to_hex(data), "0102fffe");
    EXPECT_EQ(to_hex(data, true), "0102FFFE");

    auto decoded = from_hex("0102fffe");
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), data);

    EXPECT_FALSE(from_hex("abc").has_value()); // odd length
    EXPECT_FALSE(from_hex("gg").has_value());  // invalid hex
}

TEST(CoreStringUtils, Format) {
    EXPECT_EQ(format_size(512), "512 B");
    EXPECT_EQ(format_size(1024), "1.00 KB");
    EXPECT_EQ(format_size(1024*1024), "1.00 MB");
    EXPECT_EQ(format_size(1024*1024*1024), "1.00 GB");

    EXPECT_EQ(format_address(0x1234), "0x0000000000001234");
    EXPECT_EQ(format_address(0, false), "0000000000000000");
}

TEST(CoreHash, SHA256) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::SHA256, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value().size(), 32);
    EXPECT_EQ(result.value().algorithm(), HashAlgorithm::SHA256);

    // Known test vector: SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    EXPECT_EQ(result.value().to_hex(), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(CoreHash, SHA1) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::SHA1, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value().size(), 20);

    // Known test vector: SHA1("hello world") = 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
    EXPECT_EQ(result.value().to_hex(), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

TEST(CoreHash, MD5) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value().size(), 16);

    // Known test vector: MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
    EXPECT_EQ(result.value().to_hex(), "5eb63bbbe01eeed093cb22bb8f5acdc3");
}

TEST(CoreHash, MD5_RFC1321) {
    // RFC 1321 test vectors (Section A.5)
    // "" (empty string)
    auto r0 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>(""), 0});
    ASSERT_TRUE(r0);
    EXPECT_EQ(r0.value().to_hex(), "d41d8cd98f00b204e9800998ecf8427e");

    // "a"
    auto r1 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>("a"), 1});
    ASSERT_TRUE(r1);
    EXPECT_EQ(r1.value().to_hex(), "0cc175b9c0f1b6a831c399e269772661");

    // "abc"
    auto r2 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>("abc"), 3});
    ASSERT_TRUE(r2);
    EXPECT_EQ(r2.value().to_hex(), "900150983cd24fb0d6963f7d28e17f72");

    // "message digest"
    auto r3 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>("message digest"), 14});
    ASSERT_TRUE(r3);
    EXPECT_EQ(r3.value().to_hex(), "f96b697d7cb7938d525a2f31aaf161d0");

    // "abcdefghijklmnopqrstuvwxyz"
    auto r4 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>("abcdefghijklmnopqrstuvwxyz"), 26});
    ASSERT_TRUE(r4);
    EXPECT_EQ(r4.value().to_hex(), "c3fcd3d76192e4007dfb496cca67e13b");

    // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    auto r5 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), 62});
    ASSERT_TRUE(r5);
    EXPECT_EQ(r5.value().to_hex(), "d174ab98d277d9f5a5611c2c9f419d9f");

    // 128-bit test: "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    auto r6 = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), 80});
    ASSERT_TRUE(r6);
    EXPECT_EQ(r6.value().to_hex(), "57edf4a22be3c955ac49da2e2107b67a");
}

TEST(CoreHash, SHA384) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::SHA384, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value().size(), 48);

    // Known test vector: SHA384("hello world") from OpenSSL default provider (FIPS 180-4 compliant)
    // SHA384("hello world") = fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd
    EXPECT_EQ(result.value().to_hex(), "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd");
}

TEST(CoreHash, SHA512) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::SHA512, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result.value().size(), 64);

    // Known test vector: SHA512("hello world") from OpenSSL default provider (FIPS 180-4 compliant)
    // SHA512("hello world") = 309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
    EXPECT_EQ(result.value().to_hex(), "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
}

TEST(CoreHash, MultiHash) {
    std::string data = "test";
    auto result = compute_all_hashes({reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);

    EXPECT_TRUE(result.value().md5.has_value());
    EXPECT_TRUE(result.value().sha1.has_value());
    EXPECT_TRUE(result.value().sha256.has_value());
    EXPECT_TRUE(result.value().sha384.has_value());
    EXPECT_TRUE(result.value().sha512.has_value());
}

TEST(CoreHash, UnsupportedAlgorithms) {
    // SHA3-256 should be available in OpenSSL 3.0+
    auto sha3_256_result = create_hash_context(HashAlgorithm::SHA3_256);
    if (sha3_256_result) {
        // If available, test it works with reference vector
        auto result = hash_data(HashAlgorithm::SHA3_256, {reinterpret_cast<const std::byte*>("hello world"), 11});
        ASSERT_TRUE(result);
        EXPECT_EQ(result.value().size(), 32);
        // SHA3-256("hello world") = 644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938
        EXPECT_EQ(result.value().to_hex(), "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938");
    } else {
        // If not available, should return proper error
        EXPECT_EQ(sha3_256_result.error().code(), ErrorCode::UnsupportedOperation);
    }

    // SHA3-512
    auto sha3_512_result = create_hash_context(HashAlgorithm::SHA3_512);
    if (sha3_512_result) {
        auto result = hash_data(HashAlgorithm::SHA3_512, {reinterpret_cast<const std::byte*>("hello world"), 11});
        ASSERT_TRUE(result);
        EXPECT_EQ(result.value().size(), 64);
        // SHA3-512("hello world") = 840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a
        EXPECT_EQ(result.value().to_hex(), "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
    } else {
        EXPECT_EQ(sha3_512_result.error().code(), ErrorCode::UnsupportedOperation);
    }

    // BLAKE2b
    auto blake2b_result = create_hash_context(HashAlgorithm::BLAKE2b);
    if (blake2b_result) {
        auto result = hash_data(HashAlgorithm::BLAKE2b, {reinterpret_cast<const std::byte*>("hello world"), 11});
        ASSERT_TRUE(result);
        EXPECT_EQ(result.value().size(), 64);
        // BLAKE2b("hello world") = 021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0
        EXPECT_EQ(result.value().to_hex(), "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0");
    } else {
        EXPECT_EQ(blake2b_result.error().code(), ErrorCode::UnsupportedOperation);
    }

    // BLAKE3 - should not be available
    auto blake3_result = create_hash_context(HashAlgorithm::BLAKE3);
    EXPECT_FALSE(blake3_result);
    EXPECT_EQ(blake3_result.error().code(), ErrorCode::UnsupportedOperation);
}

TEST(CoreHash, Entropy) {
    // Low entropy - all same byte
    std::vector<std::byte> low(100, std::byte{0x00});
    double low_ent = calculate_entropy(low);
    EXPECT_NEAR(low_ent, 0.0, 0.01);

    // High entropy - random-ish
    std::vector<std::byte> high(256);
    for (size_t i = 0; i < 256; ++i) high[i] = static_cast<std::byte>(i);
    double high_ent = calculate_entropy(high);
    EXPECT_NEAR(high_ent, 8.0, 0.1);

    // Per-block
    auto blocks = calculate_entropy_per_block(high, 64);
    EXPECT_EQ(blocks.size(), 4);
}

TEST(CoreHash, CRC32) {
    // Canonical test vector: CRC-32/ISO-HDLC of "123456789" = 0xCBF43926
    std::string data1 = "123456789";
    uint32_t crc1 = crc32({reinterpret_cast<const std::byte*>(data1.data()), data1.size()});
    EXPECT_EQ(crc1, 0xCBF43926);

    // CRC-32/ISO-HDLC of "hello world" = 0x0D4A1185 (little-endian representation)
    // The test previously expected 0xD4A1185E which is incorrect
    std::string data = "hello world";
    uint32_t crc2 = crc32({reinterpret_cast<const std::byte*>(data.data()), data.size()});
    EXPECT_EQ(crc2, 0x0D4A1185);
}

TEST(CoreHash, CRC32C) {
    // Canonical test vector: CRC-32C (Castagnoli) of "123456789" = 0xE3069283
    std::string data1 = "123456789";
    uint32_t crc1 = crc32c({reinterpret_cast<const std::byte*>(data1.data()), data1.size()});
    EXPECT_EQ(crc1, 0xE3069283);

    // CRC-32C (Castagnoli) of "hello world" = 0xC99465AA
    std::string data = "hello world";
    uint32_t crc2 = crc32c({reinterpret_cast<const std::byte*>(data.data()), data.size()});
    EXPECT_EQ(crc2, 0xC99465AA);
}

TEST(CoreHash, XXH64) {
    std::string data = "hello world";
    uint64_t hash = xxh64({reinterpret_cast<const std::byte*>(data.data()), data.size()}, 0);
    // Reference: xxHash64("hello world", seed=0) = 0xbb75740c8181914a
    EXPECT_EQ(hash, 0xbb75740c8181914aULL);
}

TEST(CoreFileUtils, Path) {
    auto exe = get_executable_path();
    EXPECT_FALSE(exe.empty());

    auto dir = get_executable_directory();
    EXPECT_FALSE(dir.empty());
    EXPECT_TRUE(fortress::file_utils::is_directory(dir));
}

TEST(CoreFileUtils, TempFile) {
    auto temp_result = create_temp_file("test_");
    ASSERT_TRUE(temp_result);
    auto& temp = temp_result.value();
    EXPECT_TRUE(std::filesystem::exists(temp.path()));
    temp.release(); // Don't auto-delete
    std::filesystem::remove(temp.path());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}