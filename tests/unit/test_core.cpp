// FORTRESS Core Tests

#include <fortress/core/error.h>
#include <fortress/core/file_utils.h>
#include <fortress/core/hash.h>
#include <fortress/core/string_utils.h>
#include <fortress/core/types.h>
#include <gtest/gtest.h>

using namespace fortress;

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
    EXPECT_TRUE(err.context().find("test.bin") != std::string::npos);
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
    EXPECT_EQ(result->size(), 32);
    EXPECT_EQ(result->algorithm(), HashAlgorithm::SHA256);

    // Known test vector: SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    EXPECT_EQ(result->to_hex(), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(CoreHash, SHA1) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::SHA1, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result->size(), 20);

    // Known test vector: SHA1("hello world") = 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
    EXPECT_EQ(result->to_hex(), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

TEST(CoreHash, MD5) {
    std::string data = "hello world";
    auto result = hash_data(HashAlgorithm::MD5, {reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);
    EXPECT_EQ(result->size(), 16);

    // Known test vector: MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
    EXPECT_EQ(result->to_hex(), "5eb63bbbe01eeed093cb22bb8f5acdc3");
}

TEST(CoreHash, MultiHash) {
    std::string data = "test";
    auto result = compute_all_hashes({reinterpret_cast<const std::byte*>(data.data()), data.size()});
    ASSERT_TRUE(result);

    EXPECT_TRUE(result.md5.has_value());
    EXPECT_TRUE(result.sha1.has_value());
    EXPECT_TRUE(result.sha256.has_value());
    EXPECT_TRUE(result.sha512.has_value());
}

TEST(CoreHash, Entropy) {
    // Low entropy - all same byte
    std::vector<std::byte> low(100, std::byte{0x00});
    double low_ent = calculate_entropy(low);
    EXPECT_NEAR(low_ent, 0.0, 0.01);

    // High entropy - random-ish
    std::vector<std::byte> high(256);
    for (int i = 0; i < 256; ++i) high[i] = static_cast<std::byte>(i);
    double high_ent = calculate_entropy(high);
    EXPECT_NEAR(high_ent, 8.0, 0.1);

    // Per-block
    auto blocks = calculate_entropy_per_block(high, 64);
    EXPECT_EQ(blocks.size(), 4);
}

TEST(CoreHash, CRC32) {
    std::string data = "hello world";
    uint32_t crc = crc32({reinterpret_cast<const std::byte*>(data.data()), data.size()});
    // Known CRC32 of "hello world"
    EXPECT_EQ(crc, 0xD4A1185E);
}

TEST(CoreHash, XXH64) {
    std::string data = "hello world";
    uint64_t hash = xxh64({reinterpret_cast<const std::byte*>(data.data()), data.size()}, 0);
    EXPECT_NE(hash, 0);
}

TEST(CoreFileUtils, Path) {
    auto exe = get_executable_path();
    EXPECT_FALSE(exe.empty());

    auto dir = get_executable_directory();
    EXPECT_FALSE(dir.empty());
    EXPECT_TRUE(is_directory(dir));
}

TEST(CoreFileUtils, TempFile) {
    auto temp = create_temp_file("test_");
    ASSERT_TRUE(temp);
    EXPECT_TRUE(std::filesystem::exists(temp->path()));
    temp->release(); // Don't auto-delete
    std::filesystem::remove(temp->path());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}