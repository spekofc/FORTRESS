# FORTRESS Tests

# Find nlohmann/json for CLI
find_package(nlohmann_json 3.10 REQUIRED)

# GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Test fixtures generation
add_custom_target(generate_fixtures
    COMMAND ${CMAKE_COMMAND} -E echo "Fixtures should be pre-built"
    COMMENT "Generating test fixtures"
)

# Unit tests
add_executable(fortress_tests
    unit/test_core.cpp
    unit/test_binary.cpp
    unit/test_pe.cpp
    unit/test_elf.cpp
    unit/test_macho.cpp
)

target_link_libraries(fortress_tests PRIVATE
    fortress_core
    fortress_binary
    gtest_main
    nlohmann_json::nlohmann_json
)

# Integration tests
add_executable(fortress_integration_tests
    integration/test_analyze.cpp
)

target_link_libraries(fortress_integration_tests PRIVATE
    fortress_core
    fortress_binary
    gtest_main
)

# Add tests
add_test(NAME fortress_unit COMMAND fortress_tests)
add_test(NAME fortress_integration COMMAND fortress_integration_tests)

# Test fixture paths
set(TEST_FIXTURES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fixtures)