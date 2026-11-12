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
# Workaround for GCC 16 + GoogleTest 1.14.0: -Werror=null-dereference false positive
# This is a known issue in GoogleTest 1.14.0 with GCC 16, not our code.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
# Disable -Werror=null-dereference for GoogleTest (known false positive in GCC 16)
target_compile_options(gtest PUBLIC $<$<CXX_COMPILER_ID:GNU>:-Wno-error=null-dereference>)
target_compile_options(gtest_main PUBLIC $<$<CXX_COMPILER_ID:GNU>:-Wno-error=null-dereference>)

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
    unit/test_analysis_model.cpp
    unit/test_cfg.cpp
    unit/test_call_graph.cpp
    unit/test_llvm_disassembler.cpp
    unit/test_xref.cpp
)

target_link_libraries(fortress_tests PRIVATE
    fortress_core
    fortress_binary
    gtest_main
    nlohmann_json::nlohmann_json
)

# Propagate LLVM disassembler option to tests
target_compile_definitions(fortress_tests PRIVATE
    FORTRESS_USE_LLVM_DISASSEMBLER=$<BOOL:${FORTRESS_USE_LLVM_DISASSEMBLER}>
)

# Add tests
add_test(NAME fortress_unit COMMAND fortress_tests)

# Test fixture paths
set(TEST_FIXTURES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fixtures)