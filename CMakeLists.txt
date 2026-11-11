# FORTRESS — Professional Open-Source Code Virtualizer
# Phase 2: Binary Analyzer Core
# CMake 3.25+, C++20, LLVM 18+

cmake_minimum_required(VERSION 3.25)
project(FORTRESS
    VERSION 0.1.0
    DESCRIPTION "Professional open-source code virtualizer - Binary Analyzer Core"
    LANGUAGES CXX
    HOMEPAGE_URL "https://github.com/fortress-project/fortress"
)

# C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Build options
option(FORTRESS_BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(FORTRESS_BUILD_TESTS "Build tests" ON)
option(FORTRESS_BUILD_CLI "Build CLI tool" ON)
option(FORTRESS_ENABLE_SANITIZERS "Enable sanitizers (Debug only)" OFF)
option(FORTRESS_USE_LLVM_DISASSEMBLER "Use LLVM MC disassembler" ON)

# Sanitizers for Debug builds
if(FORTRESS_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Warning flags
if(MSVC)
    add_compile_options(/W4 /WX /permissive- /std:c++20)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wconversion -Wsign-conversion -Wnull-dereference -Wformat=2)
    # Suppress system header warnings and third-party issues
    add_compile_options(-Wno-builtin-declaration-mismatch -Wno-attributes -Wno-template-body -Wno-double-promotion -Wno-sign-conversion)
endif()

# Enable C for LLVM's internal checks
enable_language(C)

# Find LLVM
find_package(LLVM REQUIRED CONFIG)

# Find nlohmann_json for CLI JSON output
find_package(nlohmann_json 3.10 REQUIRED)

# LLVM components needed for binary analysis and disassembly
set(LLVM_COMPONENTS
    Support
    Demangle
    Object
    BinaryFormat
    MC
    MCParser
    MCDisassembler
    TargetParser
)

# Add LLVM include directories from find_package
include_directories(${LLVM_INCLUDE_DIRS})

# Don't use LLVM_DEFINITIONS - it causes issues with multiple definitions in a single string
# The LLVM targets will handle their own compile definitions via target_link_libraries

# Set CMake module path for LLVM
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

# Use LLVM's AddLLVM.cmake for consistent settings
include(AddLLVM)

# Fortress version configuration
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/fortress/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/fortress/version.h"
)

# Subdirectories
add_subdirectory(src/core)
add_subdirectory(src/binary)
add_subdirectory(src/cli)

# Tests
if(FORTRESS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation
install(DIRECTORY include/fortress/
    DESTINATION include/fortress
    FILES_MATCHING PATTERN "*.h"
)

# CPack configuration for packaging
set(CPACK_PACKAGE_NAME "FORTRESS")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Professional open-source code virtualizer")
set(CPACK_PACKAGE_VENDOR "FORTRESS Project")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "FORTRESS")

include(CPack)