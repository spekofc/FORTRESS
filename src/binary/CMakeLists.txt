# FORTRESS Binary Library

add_library(fortress_binary STATIC
    analysis/analyzer.cpp
    formats/pe/pe_parser.cpp
    formats/elf/elf_parser.cpp
    formats/macho/macho_parser.cpp
)

target_link_libraries(fortress_binary PUBLIC
    fortress_core
    LLVMSupport
    LLVMDemangle
    LLVMObject
    LLVMBinaryFormat
    LLVMMC
    LLVMMCParser
    LLVMMCDisassembler
    LLVMTargetParser
)

target_include_directories(fortress_binary PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<INSTALL_INTERFACE:include>
)

# Install headers
install(FILES
    ../../include/fortress/binary/analysis/binary_info.h
    ../../include/fortress/binary/analysis/analyzer.h
    ../../include/fortress/binary/formats/pe/pe_parser.h
    ../../include/fortress/binary/formats/elf/elf_parser.h
    ../../include/fortress/binary/formats/macho/macho_parser.h
    DESTINATION include/fortress/binary
)