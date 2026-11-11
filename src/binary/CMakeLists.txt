# FORTRESS Binary Library

add_library(fortress_binary STATIC
    analysis/analyzer.cpp
    analysis/analysis_model.cpp
    analysis/cfg_builder.cpp
    analysis/call_graph.cpp
    analysis/function_refiner.cpp
    analysis/xref.cpp
    analysis/llvm_disassembler.cpp
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
    LLVMX86CodeGen
    LLVMX86Disassembler
    LLVMX86AsmParser
    LLVMX86Desc
    LLVMX86Info
    LLVMX86TargetMCA
)

# Propagate FORTRESS_USE_LLVM_DISASSEMBLER option to C++ as a compile definition
target_compile_definitions(fortress_binary PUBLIC
    FORTRESS_USE_LLVM_DISASSEMBLER=$<BOOL:${FORTRESS_USE_LLVM_DISASSEMBLER}>
)

# Propagate LLVM include directories through target_link_libraries
# The LLVM targets provide INTERFACE_INCLUDE_DIRECTORIES automatically

target_include_directories(fortress_binary PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<INSTALL_INTERFACE:include>
)

# Install headers
install(FILES
    ../../include/fortress/binary/analysis/binary_info.h
    ../../include/fortress/binary/analysis/analyzer.h
    ../../include/fortress/binary/analysis/analysis_model.h
    ../../include/fortress/binary/analysis/cfg_builder.h
    ../../include/fortress/binary/analysis/call_graph.h
    ../../include/fortress/binary/analysis/xref.h
    ../../include/fortress/binary/analysis/function_refiner.h
    ../../include/fortress/binary/formats/pe/pe_parser.h
    ../../include/fortress/binary/formats/pe/pe_address_converter.h
    ../../include/fortress/binary/formats/elf/elf_parser.h
    ../../include/fortress/binary/formats/elf/elf_address_converter.h
    ../../include/fortress/binary/formats/macho/macho_parser.h
    ../../include/fortress/binary/formats/macho/macho_address_converter.h
    DESTINATION include/fortress/binary
)