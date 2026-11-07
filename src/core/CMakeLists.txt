# FORTRESS Core Library

add_library(fortress_core STATIC
    error.cpp
    file_utils.cpp
    hash.cpp
)

target_link_libraries(fortress_core PUBLIC
    LLVMSupport
    LLVMDemangle
)

target_include_directories(fortress_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
    $<INSTALL_INTERFACE:include>
)

# Install headers
install(FILES
    ../../include/fortress/core/error.h
    ../../include/fortress/core/file_utils.h
    ../../include/fortress/core/hash.h
    ../../include/fortress/core/string_utils.h
    ../../include/fortress/core/types.h
    DESTINATION include/fortress/core
)