# FORTRESS CLI

add_executable(fortress
    main.cpp
    analyze_cmd.cpp
    output.cpp
)

target_link_libraries(fortress PRIVATE
    fortress_core
    fortress_binary
    LLVMSupport
)

target_include_directories(fortress PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

# Install
install(TARGETS fortress
    RUNTIME DESTINATION bin
)