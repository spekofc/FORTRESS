# FORTRESS CLI

add_executable(fortress
    main.cpp
    analyze_cmd.cpp
    cfg_cmd.cpp
    output.cpp
)

target_link_libraries(fortress PRIVATE
    fortress_core
    fortress_binary
    LLVMSupport
    nlohmann_json::nlohmann_json
)

target_include_directories(fortress PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_BINARY_DIR}/include
)

# Install
install(TARGETS fortress
    RUNTIME DESTINATION bin
)