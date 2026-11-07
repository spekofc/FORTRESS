// FORTRESS CLI - Output Helpers (placeholder)

#include <fortress/core/string_utils.h>
#include <iostream>

namespace fortress::cli {

void print_banner() {
    std::cout << "FORTRESS " << FORTRESS_VERSION_STRING << "\n";
}

void print_error(const std::string& msg) {
    std::cerr << "Error: " << msg << "\n";
}

void print_warning(const std::string& msg) {
    std::cerr << "Warning: " << msg << "\n";
}

void print_info(const std::string& msg) {
    std::cout << msg << "\n";
}

} // namespace fortress::cli