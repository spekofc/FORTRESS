// FORTRESS CLI - Main Entry Point

#include <fortress/core/error.h>
#include <fortress/core/version.h>
#include <fortress/core/string_utils.h>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>

namespace fortress::cli {

struct Command {
    std::string name;
    std::string description;
    std::string usage;
    std::function<int(const std::vector<std::string>&)> handler;
};

class CLI {
public:
    CLI(int argc, char* argv[]) : args_(argv, argv + argc) {}

    int run() {
        if (args_.size() < 2) {
            print_help();
            return 1;
        }

        std::string command = args_[1];

        if (command == "help" || command == "--help" || command == "-h") {
            print_help();
            return 0;
        }

        if (command == "version" || command == "--version") {
            print_version();
            return 0;
        }

        auto it = commands_.find(command);
        if (it == commands_.end()) {
            std::cerr << "Error: Unknown command '" << command << "'\n";
            std::cerr << "Run 'fortress help' for usage.\n";
            return 1;
        }

        std::vector<std::string> cmd_args(args_.begin() + 2, args_.end());
        return it->second.handler(cmd_args);
    }

    void register_command(const Command& cmd) {
        commands_[cmd.name] = cmd;
    }

private:
    std::vector<std::string> args_;
    std::unordered_map<std::string, Command> commands_;

    void print_version() {
        std::cout << "FORTRESS " << FORTRESS_VERSION_STRING << "\n";
        std::cout << "Professional open-source code virtualizer\n";
        std::cout << "https://github.com/fortress-project/fortress\n";
    }

    void print_help() {
        print_version();
        std::cout << "\nUsage: fortress <command> [options]\n\n";
        std::cout << "Commands:\n";

        std::vector<std::pair<std::string, std::string>> sorted;
        for (const auto& [name, cmd] : commands_) {
            sorted.emplace_back(name, cmd.description);
        }
        std::sort(sorted.begin(), sorted.end());

        for (const auto& [name, desc] : sorted) {
            std::cout << "  " << std::left << std::setw(16) << name << desc << "\n";
        }

        std::cout << "\nRun 'fortress <command> --help' for command-specific help.\n";
    }
};

} // namespace fortress::cli

// Forward declarations
int analyze_command(const std::vector<std::string>& args);

int main(int argc, char* argv[]) {
    fortress::cli::CLI cli(argc, argv);

    cli.register_command({"analyze", "Analyze a binary file", "fortress analyze -i <file> [options]", analyze_command});

    // TODO: Add more commands as implemented
    // cli.register_command({"protect", "Protect a binary", "fortress protect -i <file> -o <output> [options]", protect_command});
    // cli.register_command({"vm", "Manage virtual machines", "fortress vm [subcommand]", vm_command});
    // cli.register_command({"build", "Build a project", "fortress build [options]", build_command});

    try {
        return cli.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}