#include <iostream>
#include <memory>
#include <stdexcept>
#include <filesystem>

#include "Computer.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <kernel rom file> <storage file>\n";
        return 1;
    }
    try {
        std::unique_ptr<Computer> computer = std::make_unique<Computer>(argv[1], argv[2]);
        computer->run(0xFFFF'FFFF);
        computer->saveStorage(argv[2]);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return -1;
    }
    return 0;

}