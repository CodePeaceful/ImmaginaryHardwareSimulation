#include "iostream"
#include "filesystem"

#include "Assembler.hpp"

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: assembler <input file> <output file>";
        return 1;
    }

    std::filesystem::path inputFile = argv[1];
    std::filesystem::path outputFile = argv[2];

    try {
        Assembler assembler(inputFile);
        assembler.assemble(outputFile);
        std::cout << "Assembly successful. Output written to " << outputFile;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what();
        return 1;
    }

    return 0;
}