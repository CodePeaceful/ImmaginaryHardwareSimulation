#include "Assembler.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <cstring>

Assembler::Assembler(const std::filesystem::path& inputFile) : inputFile(inputFile) {}

void Assembler::assemble(const std::filesystem::path& outputFile) {
    // Read the input file
    std::vector<std::string> lines;
    std::ifstream in(inputFile);
    if (!in.is_open()) {
        throw std::runtime_error("Failed to open input file: " + inputFile.string());
    }

    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    in.close();

    // First pass to collect labels and calculate addresses
    firstPass(lines);

    // Second pass to generate machine code
    std::vector<uint8_t> machineCode = secondPass(lines);

    // Write the machine code to the output file
    std::ofstream outputFileStream(outputFile, std::ios::binary);
    if (!outputFileStream.is_open()) {
        throw std::runtime_error("Failed to open output file: " + outputFile.string());
    }
    outputFileStream.write(reinterpret_cast<const char*>(machineCode.data()), machineCode.size());
}

void Assembler::firstPass(const std::vector<std::string>& lines) {
    uint32_t currentAddress = 0;
    for (const auto& line : lines) {
        if (line.empty() || line[0] == ';') {
            continue; // Skip empty lines and comments
        }
        if (std::isspace(line[0])) {
            currentAddress = getIndentedNewAddress(line, currentAddress);
        }
        else {
            handleCompileTimeLabel(line, currentAddress);
        }
    }
}

uint32_t Assembler::getIndentedNewAddress(const std::string& line, uint32_t currentAddress) {
    auto it = std::ranges::find_if(line, [](char c) { return !std::isspace(c); });
    if (it != line.end()) {
        if (*it == '.') {
            return getDotDirectiveNewAddress(line, currentAddress);
        }
        else if (std::isalpha(*it)) {
            return currentAddress + getInstructionLength(line);
        }
        // Handle other cases if necessary
    }
    return currentAddress;
}

void trim(std::string& s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), s.end());
}

void Assembler::handleCompileTimeLabel(const std::string& line, uint32_t currentAddress) {
    // = or : first
    auto equalPos = line.find('=');
    auto colonPos = line.find(':');
    auto semicolonPos = line.find(';');
    if (equalPos < colonPos) {
        std::string label = line.substr(0, equalPos);
        std::string valueStr = line.substr(equalPos + 1, semicolonPos != std::string::npos ? semicolonPos - equalPos - 1 : std::string::npos);
        valueStr.erase(std::remove_if(valueStr.begin(), valueStr.end(), ::isspace), valueStr.end());
        if (u8_defines.contains(label) || labels_u16_defines.contains(label) || u32_defines.contains(label) || f32_defines.contains(label)) {
            throw std::runtime_error("Duplicate define: " + label);
        }
        if (label.empty() || !std::isalpha(label[0]) || !std::all_of(label.begin(), label.end(), [](char c) { return std::isalnum(c) || c == '_'; })) {
            throw std::runtime_error("Invalid define name: " + label);
        }
        trim(valueStr);
        trim(label);
        // is it binary, hex, decimal or float?
        if (valueStr.find('.') != std::string::npos) {
            f32_defines[label] = std::stof(valueStr);
        }
        else {
            auto value = readIntegerLiteral(valueStr);
            if (value <= 0xFF) {
                u8_defines[label] = value;
            }
            else if (value <= 0xFFFF) {
                labels_u16_defines[label] = value;
            }
            else if (value <= 0xFFFFFFFF) {
                u32_defines[label] = value;
            }
            else {
                throw std::runtime_error("Value out of range for define: " + label);
            }
        }
    }
    else if (colonPos != std::string::npos) {
        std::string label = line.substr(0, colonPos);
        if (labels_u16_defines.contains(label)) {
            throw std::runtime_error("Duplicate label: " + label);
        }
        if (u8_defines.contains(label) || u32_defines.contains(label) || f32_defines.contains(label)) {
            throw std::runtime_error("Label conflicts with existing define: " + label);
        }
        if (label.empty() || !std::isalpha(label[0]) || !std::all_of(label.begin(), label.end(), [](char c) { return std::isalnum(c) || c == '_'; })) {
            throw std::runtime_error("Invalid label name: " + label);
        }
        labels_u16_defines[label] = currentAddress;
    }
}

uint32_t Assembler::getInstructionLength(const std::string& line) {
    // split the line into tokens
    std::istringstream iss(line);
    std::vector<std::string> tokens{std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>{}};
    // remove everything after ; (comment)
    auto semicolonPos = line.find(';');
    if (semicolonPos != std::string::npos) {
        std::string codePart = line.substr(0, semicolonPos);
        std::istringstream codeIss(codePart);
        tokens = {std::istream_iterator<std::string>{codeIss}, std::istream_iterator<std::string>{}};
    }

    if (tokens.empty()) {
        return 0;
    }
    std::string instruction = tokens[0];
    // check parameters
    if (tokens.size() == 1) {
        return getInstructionLengthNoParameters(instruction);
    }
    if (tokens.size() == 2) {
        std::string param = tokens[1];
        return getInstructionLengthOneParameter(instruction, param);
    }
    if (tokens.size() == 3) {
        std::string param1 = tokens[1];
        std::string param2 = tokens[2];
        return getInstructionLengthTwoParameters(instruction, param1, param2);
    }
    if (tokens.size() == 4) {
        std::string param1 = tokens[1];
        std::string param2 = tokens[2];
        std::string param3 = tokens[3];
        return getInstructionLengthThreeParameters(instruction, param1, param2, param3);
    }
    throw std::runtime_error("Too many parameters for instruction: " + line);
}

uint32_t Assembler::getInstructionLengthNoParameters(const std::string& instruction) {
    if (noParameterMap.contains(instruction)) {
        return noParameterMap[instruction];
    }
    throw std::runtime_error("Unknown instruction with no parameters: " + instruction);
}

uint32_t Assembler::getInstructionLengthOneParameter(const std::string& instruction, std::string& param) {
    if (param[0] == '*') {
        param = param.substr(1);
        // register or immediate?
        if (pointerMap.contains(instruction)) {
            return std::ranges::contains(wordRegisterNames, param) ? 2 : 4;
        }
    }
    if (target8bitMap.contains(instruction) && (std::ranges::contains(byteRegisterNames, param) || param == "flags")) {
        return 2;
    }
    if (target16bitMap.contains(instruction) && std::ranges::contains(wordRegisterNames, param)) {
        return 2;
    }
    if (target32bitMap.contains(instruction) && std::ranges::contains(dwordRegisterNames, param)) {
        return 2;
    }
    if (targetFloatMap.contains(instruction) && std::ranges::contains(floatRegisterNames, param)) {
        return 2;
    }
    throw std::runtime_error("Unknown instruction or parameter: " + instruction + " " + param);
}

uint32_t Assembler::getInstructionLengthTwoParameters(const std::string& instruction, const std::string& param1, std::string& param2) {
    if (param1[0] == '*') {
        throw std::runtime_error("Invalid first parameter for two-parameter instruction: " + param1);
    }
    if (param2[0] == '*') {
        param2 = param2.substr(1);
        if (pointerMap.contains(instruction)) {
            return std::ranges::contains(wordRegisterNames, param2) ? 2 : 4;
        }
        throw std::runtime_error("Unknown instruction or parameter: " + instruction + " " + param1 + " " + param2);
    }
    if (std::ranges::contains(byteRegisterNames, param1)) {
        if (std::ranges::contains(wordRegisterNames, param2)) {
            if (targetSourceMultySizeMap.contains(instruction)) {
                return 2;
            }
            throw std::runtime_error("Unknown instruction for byte to word operation: " + instruction);
        }
        if (std::ranges::contains(dwordRegisterNames, param2) || std::ranges::contains(floatRegisterNames, param2)) {
            throw std::runtime_error("No instruction for byte to dword/float operation");
        }
        if (targetSourceSource8bitMap.contains(instruction)) {
            return instruction == "cmp" && !std::ranges::contains(wordRegisterNames, param2) ? 4 : 2;
        }
        throw std::runtime_error("Unknown instruction for byte to byte operation: " + instruction);
    }
    if (std::ranges::contains(wordRegisterNames, param1)) {
        if (std::ranges::contains(byteRegisterNames, param2)) {
            if (targetSourceMultySizeMap.contains(instruction)) {
                return 2;
            }
            throw std::runtime_error("Unknown instruction for word to byte operation: " + instruction);
        }
        if (std::ranges::contains(dwordRegisterNames, param2)) {
            if (targetSourceMultySizeMap.contains(instruction)) {
                return 2;
            }
            throw std::runtime_error("Unknown instruction for word to dword operation: " + instruction);
        }
        if (std::ranges::contains(floatRegisterNames, param2)) {
            throw std::runtime_error("No instruction for word to float operation");
        }
        if (targetSourceSource16bitMap.contains(instruction)) {
            return std::ranges::contains(wordRegisterNames, param2) ? 2 : 4;
        }
        throw std::runtime_error("Unknown instruction for word to word operation: " + instruction);
    }
    if (std::ranges::contains(dwordRegisterNames, param1)) {
        if (std::ranges::contains(byteRegisterNames, param2)) {
            throw std::runtime_error("No instruction for dword to byte operation");
        }
        if (std::ranges::contains(wordRegisterNames, param2)) {
            if (targetSourceMultySizeMap.contains(instruction)) {
                return 2;
            }
            throw std::runtime_error("Unknown instruction for dword to word operation: " + instruction);
        }
        if (std::ranges::contains(floatRegisterNames, param2)) {
            if (targetSourceMultySizeMap.contains(instruction)) {
                return 2;
            }
            throw std::runtime_error("Unknown instruction for dword to float operation: " + instruction);
        }
        if (targetSourceSource32bitMap.contains(instruction)) {
            return std::ranges::contains(dwordRegisterNames, param2) ? 2 : 6;
        }
        throw std::runtime_error("Unknown instruction for dword to dword operation: " + instruction);
    }
    if (std::ranges::contains(floatRegisterNames, param1)) {
        if (std::ranges::contains(byteRegisterNames, param2) || std::ranges::contains(wordRegisterNames, param2)) {
            throw std::runtime_error("No instruction for float to byte/word operation");
        }
        if (std::ranges::contains(dwordRegisterNames, param2)) {
            if (targetSourceMultySizeMap.contains(instruction)) {
                return 2;
            }
            throw std::runtime_error("Unknown instruction for float to dword operation: " + instruction);
        }
        if (targetSourceSourceFloatMap.contains(instruction)) {
            return std::ranges::contains(floatRegisterNames, param2) ? 2 : 6;
        }
        throw std::runtime_error("Unknown instruction for float to float operation: " + instruction);
    }
}

uint32_t Assembler::getInstructionLengthThreeParameters(const std::string& instruction, const std::string& param1, std::string& param2, std::string& param3) {
    if (param1[0] == '*') {
        throw std::runtime_error("Invalid first parameter for three-parameter instruction: " + param1);
    }
    if (param2[0] == '*' ^ param3[0] == '*') {
        throw std::runtime_error("None or both of the last two parameters must be a pointer for three-parameter instructions: " + param2 + " " + param3);
    }
    if (param2[0] == '*' && param3[0] == '*') {
        param2 = param2.substr(1);
        param3 = param3.substr(1);
        if (std::ranges::contains(byteRegisterNames, param1)) {
            if (targetPointerPointer8bitMap.contains(instruction)) {
                if (std::ranges::contains(wordRegisterNames, param2) && std::ranges::contains(wordRegisterNames, param3)) {
                    return 2;
                }
                if (std::ranges::contains(wordRegisterNames, param2) || std::ranges::contains(wordRegisterNames, param3)) {
                    return 4;
                }
                throw std::runtime_error("only one pointer may be immediate for byte register three-parameter instruction: " + instruction + " " + param1 + " " + param2 + " " + param3);
            }
            throw std::runtime_error("Unknown instruction for byte register three-parameter operation: " + instruction);
        }
        if (std::ranges::contains(wordRegisterNames, param1)) {
            if (targetPointerPointer16bitMap.contains(instruction)) {
                if (std::ranges::contains(wordRegisterNames, param2) && std::ranges::contains(wordRegisterNames, param3)) {
                    return 2;
                }
                if (std::ranges::contains(wordRegisterNames, param2) || std::ranges::contains(wordRegisterNames, param3)) {
                    return 4;
                }
                throw std::runtime_error("only one pointer may be immediate for word register three-parameter instruction: " + instruction + " " + param1 + " " + param2 + " " + param3);
            }
            throw std::runtime_error("Unknown instruction for word register three-parameter operation: " + instruction);
        }
        if (std::ranges::contains(dwordRegisterNames, param1)) {
            if (targetPointerPointer32bitMap.contains(instruction)) {
                if (std::ranges::contains(wordRegisterNames, param2) && std::ranges::contains(wordRegisterNames, param3)) {
                    return 2;
                }
                if (std::ranges::contains(wordRegisterNames, param2) || std::ranges::contains(wordRegisterNames, param3)) {
                    return 4;
                }
                throw std::runtime_error("only one pointer may be immediate for dword register three-parameter instruction: " + instruction + " " + param1 + " " + param2 + " " + param3);
            }
            throw std::runtime_error("Unknown instruction for dword register three-parameter operation: " + instruction);
        }
        if (std::ranges::contains(floatRegisterNames, param1)) {
            if (targetPointerPointerFloatMap.contains(instruction)) {
                if (std::ranges::contains(wordRegisterNames, param2) && std::ranges::contains(wordRegisterNames, param3)) {
                    return 2;
                }
                if (std::ranges::contains(wordRegisterNames, param2) || std::ranges::contains(wordRegisterNames, param3)) {
                    return 4;
                }
                throw std::runtime_error("only one pointer may be immediate for float register three-parameter instruction: " + instruction + " " + param1 + " " + param2 + " " + param3);
            }
            throw std::runtime_error("Unknown instruction for float register three-parameter operation: " + instruction);
        }
    }
    if (param2[0] != '*' && param3[0] != '*') {
        if (std::ranges::contains(byteRegisterNames, param1)) {
            if (std::ranges::contains(wordRegisterNames, param2) && targetSourceSource8bitMap.contains(instruction)) {
                return 4;
            }
            throw std::runtime_error("Unknown instruction for byte register three-parameter operation: " + instruction);
        }
        if (std::ranges::contains(wordRegisterNames, param1)) {
            if (std::ranges::contains(wordRegisterNames, param2) && targetSourceSource16bitMap.contains(instruction)) {
                return std::ranges::contains(wordRegisterNames, param3) ? 2 : 4;
            }
            throw std::runtime_error("Unknown instruction for word register three-parameter operation: " + instruction);
        }
        if (std::ranges::contains(dwordRegisterNames, param1)) {
            if (std::ranges::contains(wordRegisterNames, param2) && targetSourceSource32bitMap.contains(instruction)) {
                return std::ranges::contains(wordRegisterNames, param3) ? 2 : 6;
            }
            throw std::runtime_error("Unknown instruction for dword register three-parameter operation: " + instruction);
        }
        if (std::ranges::contains(floatRegisterNames, param1)) {
            if (std::ranges::contains(wordRegisterNames, param2) && targetSourceSourceFloatMap.contains(instruction)) {
                return std::ranges::contains(wordRegisterNames, param3) ? 2 : 6;
            }
            throw std::runtime_error("Unknown instruction for float register three-parameter operation: " + instruction);
        }
        if (param1 == "dis") {
            if (std::ranges::contains(byteRegisterNames, param2) && targetSourceSource8bitMap.contains(instruction)) {
                return 4;
            }
            if (std::ranges::contains(wordRegisterNames, param2) && targetSourceSource16bitMap.contains(instruction)) {
                return std::ranges::contains(wordRegisterNames, param3) ? 2 : 4;
            }
            if (std::ranges::contains(dwordRegisterNames, param2) && targetSourceSource32bitMap.contains(instruction)) {
                return std::ranges::contains(wordRegisterNames, param3) ? 2 : 6;
            }
            if (std::ranges::contains(floatRegisterNames, param2) && targetSourceSourceFloatMap.contains(instruction)) {
                return std::ranges::contains(wordRegisterNames, param3) ? 2 : 6;
            }
            throw std::runtime_error("Unknown instruction for discard three-parameter operation: " + instruction);
        }
    }
    throw std::runtime_error("Invalid parameters for three-parameter instruction: " + instruction + " " + param1 + " " + param2 + " " + param3);
}

uint32_t Assembler::getDotDirectiveNewAddress(const std::string& line, uint32_t currentAddress) {
    std::istringstream iss(line);
    std::vector<std::string> tokens{std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>{}};
    if (tokens.size() == 2) {
        std::string directive = tokens[0];
        std::string valueStr = tokens[1];
        valueStr.erase(std::remove_if(valueStr.begin(), valueStr.end(), ::isspace), valueStr.end());
        if (directive == ".org") {
            return readIntegerLiteral(valueStr);
        }
        if (directive == ".byte") {
            return currentAddress + 1;
        }
        if (directive == ".word") {
            return currentAddress + 2;
        }
        if (directive == ".dword") {
            return currentAddress + 4;
        }
        if (directive == ".float") {
            return currentAddress + 4;
        }
    }
    if (tokens.size() == 1) {
        std::string directive = tokens[0];
        if (directive == ".page_start") {
            return (currentAddress + 0x1ff) & ~0x1ff; // align to next 512-byte page
        }
    }
    throw std::runtime_error("Unknown . directive: " + tokens[0]);
}

uint32_t Assembler::readIntegerLiteral(const std::string& literal) {
    if (literal.starts_with("0b")) {
        return std::stoul(literal.substr(2), nullptr, 2);
    }
    if (literal.starts_with("0x")) {
        return std::stoul(literal.substr(2), nullptr, 16);
    }
    return std::stoul(literal);
}

std::vector<uint8_t> Assembler::secondPass(const std::vector<std::string>& lines) {
    std::vector<uint8_t> machineCode;
    uint32_t currentAddress = 0;
    for (const auto& line : lines) {
        if (line.empty() || line[0] == ';') {
            continue; // Skip empty lines and comments
        }
        // ignoring labels as they are already handled and maped to addresses in the first pass
        if (std::isspace(line[0])) {
            auto it = std::ranges::find_if(line, [](char c) { return !std::isspace(c); });
            if (it != line.end()) {
                if (*it == '.') {
                    uint32_t pageOffset = currentAddress & 0x1ff;
                    currentAddress = getDotDirectiveNewAddress(line, currentAddress);
                    if (line.find(".page_start") != std::string::npos || line.find(".org") != std::string::npos) {
                        // fill with zeros until page offset aligned
                        while (currentAddress & 0x1ff != pageOffset) {
                            machineCode.push_back(0);
                            ++pageOffset;
                        }
                    }
                    // user defined data directives, read parameter and set values
                    else if (line.find(".byte") != std::string::npos) {
                        std::string valueStr = line.substr(line.find(".byte") + 5);
                        valueStr.erase(std::remove_if(valueStr.begin(), valueStr.end(), ::isspace), valueStr.end());
                        uint8_t value;
                        if (u8_defines.contains(valueStr)) {
                            value = u8_defines[valueStr];
                        }
                        else {
                            value = static_cast<uint8_t>(readIntegerLiteral(valueStr));
                        }
                        machineCode.push_back(value);
                    }
                    else if (line.find(".word") != std::string::npos) {
                        std::string valueStr = line.substr(line.find(".word") + 5);
                        valueStr.erase(std::remove_if(valueStr.begin(), valueStr.end(), ::isspace), valueStr.end());
                        uint16_t value;
                        if (labels_u16_defines.contains(valueStr)) {
                            value = labels_u16_defines[valueStr];
                        }
                        else if (u8_defines.contains(valueStr)) {
                            value = u8_defines[valueStr];
                        }
                        else {
                            value = static_cast<uint16_t>(readIntegerLiteral(valueStr));
                        }
                        machineCode.push_back(value & 0xff);
                        machineCode.push_back((value >> 8) & 0xff);
                    }
                    else if (line.find(".dword") != std::string::npos) {
                        std::string valueStr = line.substr(line.find(".dword") + 5);
                        valueStr.erase(std::remove_if(valueStr.begin(), valueStr.end(), ::isspace), valueStr.end());
                        uint32_t value;
                        if (u32_defines.contains(valueStr)) {
                            value = u32_defines[valueStr];
                        }
                        else if (labels_u16_defines.contains(valueStr)) {
                            value = labels_u16_defines[valueStr];
                        }
                        else if (u8_defines.contains(valueStr)) {
                            value = u8_defines[valueStr];
                        }
                        else {
                            value = static_cast<uint32_t>(readIntegerLiteral(valueStr));
                        }
                        machineCode.push_back(value & 0xff);
                        machineCode.push_back((value >> 8) & 0xff);
                        machineCode.push_back((value >> 16) & 0xff);
                        machineCode.push_back((value >> 24) & 0xff);
                    }
                    else if (line.find(".float") != std::string::npos) {
                        std::string valueStr = line.substr(line.find(".float") + 6);
                        valueStr.erase(std::remove_if(valueStr.begin(), valueStr.end(), ::isspace), valueStr.end());
                        float value;
                        if (f32_defines.contains(valueStr)) {
                            value = f32_defines[valueStr];
                        }
                        else {
                            value = static_cast<float>(std::stof(valueStr));
                        }
                        // Convert float to bytes (assuming IEEE 754 format)
                        uint32_t floatAsInt;
                        std::memcpy(&floatAsInt, &value, sizeof(float));
                        machineCode.push_back(floatAsInt & 0xff);
                        machineCode.push_back((floatAsInt >> 8) & 0xff);
                        machineCode.push_back((floatAsInt >> 16) & 0xff);
                        machineCode.push_back((floatAsInt >> 24) & 0xff);
                    }
                }
                else if (std::isalpha(*it)) {
                    auto instructionLength = getInstructionLength(line);
                    auto instructionMachineCode = generateMachineCodeForInstruction(line);
                    machineCode.insert(machineCode.end(), instructionMachineCode.begin(), instructionMachineCode.end());
                    currentAddress += instructionLength;
                }
                // Handle other cases if necessary
            }
        }
    }
    return machineCode;
}

std::vector<uint8_t> Assembler::generateMachineCodeForInstruction(const std::string& line) {
    // split the line into tokens
    std::istringstream iss(line);
    std::vector<std::string> tokens{std::istream_iterator<std::string>{iss}, std::istream_iterator<std::string>{}};
    // remove everything after ; (comment)
    auto semicolonPos = line.find(';');
    if (semicolonPos != std::string::npos) {
        std::string codePart = line.substr(0, semicolonPos);
        std::istringstream codeIss(codePart);
        tokens = {std::istream_iterator<std::string>{codeIss}, std::istream_iterator<std::string>{}};
    }

    if (tokens.empty()) {
        return { };
    }
    std::string instruction = tokens[0];
    // check parameters
    if (tokens.size() == 1) {
        return getInstructionCodeNoParameters(instruction);
    }
    if (tokens.size() == 2) {
        std::string param = tokens[1];
        return getInstructionCodeOneParameter(instruction, param);
    }
    if (tokens.size() == 3) {
        std::string param1 = tokens[1];
        std::string param2 = tokens[2];
        return getInstructionCodeTwoParameters(instruction, param1, param2);
    }
    if (tokens.size() == 4) {
        std::string param1 = tokens[1];
        std::string param2 = tokens[2];
        std::string param3 = tokens[3];
        return getInstructionCodeThreeParameters(instruction, param1, param2, param3);
    }
    throw std::runtime_error("Too many parameters for instruction: " + line);
}

std::vector<uint8_t> Assembler::getInstructionCodeNoParameters(const std::string& instruction) {
    uint16_t opcode = noParameterMap[instruction];
    return {static_cast<uint8_t>((opcode >> 8) & 0xFF), static_cast<uint8_t>(opcode & 0xFF)};
}

std::vector<uint8_t> Assembler::getInstructionCodeOneParameter(const std::string& instruction, std::string& param) {
    if (param[0] == '*') {
        param = param.substr(1);
        uint16_t opcode = pointerMap[instruction];
        std::vector<uint8_t> code{static_cast<uint8_t>((opcode >> 8) & 0xFF), static_cast<uint8_t>(opcode & 0xFF)};
        if (std::ranges::contains(wordRegisterNames, param)) {
            // set register id in opcode
            code[1] |= std::distance(wordRegisterNames.begin(), std::ranges::find(wordRegisterNames, param));
            return code;
        }
        // immediate value (register id 7)
        code[1] |= 7;
        uint32_t immediate = readIntegerLiteral(param);
        code.push_back(static_cast<uint8_t>(immediate & 0xFF));
        code.push_back(static_cast<uint8_t>((immediate >> 8) & 0xFF));
        return code;
    }
    if (std::ranges::contains(byteRegisterNames, param) || param == "flags") {
        uint16_t opcode = target8bitMap[instruction];
        std::vector<uint8_t> code{static_cast<uint8_t>((opcode >> 8) & 0xFF), static_cast<uint8_t>(opcode & 0xFF)};
        if (param == "flags") {
            code[1] |= 7; // flags register id
        }
        else {
            code[1] |= std::distance(byteRegisterNames.begin(), std::ranges::find(byteRegisterNames, param));
        }
        return code;
    }
    if (std::ranges::contains(wordRegisterNames, param)) {
        uint16_t opcode = target16bitMap[instruction];
        std::vector<uint8_t> code{static_cast<uint8_t>((opcode >> 8) & 0xFF), static_cast<uint8_t>(opcode & 0xFF)};
        code[1] |= std::distance(wordRegisterNames.begin(), std::ranges::find(wordRegisterNames, param));
        return code;
    }
    if (std::ranges::contains(dwordRegisterNames, param)) {
        uint16_t opcode = target32bitMap[instruction];
        std::vector<uint8_t> code{static_cast<uint8_t>((opcode >> 8) & 0xFF), static_cast<uint8_t>(opcode & 0xFF)};
        code[1] |= std::distance(dwordRegisterNames.begin(), std::ranges::find(dwordRegisterNames, param));
        return code;
    }
    if (std::ranges::contains(floatRegisterNames, param)) {
        uint16_t opcode = targetFloatMap[instruction];
        std::vector<uint8_t> code{static_cast<uint8_t>((opcode >> 8) & 0xFF), static_cast<uint8_t>(opcode & 0xFF)};
        code[1] |= std::distance(floatRegisterNames.begin(), std::ranges::find(floatRegisterNames, param));
        return code;
    }
    throw std::runtime_error("Unknown instruction or parameter: " + instruction + " " + param);
}
