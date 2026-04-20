#pragma once

#include <filesystem>
#include <stdexcept>
#include <vector>
#include <map>

class Assembler
{
private:
    static std::map<std::string, uint16_t> targetSourceSource8bitMap;
    static std::map<std::string, uint16_t> targetSourceSource16bitMap;
    static std::map<std::string, uint16_t> targetSourceSource32bitMap;
    static std::map<std::string, uint16_t> targetSourceSourceFloatMap;

    static std::map<std::string, uint16_t> targetPointerPointer8bitMap;
    static std::map<std::string, uint16_t> targetPointerPointer16bitMap;
    static std::map<std::string, uint16_t> targetPointerPointer32bitMap;
    static std::map<std::string, uint16_t> targetPointerPointerFloatMap;

    static std::map<std::string, uint16_t> targetPointer8bitMap;
    static std::map<std::string, uint16_t> targetPointer16bitMap;
    static std::map<std::string, uint16_t> targetPointer32bitMap;
    static std::map<std::string, uint16_t> targetPointerFloatMap;

    static std::map<std::string, uint16_t> targetSource8bitMap;
    static std::map<std::string, uint16_t> targetSource16bitMap;
    static std::map<std::string, uint16_t> targetSource32bitMap;
    static std::map<std::string, uint16_t> targetSourceFloatMap;

    static std::map<std::string, uint16_t> targetSourceMultySizeMap;

    static std::map<std::string, uint16_t> target8bitMap;
    static std::map<std::string, uint16_t> target16bitMap;
    static std::map<std::string, uint16_t> target32bitMap;
    static std::map<std::string, uint16_t> targetFloatMap;

    static std::map<std::string, uint16_t> pointerMap;

    static std::map<std::string, uint16_t> noParameterMap;

    static std::array<std::string, 14> byteRegisterNames;
    static std::array<std::string, 6> wordRegisterNames;
    static std::array<std::string, 3> dwordRegisterNames;
    static std::array<std::string, 3> floatRegisterNames;

    std::map<std::string, uint8_t> u8_defines;
    std::map<std::string, uint16_t> labels_u16_defines;
    std::map<std::string, uint32_t> u32_defines;
    std::map<std::string, float> f32_defines;

    std::filesystem::path inputFile;

public:
    explicit Assembler(const std::filesystem::path& inputFile);
    void assemble(const std::filesystem::path& outputFile);

private:
    void firstPass(const std::vector<std::string>& lines);
    static uint32_t getIndentedNewAddress(const std::string& line, uint32_t currentAddress);
    void handleCompileTimeLabel(const std::string& line, uint32_t currentAddress);

    static uint32_t getInstructionLength(const std::string& line);
    static uint32_t getInstructionLengthNoParameters(const std::string& instruction);
    static uint32_t getInstructionLengthOneParameter(const std::string& instruction, std::string& param);
    static uint32_t getInstructionLengthTwoParameters(const std::string& instruction, const std::string& param1, std::string& param2);
    static uint32_t getInstructionLengthThreeParameters(const std::string& instruction, const std::string& param1, std::string& param2, std::string& param3);

    static uint32_t getDotDirectiveNewAddress(const std::string& line, uint32_t currentAddress);

    static uint32_t readIntegerLiteral(const std::string& literal);

    // all functions below assume that the instruction and parameters are valid and just return the machine code for them (missing labels still throw exceptions)
    std::vector<uint8_t> secondPass(const std::vector<std::string>& lines);
    std::vector<uint8_t> generateMachineCodeForInstruction(const std::string& line);
    std::vector<uint8_t> getInstructionCodeNoParameters(const std::string& instruction);
    std::vector<uint8_t> getInstructionCodeOneParameter(const std::string& instruction, std::string& param);
    std::vector<uint8_t> getInstructionCodeTwoParameters(const std::string& instruction, const std::string& param1, std::string& param2);
    std::vector<uint8_t> getInstructionCodeThreeParameters(const std::string& instruction, const std::string& param1, const std::string& param2, const std::string& param3);
};