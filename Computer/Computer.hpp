#pragma once
#include <array>
#include <cstdint>
#include <expected>
#include <functional>

#include<filesystem>

class Computer
{
private:
    using MemoryBlock = std::array<uint8_t, 512>;
    // registers 16bit
    uint16_t A, B, C, D, E, G, stackPointer, progCount;
    // registers 32bit
    uint32_t X, Y, Z;
    // registers float
    float fA, fB, fC;

    uint32_t loadBuffer;
    uint8_t flags;

    std::array<uint8_t, 0x1'0000> kernelRam;
    std::array<MemoryBlock, 0x1000> programRam;
    std::array<MemoryBlock, 0x8000> storage;

    std::array<uint8_t, 6> currentInstruction;
    uint8_t instructionProgress{ };

    // will always point at free lists
    std::array<uint16_t, 256> memoryMapperCache;

public:
    Computer(const std::filesystem::path& kernelRomFile, const std::filesystem::path& storageFile);
    void reset();
    void run(std::size_t cycles);
    // run one cycle
    void run();

private:
    std::expected<uint8_t*, bool> userMapMemory(uint16_t userAdress);
    void loadInstructionByte();
    void handleJump();
    void handleLogic();
    void load8BitImmediate();
    void loadMultyByteImmediate();
    void handleMemoryLoad();
    void handleMemoryStore();
    void handlePop();
    void handlePush();
    void handleLoadWithOffset();
    void handleStoreWithOffset();
    void handleRegisterTransfer();

    // jumps
    void syscall();
    void startProgram();
    void executeSegfault();
    void stopProgram();
    void returnFromSubroutine();
    void jumpToSubroutineRegister(uint8_t registerId);
    void jumpToSubroutineImmediate();
    void jumpConditionalRegister(std::function<bool(uint8_t)> condition, uint8_t registerId);
    void jumpConditionalImmediate(std::function<bool(uint8_t)> condition);

    // ALU
    void compare8bit();
    void compareMultyByte();
    void threeParameterLogic();
    void singleRegisterLogic();

    void compare8bitImmediate();
    void compare8bitRegister();
    void compare16bit();
    void compare32bit();
    void compareFloat();
    void threeParameterLogic8bit();
    void threeParameterLogic16bit();
    void threeParameterLogic32bit();
    void threeParameterLogicFloat();
    void singleRegisterLogic16bit();
    void singleRegisterLogic32bit();
    void singleRegisterLogic8bit();

    // utils
    void setSegfault();
    uint16_t getI16RegisterById(uint8_t id);
    void setI16RegisterById(uint8_t id, uint16_t value);
    uint32_t getI32RegisterById(uint8_t id);
    void setI32RegisterById(uint8_t id, uint32_t value);
    uint8_t getI8RegisterById(uint8_t id);
    void setI8RegisterById(uint8_t id, uint8_t value);
    float getF32RegisterById(uint8_t id);
    void setF32RegisterById(uint8_t id, float value);
};
