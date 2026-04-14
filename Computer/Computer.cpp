#include "Computer.hpp"

#include <utility>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

constexpr uint16_t handleSegfaultAdress = 0x0000;
constexpr uint16_t handleStopProgramAdress = 0x0002;
constexpr uint16_t handleSyscalAdress = 0x0004;
constexpr uint16_t shutdownByteAdress = 0x6400;

constexpr uint16_t activePidAdress = 0x7fff;
constexpr uint16_t userMemoryMapStart = 0x4000;
constexpr uint8_t carryFlag = 0b0000'0001;
constexpr uint8_t zeroFlag = 0b0000'0010;
constexpr uint8_t interruptFlag = 0b0000'0100;
constexpr uint8_t compareGreaterFlag = 0b0000'1000;
constexpr uint8_t compareEqualFlag = 0b0001'0000;
constexpr uint8_t kernelModeFlag = 0b0010'0000;
constexpr uint8_t overflowFlag = 0b0100'0000;
constexpr uint8_t negativeFlag = 0b1000'0000;

#define LOAD_MEMORY(target, adress) \
if (kernelModeFlag & flags) { \
    target = kernelRam[adress]; \
} \
else if (auto byte = userMapMemory(adress)) { \
    target = *byte.value(); \
} \
else { \
    setSegfault(); \
    X = 0xFFFF'FFFF; \
    return; \
}

#define STORE_MEMORY(source, adress) \
if (kernelModeFlag & flags) { \
    kernelRam[adress] = source; \
} \
else if (auto byte = userMapMemory(adress)) { \
    *byte.value() = source; \
} \
else { \
    setSegfault(); \
    X = 0xFFFF'FFFF; \
    return; \
}

Computer::Computer(const std::filesystem::path& kernelRomFile, const std::filesystem::path& storageFile) {
    auto kernelRomSize = std::filesystem::file_size(kernelRomFile);
    if (kernelRomSize > kernelRam.size()) {
        throw std::runtime_error("Kernel rom file too big");
    }
    auto storageSize = std::filesystem::file_size(storageFile);
    if (storageSize > storage.size() * sizeof(MemoryBlock)) {
        throw std::runtime_error("Storage file too big");
    }
    std::ifstream kernelFile(kernelRomFile, std::ios::binary);
    kernelFile.read(reinterpret_cast<char*>(kernelRam.data()), kernelRam.size());
    std::ifstream storage(storageFile, std::ios::binary);
    for (auto& block : this->storage) {
        storage.read(reinterpret_cast<char*>(block.data()), block.size());
    }
    inputThread = std::jthread(&Computer::inputLoop, this);
    outputThread = std::jthread(&Computer::outputLoop, this);
}

void Computer::reset() {
    progCount = 6;
    flags = kernelModeFlag;
}

void Computer::run(std::size_t cycles) {
    for (std::size_t c = 0; c < cycles; ++c) {
        run();
    }
}

void Computer::run() {
    if (instructionProgress < 2) {
        loadInstructionByte();
        return;
    }
    if (currentInstruction[0] == 0x40) {
        handleJump();
        return;
    }
    if (currentInstruction[0] & 0x80) {
        handleLogic();
        return;
    }
    if (currentInstruction[0] < 0x10) {
        load8BitImmediate();
        return;
    }
    if (currentInstruction[0] == 0x20) {
        loadMultyByteImmediate();
        return;
    }
    if (currentInstruction[0] == 0x30) {
        handleMemoryLoad();
        return;
    }
    if (currentInstruction[0] == 0x70) {
        handleMemoryStore();
        return;
    }
    if (currentInstruction[0] == 0x10) {
        handlePop();
        return;
    }
    if (currentInstruction[0] == 0x50) {
        handlePush();
        return;
    }
    if (currentInstruction[0] >= 0x18 && currentInstruction[0] < 0x20) {
        handleLoadWithOffset();
        return;
    }
    if (currentInstruction[0] >= 0x58 && currentInstruction[0] < 0x60) {
        handleStoreWithOffset();
        return;
    }
    if (currentInstruction[0] >= 0x42 && currentInstruction[0] < 0x48) {
        handleRegisterTransfer();
        return;
    }
}

void Computer::saveStorage(const std::filesystem::path& storageFile) {
    std::ofstream file(storageFile, std::ios::binary);
    for (const auto& block : storage) {
        file.write(reinterpret_cast<const char*>(block.data()), block.size());
    }
}

void Computer::inputLoop() {
    while (true) {
        if (kernelRam[shutdownByteAdress]) {
            return;
        }
        char input;
        std::cin.get(input);
        // input to input buffer at kernel ram 0x6000 to 0x60ff, buffer offset position (kernel ram 0x6200)
        kernelRam[0x6000 + kernelRam[0x6200]] = static_cast<uint8_t>(input);
        // increment buffer offset
        kernelRam[0x6200] = (kernelRam[0x6200] + 1) % 256;
    }
}

void Computer::outputLoop() {
    while (true) {
        if (kernelRam[shutdownByteAdress]) {
            return;
        }
        // output from output buffer at kernel ram 0x6100 to 0x61ff, buffer offset position (kernel ram 0x6300)
        if (kernelRam[0x6300] != kernelRam[0x6380]) {
            char output = static_cast<char>(kernelRam[0x6100 + kernelRam[0x6300]]);
            std::cout << output;
            // increment buffer offset
            kernelRam[0x6300] = (kernelRam[0x6300] + 1) % 256;
        }
        else {
            // if buffer empty wait a bit before checking again
            std::this_thread::sleep_for(100ms);
        }
    }
}

std::expected<uint8_t*, bool> Computer::userMapMemory(uint16_t userAdress) {
    const uint8_t pid = kernelRam[activePidAdress];
    auto activeFreeList = programRam[memoryMapperCache[pid]];
    const uint16_t shortAdress = userAdress % sizeof(MemoryBlock);
    const uint16_t blockAdress = userAdress / sizeof(MemoryBlock);
    const uint16_t targetBlock = static_cast<uint16_t>(activeFreeList[blockAdress * 4]) + static_cast<uint16_t>(activeFreeList[blockAdress * 4]) << 8;
    // back check
    if (!(kernelRam[blockAdress * 2 + userMemoryMapStart] == pid && kernelRam[blockAdress * 2 + userMemoryMapStart + 1] == static_cast<uint8_t>(blockAdress))) {
        return std::unexpected(false);
    }
    return &programRam[blockAdress][shortAdress];
}

void Computer::loadInstructionByte() {
    LOAD_MEMORY(currentInstruction[instructionProgress], progCount);
    ++instructionProgress;
    ++progCount;
}

void Computer::handleJump() {
    if (currentInstruction[1] == 0x00) {
        syscall();
        return;
    }
    if (currentInstruction[1] == 0x01) {
        startProgram();
        return;
    }
    if (currentInstruction[1] == 0x02) {
        executeSegfault();
        return;
    }
    if (currentInstruction[1] == 0x03) {
        stopProgram();
        return;
    }
    if (currentInstruction[1] == 0x04) {
        returnFromSubroutine();
        return;
    }
    if (currentInstruction[1] >= 0x08 && currentInstruction[1] < 0x0f) {
        jumpToSubroutineRegister(currentInstruction[1] - 0x08);
        return;
    }
    if (currentInstruction[1] == 0x0f) {
        jumpToSubroutineImmediate();
        return;
    }

    // jump conditions total instruction space enough for 29 conditions but only 14 used, maybe more in future adding more is only done by expanding the array
    static std::array<std::function<bool(uint8_t)>, 14> jumpReasons{
        // jump Always
        [](uint8_t flags) {return true; },
        // jumpOnInterrupt
        [](uint8_t flags) {return interruptFlag & flags; },
        // jump Greater
        [](uint8_t flags) {return !(compareEqualFlag & flags) && compareEqualFlag & flags; },
        // jump Less
        [](uint8_t flags) {return !(compareEqualFlag & flags) && !(compareEqualFlag & flags); },
        // jump Equal
        [](uint8_t flags) {return compareEqualFlag & flags; },
        // jump not Equal
        [](uint8_t flags) {return !(compareEqualFlag & flags); },
        // jump GreaterEqual
        [](uint8_t flags) {return compareEqualFlag & flags || compareEqualFlag & flags; },
        // jump LessEqual
        [](uint8_t flags) {return compareEqualFlag & flags || !(compareEqualFlag & flags); },
        // jumpCarry
        [](uint8_t flags) {return carryFlag & flags; },
        // jumpNotCarry
        [](uint8_t flags) {return !(carryFlag & flags); },
        // jumpZero
        [](uint8_t flags) {return zeroFlag & flags; },
        // jumpNotZero
        [](uint8_t flags) {return !(zeroFlag & flags); },
        // jumpNegative
        [](uint8_t flags) {return negativeFlag & flags; },
        // jumpNotNegative
        [](uint8_t flags) {return !(negativeFlag & flags); }
    };

    if (currentInstruction[1] / 8 >= 2 && currentInstruction[1] / 8 < jumpReasons.size() + 2) {
        auto condition = jumpReasons[currentInstruction[1] / 8 - 2];
        if (currentInstruction[1] % 8 == 7) {
            jumpConditionalImmediate(condition);
            return;
        }
        jumpConditionalRegister(condition, currentInstruction[1] % 8);
        return;
    }
}

void Computer::handleLogic() {
    if (currentInstruction[0] == 0x80) {
        compare8bit();
        return;
    }
    if (currentInstruction[0] == 0x81) {
        compareMultyByte();
        return;
    }
    if (currentInstruction[0] & 0xf0 >= 0x90 && currentInstruction[0] & 0xf0 <= 0xe0) {
        threeParameterLogic();
        return;
    }
    if (currentInstruction[0] == 0xf0) {
        singleRegisterLogic();
        return;
    }
}

void Computer::load8BitImmediate() {
    if (currentInstruction[1] == 0) {
        flags |= zeroFlag;
    }
    else {
        flags &= ~zeroFlag;
    }
    if (0x80 & currentInstruction[1]) {
        flags |= negativeFlag;
    }
    else {
        flags &= ~negativeFlag;
    }
    setI8RegisterById(currentInstruction[0] & 0x0f, currentInstruction[1]);
    instructionProgress = 0;
}

void Computer::loadMultyByteImmediate() {
    if (instructionProgress <= currentInstruction[1] & 0x08 ? 5 : 3) {
        loadInstructionByte();
        return;
    }
    if (currentInstruction[1] < 0x08) {
        uint16_t value = currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
        if (value == 0) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (value & 0x8000) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setI16RegisterById(currentInstruction[1] & 0x07, value);
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[1] >= 0x08 && currentInstruction[1] < 0x0c) {
        uint32_t value = currentInstruction[2] + (static_cast<uint32_t>(currentInstruction[3]) << 8) + (static_cast<uint32_t>(currentInstruction[4]) << 16) + (static_cast<uint32_t>(currentInstruction[5]) << 24);
        if (value == 0) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (value & 0x8000'0000) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setI32RegisterById(currentInstruction[1] & 0x03, value);
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[1] >= 0x0c && currentInstruction[1] < 0x10) {
        uint32_t value = currentInstruction[2] + (static_cast<uint32_t>(currentInstruction[3]) << 8) + (static_cast<uint32_t>(currentInstruction[4]) << 16) + (static_cast<uint32_t>(currentInstruction[5]) << 24);
        float fValue;
        std::memcpy(&fValue, &value, sizeof(float));
        if (fValue == 0.0f) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (fValue < 0.0f) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setF32RegisterById(currentInstruction[1] & 0x03, fValue);
        instructionProgress = 0;
        return;
    }
}

void Computer::handleMemoryLoad() {
    bool isImmediate = currentInstruction[1] & 0x07 == 0x07;
    if (isImmediate) {
        if (instructionProgress <= 3) {
            loadInstructionByte();
            return;
        }
    }
    uint16_t adress;
    if (currentInstruction[1] & 0x07 == 0x07) {
        adress = currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
    }
    else {
        adress = getI16RegisterById(currentInstruction[1] & 0x07);
    }
    if (currentInstruction[1] & 0xc0 == 0x00) {
        // 16 bit load
        if (instructionProgress == 2 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress);
            loadBuffer = value;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 1);
            loadBuffer += static_cast<uint16_t>(value) << 8;
            if (loadBuffer == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (loadBuffer & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            setI16RegisterById(currentInstruction[1] & 0x07, loadBuffer);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xe0 == 0x40) {
        // 32 bit load
        if (instructionProgress == 2 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress);
            loadBuffer = value;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 1);
            loadBuffer += static_cast<uint16_t>(value) << 8;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 2);
            loadBuffer += static_cast<uint32_t>(value) << 16;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 3);
            loadBuffer += static_cast<uint32_t>(value) << 24;
            if (loadBuffer == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (loadBuffer & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            setI32RegisterById(currentInstruction[1] & 0x07, loadBuffer);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xe0 == 0x60) {
        // float load
        if (instructionProgress == 2 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress);
            loadBuffer = value;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 1);
            loadBuffer += static_cast<uint16_t>(value) << 8;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 2);
            loadBuffer += static_cast<uint32_t>(value) << 16;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5 + (isImmediate ? 2 : 0)) {
            uint8_t value;
            LOAD_MEMORY(value, adress + 3);
            loadBuffer += static_cast<uint32_t>(value) << 24;
            float fValue;
            std::memcpy(&fValue, &loadBuffer, sizeof(float));
            if (fValue == 0.0f) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (fValue < 0.0f) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            setF32RegisterById(currentInstruction[1] & 0x07, fValue);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0x80 == 0x80) {
        // 8 bit load
        uint8_t value;
        LOAD_MEMORY(value, adress);
        setI8RegisterById(currentInstruction[1] & 0x07, value);
        instructionProgress = 0;
        return;
    }
}

void Computer::handleMemoryStore() {
    bool isImmediate = currentInstruction[1] & 0x07 == 0x07;
    if (isImmediate) {
        if (instructionProgress <= 3) {
            loadInstructionByte();
            return;
        }
    }
    uint16_t adress;
    if (currentInstruction[1] & 0x07 == 0x07) {
        adress = currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
    }
    else {
        adress = getI16RegisterById(currentInstruction[1] & 0x07);
    }
    if (currentInstruction[1] & 0xc0 == 0x00) {
        // 16 bit store
        if (instructionProgress == 2 + (isImmediate ? 2 : 0)) {
            uint16_t value = getI16RegisterById(currentInstruction[1] & 0x07);
            STORE_MEMORY(value & 0x00ff, adress);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3 + (isImmediate ? 2 : 0)) {
            uint16_t value = getI16RegisterById(currentInstruction[1] & 0x07);
            value >>= 8;
            STORE_MEMORY(value & 0x00ff, adress + 1);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xe0 == 0x40) {
        // 32 bit store
        if (instructionProgress == 2 + (isImmediate ? 2 : 0)) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            STORE_MEMORY(value & 0x00ff, adress);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3 + (isImmediate ? 2 : 0)) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            value >>= 8;
            STORE_MEMORY(value & 0x00ff, adress + 1);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4 + (isImmediate ? 2 : 0)) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            value >>= 16;
            STORE_MEMORY(value & 0x00ff, adress + 2);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5 + (isImmediate ? 2 : 0)) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            value >>= 24;
            STORE_MEMORY(value & 0x00ff, adress + 3);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xe0 == 0x60) {
        // float store
        if (instructionProgress == 2 + (isImmediate ? 2 : 0)) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            STORE_MEMORY(value & 0x00ff, adress);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3 + (isImmediate ? 2 : 0)) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            value >>= 8;
            STORE_MEMORY(value & 0x00ff, adress + 1);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4 + (isImmediate ? 2 : 0)) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            value >>= 16;
            STORE_MEMORY(value & 0x00ff, adress + 2);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5 + (isImmediate ? 2 : 0)) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            value >>= 24;
            STORE_MEMORY(value & 0x00ff, adress + 3);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0x80 == 0x80) {
        // 8 bit store
        uint8_t value = getI8RegisterById(currentInstruction[1] & 0x07);
        STORE_MEMORY(value, adress);
        instructionProgress = 0;
        return;
    }
}

void Computer::handlePop() {
    if (currentInstruction[1] & 0xf8 == 0x00) {
        // 16 bit pop
        if (instructionProgress == 2) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer = value;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint16_t>(value) << 8;
            if (loadBuffer == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (loadBuffer & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            setI16RegisterById(currentInstruction[1] & 0x07, loadBuffer);
            ++stackPointer;
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xfc == 0x08) {
        // 32 bit pop
        if (instructionProgress == 2) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer = value;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint16_t>(value) << 8;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint32_t>(value) << 16;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint32_t>(value) << 24;
            if (loadBuffer == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (loadBuffer & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            setI32RegisterById(currentInstruction[1] & 0x07, loadBuffer);
            ++stackPointer;
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xfc == 0x0c) {
        // float pop
        if (instructionProgress == 2) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer = value;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint16_t>(value) << 8;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint32_t>(value) << 16;
            ++stackPointer;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5) {
            uint8_t value;
            LOAD_MEMORY(value, stackPointer);
            loadBuffer += static_cast<uint32_t>(value) << 24;
            float fValue;
            std::memcpy(&fValue, &loadBuffer, sizeof(float));
            if (fValue == 0.0f) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (fValue < 0.0f) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            setF32RegisterById(currentInstruction[1] & 0x07, fValue);
            ++stackPointer;
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xf0 == 0x10) {
        // 8 bit pop
        uint8_t value;
        LOAD_MEMORY(value, stackPointer);
        if (currentInstruction[1] == 0x17) {
            // pop flags
            flags = value;
            ++stackPointer;
            instructionProgress = 0;
            return;
        }
        if (value == 0) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (value & 0x80) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setI8RegisterById(currentInstruction[1] & 0x07, value);
        ++stackPointer;
        instructionProgress = 0;
        return;
    }
}

void Computer::handlePush() {
    if (currentInstruction[1] & 0xf8 == 0x00) {
        // 16 bit push
        if (instructionProgress == 2) {
            uint16_t value = getI16RegisterById(currentInstruction[1] & 0x07);
            value >>= 8;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3) {
            uint16_t value = getI16RegisterById(currentInstruction[1] & 0x07);
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xfc == 0x08) {
        // 32 bit push
        if (instructionProgress == 2) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            value >>= 24;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            value >>= 16;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            value >>= 8;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0x07);
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xfc == 0x0c) {
        // float push
        if (instructionProgress == 2) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            value >>= 24;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 3) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            value >>= 16;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            value >>= 8;
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0x07);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            --stackPointer;
            STORE_MEMORY(value & 0x00ff, stackPointer);
            instructionProgress = 0;
            return;
        }
    }
    if (currentInstruction[1] & 0xf0 == 0x10) {
        // 8 bit push
        if (currentInstruction[1] == 0x17) {
            // push flags
            --stackPointer;
            STORE_MEMORY(flags, stackPointer);
            instructionProgress = 0;
            return;
        }
        uint8_t value = getI8RegisterById(currentInstruction[1] & 0x07);
        --stackPointer;
        STORE_MEMORY(value, stackPointer);
        instructionProgress = 0;
        return;
    }
}

void Computer::handleLoadWithOffset() {
    bool immediatePointer, immediateOffset;
    immediateOffset = (currentInstruction[1] & 0x07) == 0x07;
    immediatePointer = (currentInstruction[1] & 0x38) == 0x38;
    if (immediatePointer && immediateOffset) {
        // this does not make much sense, therfore a cpu lockup is created
        return;
    }
    if (immediateOffset) {
        loadWithImmediateOffset();
        return;
    }
    if (immediatePointer) {
        loadWithOffsetImmediatePointer();
        return;
    }
    loadWithRegisterPointerAndOffset();
}

void Computer::handleStoreWithOffset() {
    bool immediatePointer, immediateOffset;
    immediateOffset = (currentInstruction[1] & 0x07) == 0x07;
    immediatePointer = (currentInstruction[1] & 0x38) == 0x38;
    if (immediateOffset && immediatePointer) {
        // this does not make much sense, therfore a cpu lockup is created
        return;
    }
    if (immediateOffset) {
        storeWithImmediateOffset();
        return;
    }
    if (immediatePointer) {
        storeWithOffsetImmediatePointer();
        return;
    }
    storeWithRegisterPointerAndOffset();
}

void Computer::handleRegisterTransfer() {
    if (currentInstruction[0] == 0x42 && currentInstruction[1] & 0x80 == 0x00) {
        // i16 to i16 register transfer
        setI16RegisterById(currentInstruction[1] & 0x38 >> 3, getI16RegisterById(currentInstruction[1] & 0x07));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x42 && currentInstruction[1] & 0xc0 == 0x80) {
        // i32 to i32 register transfer
        setI32RegisterById(currentInstruction[1] & 0xc >> 2, getI32RegisterById(currentInstruction[1] & 0x03));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x42 && currentInstruction[1] & 0xc0 == 0xc0) {
        // f32 to f32 register transfer
        setF32RegisterById(currentInstruction[1] & 0xc >> 2, getF32RegisterById(currentInstruction[1] & 0x03));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x43) {
        // i8 to i8 register transfer
        setI8RegisterById(currentInstruction[1] & 0xf0 >> 4, getI8RegisterById(currentInstruction[1] & 0x0f));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x44) {
        // i8 to i16 register transfer
        setI16RegisterById(currentInstruction[1] & 0x70 >> 4, getI8RegisterById(currentInstruction[1] & 0x0f));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x45) {
        // i16 to i8 register transfer
        setI8RegisterById(currentInstruction[1] & 0x78 >> 3, getI16RegisterById(currentInstruction[1] & 0x07));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x46 && currentInstruction[1] & 0x80 == 0x00) {
        // i16 to i32 register transfer
        setI32RegisterById(currentInstruction[1] & 0x18 >> 3, getI16RegisterById(currentInstruction[1] & 0x07));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x46 && currentInstruction[1] & 0x80 == 0x80) {
        // i32 to i16 register transfer
        setI16RegisterById(currentInstruction[1] & 0x18 >> 3, getI32RegisterById(currentInstruction[1] & 0x07));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x47 && currentInstruction[1] & 0x80 == 0x00) {
        // i32 to f32 register transfer (signed conversion)
        uint32_t iValue = getI32RegisterById(currentInstruction[1] & 0x03);
        setF32RegisterById(currentInstruction[1] & 0x0c >> 2, static_cast<float>(reinterpret_cast<int32_t&>(iValue)));
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x47 && currentInstruction[1] & 0x80 == 0x80) {
        // f32 to i32 register transfer (signed conversion)
        int32_t iValue = static_cast<int32_t>(getF32RegisterById(currentInstruction[1] & 0x03));
        setI32RegisterById(currentInstruction[1] & 0x0c >> 2, reinterpret_cast<uint32_t&>(iValue));
        instructionProgress = 0;
        return;
    }
}

void Computer::syscall() {
    if (kernelModeFlag & flags) {
        if (instructionProgress == 2) {
            if (auto byte = userMapMemory(0)) {
                stackPointer = *byte.value();
                ++instructionProgress;
                return;
            }
            flags &= ~kernelModeFlag;
            setSegfault();
            X = 0xFFFF'FFFF;
            return;
        }
        if (instructionProgress == 3) {
            uint16_t value = *userMapMemory(1).value();
            value <<= 8;
            stackPointer += value;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4) {
            progCount = *userMapMemory(2).value();
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5) {
            uint16_t value = *userMapMemory(3).value();
            value <<= 8;
            progCount += value;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 6) {
            flags = *userMapMemory(4).value();
            instructionProgress = 0;
            return;
        }
    }
    else {
        if (instructionProgress == 2) {
            if (auto byte = userMapMemory(0)) {
                *byte.value() = stackPointer & 0x00ff;
                ++instructionProgress;
                return;
            }
            setSegfault();
            X = 0xFFFF'FFFF;
            return;
        }
        if (instructionProgress == 3) {
            uint16_t value = stackPointer;
            value >>= 8;
            *userMapMemory(1).value() = value & 0x00ff;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 4) {
            *userMapMemory(2).value() = progCount & 0x00ff;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 5) {
            uint16_t value = progCount;
            value >>= 8;
            *userMapMemory(3).value() = value & 0x00ff;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 6) {
            *userMapMemory(4).value() = flags;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == 7) {
            progCount = kernelRam[0];
            ++instructionProgress;
            return;
        }
        uint16_t value = kernelRam[1];
        value <<= 8;
        progCount += value;
        instructionProgress = 0;
        return;
    }
}

void Computer::startProgram() {
    if (!(flags & kernelModeFlag)) {
        setSegfault();
        // only kernel can start program
        X = 0xFFFF'FFFE;
        return;
    }
    stackPointer = 0x0000;
    progCount = 0x0400;
    flags &= ~kernelModeFlag;
    instructionProgress = 0;
}

void Computer::executeSegfault() {
    if (flags & kernelModeFlag) {
        // die
        return;
    }
    progCount = handleSegfaultAdress;
    flags |= kernelModeFlag;
    instructionProgress = 0;
}

void Computer::stopProgram() {
    if (flags & kernelModeFlag) {
        // die
        return;
    }
    progCount = handleStopProgramAdress;
    flags |= kernelModeFlag;
    instructionProgress = 0;
}

void Computer::returnFromSubroutine() {
    if (instructionProgress == 2) {
        uint8_t value;
        LOAD_MEMORY(value, stackPointer);
        ++stackPointer;
        progCount = value;
        ++instructionProgress;
        return;
    }
    if (instructionProgress == 3) {
        uint8_t value;
        LOAD_MEMORY(value, stackPointer);
        ++stackPointer;
        progCount += static_cast<uint16_t>(value) << 8;
        instructionProgress = 0;
        return;
    }
    // die shoud be unreachable
}

void Computer::jumpToSubroutineRegister(uint8_t registerId) {
    if (instructionProgress == 2) {
        uint8_t value = progCount & 0x00ff;
        --stackPointer;
        STORE_MEMORY(value, stackPointer);
        ++instructionProgress;
        return;
    }
    if (instructionProgress == 3) {
        uint8_t value = progCount >> 8;
        --stackPointer;
        STORE_MEMORY(value, stackPointer);
        ++instructionProgress;
        return;
    }
    progCount = getI16RegisterById(registerId);
    instructionProgress = 0;
    return;
}

void Computer::jumpToSubroutineImmediate() {
    if (instructionProgress == 2 || instructionProgress == 3) {
        loadInstructionByte();
        return;
    }
    if (instructionProgress == 4) {
        uint8_t value = progCount & 0x00ff;
        --stackPointer;
        STORE_MEMORY(value, stackPointer);
        ++instructionProgress;
        return;
    }
    if (instructionProgress == 5) {
        uint8_t value = progCount >> 8;
        --stackPointer;
        STORE_MEMORY(value, stackPointer);
        ++instructionProgress;
        return;
    }
    progCount = currentInstruction[2];
    progCount += static_cast<uint16_t>(currentInstruction[3]) << 8;
    instructionProgress = 0;
    return;
}

void Computer::jumpConditionalRegister(std::function<bool(uint8_t)> condition, uint8_t registerId) {
    if (condition(flags)) {
        progCount = getI16RegisterById(registerId);
    }
    instructionProgress = 0;
}

void Computer::jumpConditionalImmediate(std::function<bool(uint8_t)> condition) {
    if (instructionProgress == 2 || instructionProgress == 3) {
        loadInstructionByte();
        return;
    }
    if (condition(flags)) {
        progCount = currentInstruction[2];
        progCount += static_cast<uint16_t>(currentInstruction[3]) << 8;
    }
    instructionProgress = 0;
}

void Computer::compare8bit() {
    if (currentInstruction[1] & 0x07 == 0x07) {
        compare8bitImmediate();
        return;
    }
    compare8bitRegister();
}

void Computer::compareMultyByte() {
    if (currentInstruction[1] < 0x40) {
        compare16bit();
        return;
    }
    if (currentInstruction[1] >= 0x40 && currentInstruction[1] < 0x50) {
        compare32bit();
        return;
    }
    if (currentInstruction[1] >= 0x50 && currentInstruction[1] < 0x60) {
        compareFloat();
        return;
    }
}

void Computer::threeParameterLogic() {
    // split by parameter type
    if (currentInstruction[0] & 0x0e == 0x00) {
        threeParameterLogic16bit();
        return;
    }
    if (currentInstruction[0] & 0x0f == 0x02) {
        threeParameterLogic32bit();
        return;
    }
    if (currentInstruction[0] & 0x0f == 0x04) {
        threeParameterLogicFloat();
        return;
    }
    if (currentInstruction[0] & 0x0f == 0x06) {
        threeParameterLogic8bit();
        return;
    }
}

void Computer::singleRegisterLogic() {
    // sort by register type
    if (currentInstruction[1] & 0x1f == 0x00) {
        singleRegisterLogic16bit();
        return;
    }
    if (currentInstruction[1] & 0x1f == 0x08) {
        singleRegisterLogic32bit();
        return;
    }
    if (currentInstruction[1] & 0x1f == 0x10) {
        singleRegisterLogic8bit();
        return;
    }
    // no float as shifting and rotating float not supported
}

void Computer::compare8bitImmediate() {
    if (instructionProgress <= 3) {
        loadInstructionByte();
        return;
    }
    const uint8_t regValue = getI8RegisterById(currentInstruction[1] & 0xf0 >> 4);
    const uint8_t value = currentInstruction[currentInstruction[1] & 0x08 ? 3 : 2];
    if (regValue == value) {
        flags |= compareEqualFlag;
        return;
    }
    flags &= ~compareEqualFlag;
    if (regValue > value) {
        flags |= compareGreaterFlag;
        return;
    }
    flags &= ~compareGreaterFlag;
    instructionProgress = 0;
}

void Computer::compare8bitRegister() {
    const uint8_t regValue1 = getI8RegisterById(currentInstruction[1] & 0xf0 >> 4);
    const uint8_t regValue2 = getI8RegisterById(currentInstruction[1] & 0x0f);
    if (regValue1 == regValue2) {
        flags |= compareEqualFlag;
        return;
    }
    flags &= ~compareEqualFlag;
    if (regValue1 > regValue2) {
        flags |= compareGreaterFlag;
        return;
    }
    flags &= ~compareGreaterFlag;
    instructionProgress = 0;
}

void Computer::compare16bit() {
    // immediate or register
    if (currentInstruction[1] & 0x07 == 0x07) {
        if (instructionProgress <= 3) {
            loadInstructionByte();
            return;
        }
        const uint16_t regValue = getI16RegisterById(currentInstruction[1] & 0x68 >> 3);
        uint16_t value = currentInstruction[2];
        value += static_cast<uint16_t>(currentInstruction[3]) << 8;
        if (regValue == value) {
            flags |= compareEqualFlag;
            return;
        }
        flags &= ~compareEqualFlag;
        if (regValue > value) {
            flags |= compareGreaterFlag;
            return;
        }
        flags &= ~compareGreaterFlag;
        return;
    }
    const uint16_t regValue1 = getI16RegisterById(currentInstruction[1] & 0x68 >> 3);
    const uint16_t regValue2 = getI16RegisterById(currentInstruction[1] & 0x07);
    if (regValue1 == regValue2) {
        flags |= compareEqualFlag;
        return;
    }
    flags &= ~compareEqualFlag;
    if (regValue1 > regValue2) {
        flags |= compareGreaterFlag;
        return;
    }
    flags &= ~compareGreaterFlag;
    instructionProgress = 0;
}

void Computer::compare32bit() {
    // immediate or register
    if (currentInstruction[1] & 0x03 == 0x03) {
        if (instructionProgress <= 5) {
            loadInstructionByte();
            return;
        }
        const uint32_t regValue = getI32RegisterById(currentInstruction[1] & 0x0c >> 2);
        uint32_t value = currentInstruction[2];
        value += static_cast<uint32_t>(currentInstruction[3]) << 8;
        value += static_cast<uint32_t>(currentInstruction[4]) << 16;
        value += static_cast<uint32_t>(currentInstruction[5]) << 24;
        if (regValue == value) {
            flags |= compareEqualFlag;
            return;
        }
        flags &= ~compareEqualFlag;
        if (regValue > value) {
            flags |= compareGreaterFlag;
            return;
        }
        flags &= ~compareGreaterFlag;
        return;
    }
    const uint32_t regValue1 = getI32RegisterById(currentInstruction[1] & 0x0c >> 2);
    const uint32_t regValue2 = getI32RegisterById(currentInstruction[1] & 0x03);
    if (regValue1 == regValue2) {
        flags |= compareEqualFlag;
        return;
    }
    flags &= ~compareEqualFlag;
    if (regValue1 > regValue2) {
        flags |= compareGreaterFlag;
        return;
    }
    flags &= ~compareGreaterFlag;
    instructionProgress = 0;
}

void Computer::compareFloat() {
    // immediate or register
    if (currentInstruction[1] & 0x03 == 0x03) {
        if (instructionProgress <= 5) {
            loadInstructionByte();
            return;
        }
        const float regValue = getF32RegisterById(currentInstruction[1] & 0x0c >> 2);
        uint32_t value = currentInstruction[2];
        value += static_cast<uint32_t>(currentInstruction[3]) << 8;
        value += static_cast<uint32_t>(currentInstruction[4]) << 16;
        value += static_cast<uint32_t>(currentInstruction[5]) << 24;
        float fValue;
        std::memcpy(&fValue, &value, sizeof(float));
        if (regValue == fValue) {
            flags |= compareEqualFlag;
            return;
        }
        flags &= ~compareEqualFlag;
        if (regValue > fValue) {
            flags |= compareGreaterFlag;
            return;
        }
        flags &= ~compareGreaterFlag;
        return;
    }
    const float regValue1 = getF32RegisterById(currentInstruction[1] & 0x0c >> 2);
    const float regValue2 = getF32RegisterById(currentInstruction[1] & 0x03);
    if (regValue1 == regValue2) {
        flags |= compareEqualFlag;
        return;
    }
    flags &= ~compareEqualFlag;
    if (regValue1 > regValue2) {
        flags |= compareGreaterFlag;
        return;
    }
    flags &= ~compareGreaterFlag;
    instructionProgress = 0;
}

void Computer::threeParameterLogic8bit() {
    // a b flagscarry overflow negative and zero like 6502
    static std::array<std::function<uint8_t(uint8_t, uint8_t, uint8_t&)>, 6> logicFunctions{
        // add
        [](uint8_t a, uint8_t b, uint8_t flags) {
            uint16_t result = a + b + (flags & carryFlag ? 1 : 0);
            uint8_t res8 = result & 0x00ff;
            if (result > 0xff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res8 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (((a ^ result) & (b ^ result) & 0x80)) {
                flags |= overflowFlag;
            }
            else {
                flags &= ~overflowFlag;
            }
            if (res8 & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res8;
        },
        // sub
        [](uint8_t a, uint8_t b, uint8_t& flags) {
            uint16_t result = a - b - (flags & carryFlag ? 0 : 1);
            uint8_t res8 = result & 0x00ff;
            if (result > 0xff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res8 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (((a ^ b) & (a ^ result) & 0x80)) {
                flags |= overflowFlag;
            }
            else {
                flags &= ~overflowFlag;
            }
            if (res8 & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res8;
        },
        // mul
        [](uint8_t a, uint8_t b, uint8_t& flags) {
            uint16_t result = a * b;
            uint8_t res8 = result & 0x00ff;
            if (result > 0xff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res8 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for mul
            if (res8 & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res8;
        },
        // or
        [](uint8_t a, uint8_t b, uint8_t& flags) {
            uint8_t res8 = a | b;
            if (res8 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for or
            if (res8 & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res8;
        },
        // and
        [](uint8_t a, uint8_t b, uint8_t& flags) {
            uint8_t res8 = a & b;
            if (res8 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for and
            if (res8 & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res8;
        },
        // xor
        [](uint8_t a, uint8_t b, uint8_t& flags) {
            uint8_t res8 = a ^ b;
            if (res8 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for xor
            if (res8 & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res8;
        }
    };
    if (instructionProgress <= 3) {
        loadInstructionByte();
        return;
    }
    // valid opcodes are 0x96, 0xa6, 0xb6, 0xc6, 0xd6, 0xe6
    uint8_t functionId = ((currentInstruction[0] & 0x70) >> 4) - 1;
    if (functionId >= logicFunctions.size()) {
        // invalid opcode, should be unreachable
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[functionId];
    const uint8_t a = getI8RegisterById(currentInstruction[2] & 0xf0 >> 4);
    const uint8_t b = currentInstruction[2] & 0x07 == 0x07 ? currentInstruction[3] : getI8RegisterById(currentInstruction[2] & 0x0f);
    const uint8_t result = logicFunction(a, b, flags);
    setI8RegisterById(currentInstruction[1] & 0x0f, result);
    instructionProgress = 0;
}

void Computer::threeParameterLogic16bit() {
    // a b flagscarry overflow negative and zero like 6502
    static std::array<std::function<uint16_t(uint16_t, uint16_t, uint8_t&)>, 6> logicFunctions{
        // add
        [](uint16_t a, uint16_t b, uint8_t& flags) {
            uint32_t result = a + b + (flags & carryFlag ? 1 : 0);
            uint16_t res16 = result & 0x0000ffff;
            if (result > 0xffff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res16 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (((a ^ result) & (b ^ result) & 0x8000)) {
                flags |= overflowFlag;
            }
            else {
                flags &= ~overflowFlag;
            }
            if (res16 & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res16;
        },
        // sub
        [](uint16_t a, uint16_t b, uint8_t& flags) {
            uint32_t result = a - b - (flags & carryFlag ? 0 : 1);
            uint16_t res16 = result & 0x0000ffff;
            if (result > 0xffff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res16 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (((a ^ b) & (a ^ result) & 0x8000)) {
                flags |= overflowFlag;
            }
            else {
                flags &= ~overflowFlag;
            }
            if (res16 & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res16;
        },
        // mul
        [](uint16_t a, uint16_t b, uint8_t& flags) {
            uint32_t result = a * b;
            uint16_t res16 = result & 0x0000ffff;
            if (result > 0xffff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res16 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (res16 & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res16;
        },
        // or
        [](uint16_t a, uint16_t b, uint8_t& flags) {
            uint16_t res16 = a | b;
            if (res16 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for or
            if (res16 & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res16;
        },
        // and
        [](uint16_t a, uint16_t b, uint8_t& flags) {
            uint16_t res16 = a & b;
            if (res16 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for and
            if (res16 & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res16;
        },
        // xor
        [](uint16_t a, uint16_t b, uint8_t& flags) {
            uint16_t res16 = a ^ b;
            if (res16 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for xor
            if (res16 & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res16;
        }
    };
    if (currentInstruction[1] & 0x07 == 0x07) {
        if (instructionProgress <= 3) {
            loadInstructionByte();
            return;
        }
    }
    // valid opcodes are 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0
    uint8_t logicFunctionId = ((currentInstruction[0] & 0x70) >> 4) - 1;
    if (logicFunctionId >= logicFunctions.size()) {
        // invalid function id, should not happen due to instruction decoding
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[logicFunctionId];
    const uint16_t a = getI16RegisterById(currentInstruction[1] & 0x68 >> 3);
    uint16_t b = currentInstruction[1] & 0x07 == 0x07 ? currentInstruction[2] + static_cast<uint16_t>(currentInstruction[3]) << 8 : getI16RegisterById(currentInstruction[2] & 0x07);
    const uint16_t result = logicFunction(a, b, flags);
    // target register id uses last bit of currentInstruction[0] and 2 bits of currentInstruction[1]
    setI16RegisterById((currentInstruction[0] & 0x01) << 2 + ((currentInstruction[1] & 0xc0) >> 6), result);
    instructionProgress = 0;
}

void Computer::threeParameterLogic32bit() {
    // a b flagscarry overflow negative and zero like 6502
    static std::array<std::function<uint32_t(uint32_t, uint32_t, uint8_t&)>, 6> logicFunctions{
        // add
        [](uint32_t a, uint32_t b, uint8_t& flags) {
            uint64_t result = static_cast<uint64_t>(a) + static_cast<uint64_t>(b) + (flags & carryFlag ? 1 : 0);
            uint32_t res32 = result & 0x0000'0000'ffff'ffff;
            if (result > 0xffff'ffff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res32 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (((a ^ result) & (b ^ result) & 0x8000'0000)) {
                flags |= overflowFlag;
            }
            else {
                flags &= ~overflowFlag;
            }
            if (res32 & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res32;
        },
        // sub
        [](uint32_t a, uint32_t b, uint8_t& flags) {
            uint64_t result = static_cast<uint64_t>(a) - static_cast<uint64_t>(b) - (flags & carryFlag ? 0 : 1);
            uint32_t res32 = result & 0x0000'0000'ffff'ffff;
            if (result > 0xffff'ffff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res32 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (((a ^ b) & (a ^ result) & 0x8000'0000)) {
                flags |= overflowFlag;
            }
            else {
                flags &= ~overflowFlag;
            }
            if (res32 & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res32;
        },
        // mul
        [](uint32_t a, uint32_t b, uint8_t& flags) {
            uint64_t result = static_cast<uint64_t>(a) * static_cast<uint64_t>(b);
            uint32_t res32 = result & 0x0000'0000'ffff'ffff;
            if (result > 0xffff'ffff) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (res32 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (res32 & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res32;
        },
        // or
        [](uint32_t a, uint32_t b, uint8_t& flags) {
            uint32_t res32 = a | b;
            if (res32 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for or
            if (res32 & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res32;
        },
        // and
        [](uint32_t a, uint32_t b, uint8_t& flags) {
            uint32_t res32 = a & b;
            if (res32 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for and
            if (res32 & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res32;
        },
        // xor
        [](uint32_t a, uint32_t b, uint8_t& flags) {
            uint32_t res32 = a ^ b;
            if (res32 == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for xor
            if (res32 & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return res32;
        }
    };
    if (currentInstruction[1] & 0x03 == 0x03) {
        if (instructionProgress <= 5) {
            loadInstructionByte();
            return;
        }
    }
    // valid opcodes are 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2
    uint8_t functionIndex = (currentInstruction[0] & 0x70 >> 4) - 1;
    if (functionIndex >= logicFunctions.size()) {
        // invalid function index, should not happen due to instruction decoding
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[functionIndex];
    const uint32_t a = getI32RegisterById(currentInstruction[1] & 0x0c >> 2);
    uint32_t b = currentInstruction[1] & 0x03 == 0x03 ? currentInstruction[2] + (static_cast<uint32_t>(currentInstruction[3]) << 8) + (static_cast<uint32_t>(currentInstruction[4]) << 16) + (static_cast<uint32_t>(currentInstruction[5]) << 24) : getI32RegisterById(currentInstruction[2] & 0x03);
    const uint32_t result = logicFunction(a, b, flags);
    setI32RegisterById(currentInstruction[1] & 0x30 >> 4, result);
    instructionProgress = 0;
}

void Computer::threeParameterLogicFloat() {
    // a b flagscarry overflow negative and zero like 6502
    static std::array<std::function<float(float, float, uint8_t&)>, 3> logicFunctions{
        // add
        [](float a, float b, uint8_t& flags) {
            float result = a + b;
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (result < 0) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            // no carry and overflow flag for float operations
            return result;
        },
        // sub
        [](float a, float b, uint8_t& flags) {
            float result = a - b;
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (result < 0) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            // no carry and overflow flag for float operations
            return result;
        },
        // mul
        [](float a, float b, uint8_t& flags) {
            float result = a * b;
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            if (result < 0) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            // no carry and overflow flag for float operations
            return result;
        }
    };
    if (currentInstruction[1] & 0x03 == 0x03) {
        if (instructionProgress <= 5) {
            loadInstructionByte();
            return;
        }
    }
    // valid opcodes are 0x94, 0xa4, 0xb4
    uint8_t functionIndex = (currentInstruction[0] & 0x70 >> 4) - 1;
    if (functionIndex >= logicFunctions.size()) {
        // invalid function index, should not happen due to instruction decoding
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[functionIndex];
    const float a = getF32RegisterById(currentInstruction[1] & 0x0c >> 2);
    float b;
    if (currentInstruction[1] & 0x03 == 0x03) {
        uint32_t value = currentInstruction[2];
        value += static_cast<uint32_t>(currentInstruction[3]) << 8;
        value += static_cast<uint32_t>(currentInstruction[4]) << 16;
        value += static_cast<uint32_t>(currentInstruction[5]) << 24;
        std::memcpy(&b, &value, sizeof(float));
    }
    else {
        b = getF32RegisterById(currentInstruction[2] & 0x03);
    }
    const float result = logicFunction(a, b, flags);
    setF32RegisterById(currentInstruction[1] & 0x30 >> 4, result);
    instructionProgress = 0;
}

void Computer::singleRegisterLogic16bit() {
    static std::array<std::function<uint16_t(uint16_t, uint8_t&)>, 7> logicFunctions{
        // shl
        [](uint16_t a, uint8_t& flags) {
            uint16_t result = a << 1;
            if (a & 0x8000) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for shift operations
            if (result & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // shr
        [](uint16_t a, uint8_t& flags) {
            uint16_t result = a >> 1;
            if (a & 0x0001) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for shift operations
            if (result & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // rol
        [](uint16_t a, uint8_t& flags) {
            uint16_t result = (a << 1) | ((flags & carryFlag) ? 1 : 0);
            if (a & 0x8000) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for rotate operations
            if (result & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // ror
        [](uint16_t a, uint8_t& flags) {
            uint16_t result = (a >> 1) | ((flags & carryFlag) ? 0x8000 : 0);
            if (a & 0x0001) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for rotate operations
            if (result & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // not
        [](uint16_t a, uint8_t& flags) {
            uint16_t result = ~a;
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for not operation
            if (result & 0x8000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        }
    };
    // operation is determined by bits 5-7 of currentInstruction[1]
    uint8_t functionIndex = currentInstruction[1] >> 5;
    if (functionIndex >= logicFunctions.size()) {
        // invalid function index, should not happen due to instruction decoding
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[functionIndex];
    const uint16_t a = getI16RegisterById(currentInstruction[1] & 0x07);
    const uint16_t result = logicFunction(a, flags);
    setI16RegisterById(currentInstruction[1] & 0x07, result);
    instructionProgress = 0;
}

void Computer::singleRegisterLogic32bit() {
    static std::array<std::function<uint32_t(uint32_t, uint8_t&)>, 7> logicFunctions{
        // shl
        [](uint32_t a, uint8_t& flags) {
            uint32_t result = a << 1;
            if (a & 0x8000'0000) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for shift operations
            if (result & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // shr
        [](uint32_t a, uint8_t& flags) {
            uint32_t result = a >> 1;
            if (a & 0x0000'0001) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for shift operations
            if (result & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // rol
        [](uint32_t a, uint8_t& flags) {
            uint32_t result = (a << 1) | ((flags & carryFlag) ? 1 : 0);
            if (a & 0x8000'0000) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for rotate operations
            if (result & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // ror
        [](uint32_t a, uint8_t& flags) {
            uint32_t result = (a >> 1) | ((flags & carryFlag) ? 0x8000'0000 : 0);
            if (a & 0x0000'0001) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for rotate operations
            if (result & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // not
        [](uint32_t a, uint8_t& flags) {
            uint32_t result = ~a;
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for not operation
            if (result & 0x8000'0000) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        }
    };
    // operation is determined by bits 5-7 of currentInstruction[1]
    uint8_t functionIndex = currentInstruction[1] >> 5;
    if (functionIndex >= logicFunctions.size()) {
        // invalid function index, should not happen due to instruction decoding
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[functionIndex];
    const uint32_t a = getI32RegisterById(currentInstruction[1] & 0x03);
    const uint32_t result = logicFunction(a, flags);
    setI32RegisterById(currentInstruction[1] & 0x03, result);
    instructionProgress = 0;
}

void Computer::singleRegisterLogic8bit() {
    static std::array<std::function<uint8_t(uint8_t, uint8_t&)>, 7> logicFunctions{
        // shl
        [](uint8_t a, uint8_t& flags) {
            uint8_t result = a << 1;
            if (a & 0x80) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for shift operations
            if (result & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // shr
        [](uint8_t a, uint8_t& flags) {
            uint8_t result = a >> 1;
            if (a & 0x01) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for shift operations
            if (result & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // rol
        [](uint8_t a, uint8_t& flags) {
            uint8_t result = (a << 1) | ((flags & carryFlag) ? 1 : 0);
            if (a & 0x80) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for rotate operations
            if (result & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // ror
        [](uint8_t a, uint8_t& flags) {
            uint8_t result = (a >> 1) | ((flags & carryFlag) ? 0x80 : 0);
            if (a & 0x01) {
                flags |= carryFlag;
            }
            else {
                flags &= ~carryFlag;
            }
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no overflow flag for rotate operations
            if (result & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        },
        // not
        [](uint8_t a, uint8_t& flags) {
            uint8_t result = ~a;
            if (result == 0) {
                flags |= zeroFlag;
            }
            else {
                flags &= ~zeroFlag;
            }
            // no carry and overflow flag for not operation
            if (result & 0x80) {
                flags |= negativeFlag;
            }
            else {
                flags &= ~negativeFlag;
            }
            return result;
        }
    };
    // operation is determined by bits 5-7 of currentInstruction[1]
    uint8_t functionIndex = currentInstruction[1] >> 5;
    if (functionIndex >= logicFunctions.size()) {
        // invalid function index, should not happen due to instruction decoding
        instructionProgress = 0;
        return;
    }
    auto logicFunction = logicFunctions[functionIndex];
    const uint8_t a = getI8RegisterById(currentInstruction[1] & 0x0f);
    const uint8_t result = logicFunction(a, flags);
    setI8RegisterById(currentInstruction[1] & 0x0f, result);
    instructionProgress = 0;
}

void Computer::loadWithImmediateOffset() {
    if (instructionProgress <= 3) {
        loadInstructionByte();
        return;
    }
    const uint16_t readAdress = getI16RegisterById(currentInstruction[1] & 0x38 >> 3) + currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
    loadWithOffsetFinalize(4, readAdress);
}

void Computer::loadWithOffsetImmediatePointer() {
    if (instructionProgress <= 3) {
        loadInstructionByte();
        return;
    }
    const uint16_t readAdress = getI16RegisterById(currentInstruction[1] & 0x07) + currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
    loadWithOffsetFinalize(4, readAdress);
}

void Computer::loadWithRegisterPointerAndOffset() {
    const uint16_t readAdress = getI16RegisterById(currentInstruction[1] & 0x38 >> 3) + getI16RegisterById(currentInstruction[1] & 0x07);
    loadWithOffsetFinalize(2, readAdress);
}

void Computer::loadWithOffsetFinalize(uint8_t startCycle, uint16_t readAdress) {
    if (currentInstruction[0] & 0xfe == 0x18) {
        // load 16 bit
        if (instructionProgress == startCycle) {
            uint8_t lowByte;
            LOAD_MEMORY(lowByte, readAdress);
            loadBuffer = lowByte;
            ++instructionProgress;
            return;
        }
        uint8_t highByte;
        LOAD_MEMORY(highByte, readAdress + 1);
        loadBuffer += static_cast<uint16_t>(highByte) << 8;
        if (loadBuffer == 0) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (loadBuffer & 0x8000) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setI16RegisterById(currentInstruction[0] & 0x01 << 2 + (currentInstruction[1] & 0xc0) >> 6, loadBuffer);
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x1a) {
        // load 32 bit
        if (instructionProgress == startCycle) {
            uint8_t byte0;
            LOAD_MEMORY(byte0, readAdress);
            loadBuffer = byte0;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 1) {
            uint8_t byte1;
            LOAD_MEMORY(byte1, readAdress + 1);
            loadBuffer += static_cast<uint32_t>(byte1) << 8;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 2) {
            uint8_t byte2;
            LOAD_MEMORY(byte2, readAdress + 2);
            loadBuffer += static_cast<uint32_t>(byte2) << 16;
            ++instructionProgress;
            return;
        }
        uint8_t byte3;
        LOAD_MEMORY(byte3, readAdress + 3);
        loadBuffer += static_cast<uint32_t>(byte3) << 24;
        if (loadBuffer == 0) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (loadBuffer & 0x8000'0000) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setI32RegisterById(currentInstruction[1] & 0xc0 >> 6, loadBuffer);
        instructionProgress = 0;
    }
    if (currentInstruction[0] == 0x1b) {
        // load float
        if (instructionProgress == startCycle) {
            uint8_t byte0;
            LOAD_MEMORY(byte0, readAdress);
            loadBuffer = byte0;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 1) {
            uint8_t byte1;
            LOAD_MEMORY(byte1, readAdress + 1);
            loadBuffer += static_cast<uint32_t>(byte1) << 8;
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 2) {
            uint8_t byte2;
            LOAD_MEMORY(byte2, readAdress + 2);
            loadBuffer += static_cast<uint32_t>(byte2) << 16;
            ++instructionProgress;
            return;
        }
        uint8_t byte3;
        LOAD_MEMORY(byte3, readAdress + 3);
        loadBuffer += static_cast<uint32_t>(byte3) << 24;
        float fValue;
        std::memcpy(&fValue, &loadBuffer, sizeof(float));
        if (fValue == 0.0f) {
            flags |= zeroFlag;
        }
        else {
            flags &= ~zeroFlag;
        }
        if (fValue < 0.0f) {
            flags |= negativeFlag;
        }
        else {
            flags &= ~negativeFlag;
        }
        setF32RegisterById(currentInstruction[1] & 0xc0 >> 6, fValue);
        instructionProgress = 0;
    }
    // load 8 bit
    uint8_t value;
    LOAD_MEMORY(value, readAdress);
    if (value == 0) {
        flags |= zeroFlag;
    }
    else {
        flags &= ~zeroFlag;
    }
    if (value & 0x80) {
        flags |= negativeFlag;
    }
    else {
        flags &= ~negativeFlag;
    }
    setI8RegisterById(currentInstruction[0] & 0x03 << 2 + (currentInstruction[1] & 0xc0) >> 6, value);
    instructionProgress = 0;
}

void Computer::storeWithImmediateOffset() {
    if (instructionProgress <= 3) {
        loadInstructionByte();
        return;
    }
    const uint16_t writeAdress = getI16RegisterById(currentInstruction[1] & 0x38 >> 3) + currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
    storeWithOffsetFinalize(4, writeAdress);
}

void Computer::storeWithOffsetImmediatePointer() {
    if (instructionProgress <= 3) {
        loadInstructionByte();
        return;
    }
    const uint16_t writeAdress = getI16RegisterById(currentInstruction[1] & 0x07) + currentInstruction[2] + (static_cast<uint16_t>(currentInstruction[3]) << 8);
    storeWithOffsetFinalize(4, writeAdress);
}

void Computer::storeWithRegisterPointerAndOffset() {
    const uint16_t writeAdress = getI16RegisterById(currentInstruction[1] & 0x38 >> 3) + getI16RegisterById(currentInstruction[1] & 0x07);
    storeWithOffsetFinalize(2, writeAdress);
}

void Computer::storeWithOffsetFinalize(uint8_t startCycle, uint16_t writeAdress) {
    if (currentInstruction[0] & 0xfe == 0x58) {
        // store 16 bit
        if (instructionProgress == startCycle) {
            uint16_t value = getI16RegisterById(currentInstruction[0] & 0x01 << 2 + (currentInstruction[1] & 0xc0) >> 6);
            uint8_t lowByte = value & 0x00ff;
            STORE_MEMORY(lowByte, writeAdress);
            ++instructionProgress;
            return;
        }
        uint16_t value = getI16RegisterById(currentInstruction[0] & 0x01 << 2 + (currentInstruction[1] & 0xc0) >> 6);
        uint8_t highByte = value >> 8;
        STORE_MEMORY(highByte, writeAdress + 1);
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x5a) {
        // store 32 bit
        if (instructionProgress == startCycle) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0xc0 >> 6);
            uint8_t byte0 = value & 0x0000'00ff;
            STORE_MEMORY(byte0, writeAdress);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 1) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0xc0 >> 6);
            uint8_t byte1 = (value & 0x0000'ff00) >> 8;
            STORE_MEMORY(byte1, writeAdress + 1);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 2) {
            uint32_t value = getI32RegisterById(currentInstruction[1] & 0xc0 >> 6);
            uint8_t byte2 = (value & 0x00ff'0000) >> 16;
            STORE_MEMORY(byte2, writeAdress + 2);
            ++instructionProgress;
            return;
        }
        uint32_t value = getI32RegisterById(currentInstruction[1] & 0xc0 >> 6);
        uint8_t byte3 = (value & 0xff00'0000) >> 24;
        STORE_MEMORY(byte3, writeAdress + 3);
        instructionProgress = 0;
        return;
    }
    if (currentInstruction[0] == 0x5b) {
        // store float
        if (instructionProgress == startCycle) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0xc0 >> 6);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            uint8_t byte0 = value & 0x0000'00ff;
            STORE_MEMORY(byte0, writeAdress);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 1) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0xc0 >> 6);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            uint8_t byte1 = (value & 0x0000'ff00) >> 8;
            STORE_MEMORY(byte1, writeAdress + 1);
            ++instructionProgress;
            return;
        }
        if (instructionProgress == startCycle + 2) {
            float fValue = getF32RegisterById(currentInstruction[1] & 0xc0 >> 6);
            uint32_t value;
            std::memcpy(&value, &fValue, sizeof(float));
            uint8_t byte2 = (value & 0x00ff'0000) >> 16;
            STORE_MEMORY(byte2, writeAdress + 2);
            ++instructionProgress;
            return;
        }
        float fValue = getF32RegisterById(currentInstruction[1] & 0xc0 >> 6);
        uint32_t value;
        std::memcpy(&value, &fValue, sizeof(float));
        uint8_t byte3 = (value & 0xff00'0000) >> 24;
        STORE_MEMORY(byte3, writeAdress + 3);
        instructionProgress = 0;
        return;
    }
    // store 8 bit
    uint8_t value = getI8RegisterById(currentInstruction[0] & 0x03 << 2 + (currentInstruction[1] & 0xc0) >> 6);
    STORE_MEMORY(value, writeAdress);
    instructionProgress = 0;
}

void Computer::setSegfault() {
    currentInstruction[0] = 0x40;
    currentInstruction[1] = 0x02;
    instructionProgress = 2;
}

uint16_t Computer::getI16RegisterById(uint8_t id) {
    switch (id) {
    case 0:
        return A;
    case 1:
        return B;
    case 2:
        return C;
    case 3:
        return D;
    case 4:
        return E;
    case 5:
        return G;
    case 6:
        return stackPointer;
    default:
        return 0;
    }
}

void Computer::setI16RegisterById(uint8_t id, uint16_t value) {
    switch (id) {
    case 0:
        A = value;
        break;
    case 1:
        B = value;
        break;
    case 2:
        C = value;
        break;
    case 3:
        D = value;
        break;
    case 4:
        E = value;
        break;
    case 5:
        G = value;
        break;
    case 6:
        stackPointer = value;
        break;
    default:
        break;
    }
}

uint32_t Computer::getI32RegisterById(uint8_t id) {
    switch (id) {
    case 0:
        return X;
    case 1:
        return Y;
    case 2:
        return Z;
    default:
        return 0;
    }
}

void Computer::setI32RegisterById(uint8_t id, uint32_t value) {
    switch (id) {
    case 0:
        X = value;
        break;
    case 1:
        Y = value;
        break;
    case 2:
        Z = value;
        break;
    default:
        break;
    }
}

uint8_t Computer::getI8RegisterById(uint8_t id) {
    switch (id) {
    case 0:
        return A & 0x00ff;
    case 1:
        return B & 0x00ff;
    case 2:
        return C & 0x00ff;
    case 3:
        return D & 0x00ff;
    case 4:
        return E & 0x00ff;
    case 5:
        return G & 0x00ff;
    case 8:
        return A >> 8;
    case 9:
        return B >> 8;
    case 10:
        return C >> 8;
    case 11:
        return D >> 8;
    case 12:
        return E >> 8;
    case 13:
        return G >> 8;
    default:
        return 0;
    }
}

void Computer::setI8RegisterById(uint8_t id, uint8_t value) {
    switch (id) {
    case 0:
        A &= 0xff00;
        A += value;
        break;
    case 1:
        B &= 0xff00;
        B += value;
        break;
    case 2:
        C &= 0xff00;
        C += value;
        break;
    case 3:
        D &= 0xff00;
        D += value;
        break;
    case 4:
        E &= 0xff00;
        E += value;
        break;
    case 5:
        G &= 0xff00;
        G += value;
        break;
    case 8:
        A &= 0x00ff;
        A += static_cast<uint16_t>(value) << 8;
        break;
    case 9:
        B &= 0x00ff;
        B += static_cast<uint16_t>(value) << 8;
        break;
    case 10:
        C &= 0x00ff;
        C += static_cast<uint16_t>(value) << 8;
        break;
    case 11:
        D &= 0x00ff;
        D += static_cast<uint16_t>(value) << 8;
        break;
    case 12:
        E &= 0x00ff;
        E += static_cast<uint16_t>(value) << 8;
        break;
    case 13:
        G &= 0x00ff;
        G += static_cast<uint16_t>(value) << 8;
        break;
    default:
        break;
    }
}

float Computer::getF32RegisterById(uint8_t id) {
    switch (id) {
    case 0:
        return fA;
    case 1:
        return fB;
    case 2:
        return fC;

    default:
        return 0;
    }
}

void Computer::setF32RegisterById(uint8_t id, float value) {
    switch (id) {
    case 0:
        fA = value;
        break;
    case 1:
        fB = value;
        break;
    case 2:
        fC = value;
        break;
    default:
        break;
    }
}
