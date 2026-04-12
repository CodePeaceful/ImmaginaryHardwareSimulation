#include "Computer.hpp"

#include <utility>
#include <cstring>

constexpr uint16_t handleSegfaultAdress = 0x0000;
constexpr uint16_t handleStopProgramAdress = 0x0002;
constexpr uint16_t handleSyscalAdress = 0x0004;

constexpr uint16_t activePidAdress = 0x7ffb;
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
    if (currentInstruction[0] >= 0x42 && currentInstruction[0] < 0x44) {
        handleRegisterTransfer();
        return;
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
        [](uint8_t flags) {return !(negativeFlag & flags); },
        // jumpOnInterrupt
        [](uint8_t flags) {return interruptFlag & flags; }
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
    stackPointer = 0xffff;
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
        ++stackPointer;
        uint8_t value;
        LOAD_MEMORY(value, stackPointer);
        progCount = value;
        ++instructionProgress;
        return;
    }
    if (instructionProgress == 3) {
        ++stackPointer;
        uint8_t value;
        LOAD_MEMORY(value, stackPointer);
        progCount += static_cast<uint16_t>(value) << 8;
        instructionProgress = 0;
        return;
    }
    // die shoud be unreachable
}

void Computer::jumpToSubroutineRegister(uint8_t registerId) {
    if (instructionProgress == 2) {
        uint8_t value = progCount & 0x00ff;
        STORE_MEMORY(value, stackPointer);
        --stackPointer;
        ++instructionProgress;
        return;
    }
    if (instructionProgress == 3) {
        uint8_t value = progCount >> 8;
        STORE_MEMORY(value, stackPointer);
        --stackPointer;
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
        STORE_MEMORY(value, stackPointer);
        --stackPointer;
        ++instructionProgress;
        return;
    }
    if (instructionProgress == 5) {
        uint8_t value = progCount >> 8;
        STORE_MEMORY(value, stackPointer);
        --stackPointer;
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
    // valid opcodes are 0x96, 0xa6, 0xb6, 0xc6, 0xd6, 0xe6  garanteed from instruction decoding
    auto logicFunction = logicFunctions[(currentInstruction[0] & 0x70 >> 4) - 1];
    const uint8_t a = getI8RegisterById(currentInstruction[2] & 0xf0 >> 4);
    const uint8_t b = currentInstruction[2] & 0x07 == 0x07 ? currentInstruction[3] : getI8RegisterById(currentInstruction[2] & 0x0f);
    const uint8_t result = logicFunction(a, b, flags);
    setI8RegisterById(currentInstruction[1] & 0x0f, result);
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
    // valid opcodes are 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0 garanteed from instruction decoding
    auto logicFunction = logicFunctions[(currentInstruction[0] & 0x70 >> 4) - 1];
    const uint16_t a = getI16RegisterById(currentInstruction[1] & 0x68 >> 3);
    uint16_t b = currentInstruction[1] & 0x07 == 0x07 ? currentInstruction[2] + static_cast<uint16_t>(currentInstruction[3]) << 8 : getI16RegisterById(currentInstruction[2] & 0x07);
    const uint16_t result = logicFunction(a, b, flags);
    // target register id uses last bit of currentInstruction[0] and 2 bits of currentInstruction[1]
    setI16RegisterById((currentInstruction[0] & 0x01) << 2 + ((currentInstruction[1] & 0xc0) >> 6), result);
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
    // valid opcodes are 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2 garanteed from instruction decoding
    auto logicFunction = logicFunctions[(currentInstruction[0] & 0x70 >> 4) - 1];
    const uint32_t a = getI32RegisterById(currentInstruction[1] & 0x0c >> 2);
    uint32_t b = currentInstruction[1] & 0x03 == 0x03 ? currentInstruction[2] + (static_cast<uint32_t>(currentInstruction[3]) << 8) + (static_cast<uint32_t>(currentInstruction[4]) << 16) + (static_cast<uint32_t>(currentInstruction[5]) << 24) : getI32RegisterById(currentInstruction[2] & 0x03);
    const uint32_t result = logicFunction(a, b, flags);
    setI32RegisterById(currentInstruction[1] & 0x30 >> 4, result);
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
    // valid opcodes are 0x94, 0xa4, 0xb4 garanteed from instruction decoding
    auto logicFunction = logicFunctions[(currentInstruction[0] & 0x70 >> 4) - 1];
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
    auto logicFunction = logicFunctions[currentInstruction[1] >> 5];
    const uint16_t a = getI16RegisterById(currentInstruction[1] & 0x07);
    const uint16_t result = logicFunction(a, flags);
    setI16RegisterById(currentInstruction[1] & 0x07, result);
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
    auto logicFunction = logicFunctions[currentInstruction[1] >> 5];
    const uint32_t a = getI32RegisterById(currentInstruction[1] & 0x03);
    const uint32_t result = logicFunction(a, flags);
    setI32RegisterById(currentInstruction[1] & 0x03, result);
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
    auto logicFunction = logicFunctions[currentInstruction[1] >> 5];
    const uint8_t a = getI8RegisterById(currentInstruction[1] & 0x0f);
    const uint8_t result = logicFunction(a, flags);
    setI8RegisterById(currentInstruction[1] & 0x0f, result);
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
