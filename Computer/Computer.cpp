#include "Computer.hpp"

#include <utility>

constexpr uint16_t handleSegfaultAdress = 0x0000;
constexpr uint16_t handleStopProgramAdress = 0x0002;
constexpr uint16_t handleSyscalAdress = 0x0004;

constexpr uint16_t activePidAdress = 0x7ffb;
constexpr uint16_t userMemoryMapStart = 0x4000;
constexpr uint8_t carryFlag = 0b0000'0001;
constexpr uint8_t zeroFlag = 0b0000'0010;
constexpr uint8_t compareGreaterFlag = 0b0000'1000;
constexpr uint8_t compareEqualFlag = 0b0001'0000;
constexpr uint8_t kernelModeFlag = 0b0010'0000;

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
    static std::array<std::function<bool(uint8_t)>, 11> jumpReasons{
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
        [](uint8_t flags) {return !(zeroFlag & flags); }
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


