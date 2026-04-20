#include "Assembler.hpp"

std::map<std::string, uint16_t> Assembler::targetSourceSource8bitMap{
    {"add", 0x9600},
    {"sub", 0xa600},
    {"mul", 0xb600},
    {"or", 0xc600},
    {"and", 0xd600},
    {"xor", 0xe600}
};

std::map<std::string, uint16_t> Assembler::targetSourceSource16bitMap{
    {"add", 0x9000},
    {"sub", 0xa000},
    {"mul", 0xb000},
    {"or", 0xc000},
    {"and", 0xd000},
    {"xor", 0xe000}
};

std::map<std::string, uint16_t> Assembler::targetSourceSource32bitMap{
    {"add", 0x9200},
    {"sub", 0xa200},
    {"mul", 0xb200},
    {"or", 0xc200},
    {"and", 0xd200},
    {"xor", 0xe200}
};

std::map<std::string, uint16_t> Assembler::targetSourceSourceFloatMap{
    {"add", 0x9400},
    {"sub", 0xa400},
    {"mul", 0xb400}
    // no or, and, xor for float
};


std::map<std::string, uint16_t> Assembler::targetPointerPointer8bitMap{
    {"load", 0x1c00},
    {"store", 0x5c00}
};

std::map<std::string, uint16_t> Assembler::targetPointerPointer16bitMap{
    {"load", 0x1800},
    {"store", 0x5800}
};

std::map<std::string, uint16_t> Assembler::targetPointerPointer32bitMap{
    {"load", 0x1a00},
    {"store", 0x5a00}
};

std::map<std::string, uint16_t> Assembler::targetPointerPointerFloatMap{
    {"load", 0x1b00},
    {"store", 0x5b00}
};


std::map<std::string, uint16_t> Assembler::targetPointer8bitMap{
    {"load", 0x3080},
    {"store", 0x7080}
};

std::map<std::string, uint16_t> Assembler::targetPointer16bitMap{
    {"load", 0x3000},
    {"store", 0x7000}
};

std::map<std::string, uint16_t> Assembler::targetPointer32bitMap{
    {"load", 0x3040},
    {"store", 0x7040}
};

std::map<std::string, uint16_t> Assembler::targetPointerFloatMap{
    {"load", 0x3060},
    {"store", 0x7060}
};


std::map<std::string, uint16_t> Assembler::targetSource8bitMap{
    {"load", 0x0000},
    {"cmp", 0x8000},
    {"move", 0x4300}
};

std::map<std::string, uint16_t> Assembler::targetSource16bitMap{
    {"load", 0x2000},
    {"cmp", 0x8100},
    {"move", 0x4200}
};

std::map<std::string, uint16_t> Assembler::targetSource32bitMap{
    {"load", 0x2008},
    {"cmp", 0x8140},
    {"move", 0x4280}
};

std::map<std::string, uint16_t> Assembler::targetSourceFloatMap{
    {"load", 0x200c},
    {"cmp", 0x8150},
    {"move", 0x42c0}
};


std::map<std::string, uint16_t> Assembler::targetSourceMultySizeMap{
    {"move", 0x4400}
};


std::map<std::string, uint16_t> Assembler::target8bitMap{
    {"shl", 0xf010},
    {"shr", 0xf030},
    {"rol", 0xf050},
    {"ror", 0xf070},
    {"inc", 0xf090},
    {"dec", 0xf0b0},
    {"not", 0xf0d0},
    {"push", 0x5010},
    {"pop", 0x1010}
};

std::map<std::string, uint16_t> Assembler::target16bitMap{
    {"shl", 0xf000},
    {"shr", 0xf020},
    {"rol", 0xf040},
    {"ror", 0xf060},
    {"inc", 0xf080},
    {"dec", 0xf0a0},
    {"not", 0xf0c0},
    {"push", 0x5000},
    {"pop", 0x1000}
};

std::map<std::string, uint16_t> Assembler::target32bitMap{
    {"shl", 0xf008},
    {"shr", 0xf028},
    {"rol", 0xf048},
    {"ror", 0xf068},
    {"inc", 0xf088},
    {"dec", 0xf0a8},
    {"not", 0xf0c8},
    {"push", 0x5008},
    {"pop", 0x1008}
};

std::map<std::string, uint16_t> Assembler::targetFloatMap{
    {"push", 0x500c},
    {"pop", 0x100c}
};


std::map<std::string, uint16_t> Assembler::pointerMap{
    {"jsr", 0x4008},
    {"jmp", 0x4010},
    {"ji", 0x4018},
    {"jg", 0x4020},
    {"jl", 0x4028},
    {"je", 0x4030},
    {"jne", 0x4038},
    {"jge", 0x4040},
    {"jle", 0x4048},
    {"jc", 0x4050},
    {"jnc", 0x4058},
    {"jz", 0x4060},
    {"jnz", 0x4068},
    {"jn", 0x4070},
    {"jnn", 0x4078}
};


std::map<std::string, uint16_t> Assembler::noParameterMap{
    {"sysc", 0x4000},
    {"staP", 0x4001},
    {"segf", 0x4002},
    {"stoP", 0x4003},
    {"rts", 0x4004}
};

std::array<std::string, 14> Assembler::byteRegisterNames{
    "lA", "lB", "lC", "lD", "lE", "lG", "", "", "hA", "hB", "hC", "hD", "hE", "hG"
};

std::array<std::string, 6> Assembler::wordRegisterNames{
    "A", "B", "C", "D", "E", "G"
};

std::array<std::string, 3> Assembler::dwordRegisterNames{
    "X", "Y", "Z"
};

std::array<std::string, 3> Assembler::floatRegisterNames{
    "fA", "fB", "fC"
};