add_executable(Assembler
    main.cpp
    Assembler.cpp
    Assembler_staticInit.cpp
)

target_compile_features(Assembler PUBLIC cxx_std_23)
