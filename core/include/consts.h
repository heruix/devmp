#pragma once

namespace devmp {

    enum Regs : int {
        al = 0,
        ah = 1,
        ax = 2,
        eax = 3,
        rax = 4,
        bl = 5,
        bh = 6,
        bx = 7,
        ebx = 8,
        rbx = 9,
        cl = 10,
        ch = 11,
        cx = 12,
        ecx = 13,
        rcx = 14,
        dl = 15,
        dh = 16,
        dx = 17,
        edx = 18,
        rdx = 19,
        rbp = 20,
        rsp = 21,
        sil = 22,
        si = 23,
        esi = 24,
        rsi = 25,
        dil = 26,
        di = 27,
        edi = 28,
        rdi = 29,
        r8b = 30,
        r8w = 31,
        r8d = 32,
        r8 = 33,
        r9b = 34,
        r9w = 35,
        r9d = 36,
        r9 = 37,
        r10b = 38,
        r10w = 39,
        r10d = 40,
        r10 = 41,
        r11b = 42,
        r11w = 43,
        r11d = 44,
        r11 = 45,
        r12b = 46,
        r12w = 47,
        r12d = 48,
        r12 = 49,
        r13b = 50,
        r13w = 51,
        r13d = 52,
        r13 = 53,
        r14b = 54,
        r14w = 55,
        r14d = 56,
        r14 = 57,
        r15b = 58,
        r15w = 59,
        r15d = 60,
        r15 = 61,
        unknown = -1,
        eflags = -2,
    };

    enum Eflags : int {
        A = 0,
        C = 1,
        S = 2,
        Z = 3,
        P = 4,
        O = 5,
        D = 6,
    };

}