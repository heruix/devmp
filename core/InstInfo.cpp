#include "InstInfo.h"

namespace devmp {
    bool InstInfo::isKeep() const {
        return keep;
    }

    void InstInfo::setKeep(bool keep) {
        InstInfo::keep = keep;
    }

    bool InstInfo::isUseless() const {
        return useless;
    }

    void InstInfo::setUseless(bool useless) {
        InstInfo::useless = useless;
    }

    bool InstInfo::isDeleted() const {
        return deleted;
    }

    void InstInfo::setDeleted(bool deleted) {
        InstInfo::deleted = deleted;
    }

    void InstInfo::setRegRead(Regs reg, bool selected) {
        setRegBitFlag(reg, selected, regs_read);
    }

    void InstInfo::setRegWrite(Regs reg, bool selected) {
        setRegBitFlag(reg, selected, regs_write);
    }

    void InstInfo::setRegBitFlag(Regs reg, bool flag, uint64_t &var) {
        if (reg < 0) {
            return;
        }
        int64_t mask = 0;
        const int64_t one = 1;
        switch (reg) {
            case Regs::rax:
                mask |= one << Regs::rax;
            case Regs::eax:
                mask |= one << Regs::eax;
            case Regs::ax:
                mask |= one << Regs::ax;
                mask |= one << Regs::ah;
            case Regs::al:
                mask |= one << Regs::al;
                break;
            case Regs::ah:
                mask |= one << Regs::ah;
                break;
            case Regs::rbx:
                mask |= one << Regs::rbx;
            case Regs::ebx:
                mask |= one << Regs::ebx;
            case Regs::bx:
                mask |= one << Regs::bx;
                mask |= one << Regs::bh;
            case Regs::bl:
                mask |= one << Regs::bl;
                break;
            case Regs::bh:
                mask |= one << Regs::bh;
                break;
            case Regs::rcx:
                mask |= one << Regs::rcx;
            case Regs::ecx:
                mask |= one << Regs::ecx;
            case Regs::cx:
                mask |= one << Regs::cx;
                mask |= one << Regs::ch;
            case Regs::cl:
                mask |= one << Regs::cl;
                break;
            case Regs::ch:
                mask |= one << Regs::ch;
                break;
            case Regs::rdx:
                mask |= one << Regs::rdx;
            case Regs::edx:
                mask |= one << Regs::edx;
            case Regs::dx:
                mask |= one << Regs::dx;
                mask |= one << Regs::dh;
            case Regs::dl:
                mask |= one << Regs::dl;
                break;
            case Regs::dh:
                mask |= one << Regs::dh;
                break;
            case Regs::rbp:
            case Regs::rsp:
                mask |= one << reg;
                break;
            case Regs::rsi:
                mask |= one << Regs::rsi;
            case Regs::esi:
                mask |= one << Regs::esi;
            case Regs::si:
                mask |= one << Regs::si;
            case Regs::sil:
                mask |= one << Regs::sil;
                break;
            case Regs::rdi:
                mask |= one << Regs::rdi;
            case Regs::edi:
                mask |= one << Regs::edi;
            case Regs::di:
                mask |= one << Regs::di;
            case Regs::dil:
                mask |= one << Regs::dil;
                break;
            case Regs::r8:
                mask |= one << Regs::r8;
            case Regs::r8d:
                mask |= one << Regs::r8d;
            case Regs::r8w:
                mask |= one << Regs::r8w;
            case Regs::r8b:
                mask |= one << Regs::r8b;
                break;
            case Regs::r9:
                mask |= one << Regs::r9;
            case Regs::r9d:
                mask |= one << Regs::r9d;
            case Regs::r9w:
                mask |= one << Regs::r9w;
            case Regs::r9b:
                mask |= one << Regs::r9b;
                break;
            case Regs::r10:
                mask |= one << Regs::r10;
            case Regs::r10d:
                mask |= one << Regs::r10d;
            case Regs::r10w:
                mask |= one << Regs::r10w;
            case Regs::r10b:
                mask |= one << Regs::r10b;
                break;
            case Regs::r11:
                mask |= one << Regs::r11;
            case Regs::r11d:
                mask |= one << Regs::r11d;
            case Regs::r11w:
                mask |= one << Regs::r11w;
            case Regs::r11b:
                mask |= one << Regs::r11b;
                break;
            case Regs::r12:
                mask |= one << Regs::r12;
            case Regs::r12d:
                mask |= one << Regs::r12d;
            case Regs::r12w:
                mask |= one << Regs::r12w;
            case Regs::r12b:
                mask |= one << Regs::r12b;
                break;
            case Regs::r13:
                mask |= one << Regs::r13;
            case Regs::r13d:
                mask |= one << Regs::r13d;
            case Regs::r13w:
                mask |= one << Regs::r13w;
            case Regs::r13b:
                mask |= one << Regs::r13b;
                break;
            case Regs::r14:
                mask |= one << Regs::r14;
            case Regs::r14d:
                mask |= one << Regs::r14d;
            case Regs::r14w:
                mask |= one << Regs::r14w;
            case Regs::r14b:
                mask |= one << Regs::r14b;
                break;
            case Regs::r15:
                mask |= one << Regs::r15;
            case Regs::r15d:
                mask |= one << Regs::r15d;
            case Regs::r15w:
                mask |= one << Regs::r15w;
            case Regs::r15b:
                mask |= one << Regs::r15b;
                break;
        }
        if (flag) {
            var |= mask;
        } else {
            var &= ~mask;
        }
    }

    InstInfo::InstInfo(cs_insn *inst) : inst(inst) {}

    void InstInfo::setEflags(uint64_t eflags) {
#define test_eflags_rw(flags) \
        if(eflags&(X86_EFLAGS_SET_##flags##F|X86_EFLAGS_MODIFY_##flags##F|X86_EFLAGS_RESET_##flags##F|X86_EFLAGS_PRIOR_##flags##F)){ \
            this->eflags_write|=1<<Eflags::flags; \
        }\
        if(eflags&X86_EFLAGS_TEST_##flags##F){ \
            this->eflags_read|=1<<Eflags::flags;\
        }
        test_eflags_rw(A)
        test_eflags_rw(C)
        test_eflags_rw(S)
        test_eflags_rw(Z)
        test_eflags_rw(P)
        test_eflags_rw(O)
        test_eflags_rw(D)
#undef test_eflags_rw
    }

}