#include "capstone/capstone.h"
#include "utils.h"
#include "InstInfo.h"
#include "consts.h"
#include <cstring>

namespace devmp {

    bool isInstMemOp(csh handle, cs_insn *inst) {
        if (!strcmp(inst->mnemonic, "lea")) {
            return false;
        }
        if (!strcmp(inst->mnemonic, "push") || !strcmp(inst->mnemonic, "pop")|| !strcmp(inst->mnemonic, "pushfs") || !strcmp(inst->mnemonic, "popfs")) {
            return true;
        }
        return cs_op_count(handle, inst, X86_OP_MEM) != 0;
    }

    bool isJccOp(csh handle, cs_insn *insn) {
        if (!strcmp(insn->mnemonic, "jmp")) {
            return true;
        }
        return insn->mnemonic[0] == 'j' && cs_reg_read(handle, insn, x86_reg::X86_REG_EFLAGS);
    }

    bool specialInst(csh handle, cs_insn *insn, InstInfo *instInfo) {
        if (!strcmp(insn->mnemonic, "xor")) {
            if (insn->detail->x86.op_count == 2) {
                cs_x86_op &op0 = insn->detail->x86.operands[0];
                cs_x86_op &op1 = insn->detail->x86.operands[1];
                if (op0.type == x86_op_type::X86_OP_REG && op1.type == x86_op_type::X86_OP_REG && op1.reg == op0.reg) {
                    instInfo->setRegWrite(getRegsFromName(cs_reg_name(handle, op0.reg)), true);
                    return true;
                }
                if (op1.type == x86_op_type::X86_OP_IMM && op1.imm == 0) {
                    instInfo->setUseless(true);
                    return true;
                }
            }
        } else if (!strcmp(insn->mnemonic, "sub")) {
            if (insn->detail->x86.op_count == 2) {
                cs_x86_op &op0 = insn->detail->x86.operands[0];
                cs_x86_op &op1 = insn->detail->x86.operands[1];
                if (op0.type == x86_op_type::X86_OP_REG && op1.type == x86_op_type::X86_OP_REG && op1.reg == op0.reg) {
                    instInfo->setRegWrite(getRegsFromName(cs_reg_name(handle, op0.reg)), true);
                    return true;
                }
                if (op1.type == x86_op_type::X86_OP_IMM && op1.imm == 0) {
                    instInfo->setUseless(true);
                    return true;
                }
            }
        } else if (!strcmp(insn->mnemonic, "and")) {
            if (insn->detail->x86.op_count == 2) {
                cs_x86_op &op0 = insn->detail->x86.operands[0];
                cs_x86_op &op1 = insn->detail->x86.operands[1];
                if (op1.type == x86_op_type::X86_OP_IMM) {
                    if (op1.imm == 0) {
                        instInfo->setRegWrite(getRegsFromName(cs_reg_name(handle, op0.reg)), true);
                        return true;
                    } else if (op1.imm == ~0) {
                        instInfo->setUseless(true);
                        return true;
                    }
                }
            }
        } else if (!strcmp(insn->mnemonic, "or")) {
            if (insn->detail->x86.op_count == 2) {
                cs_x86_op &op0 = insn->detail->x86.operands[0];
                cs_x86_op &op1 = insn->detail->x86.operands[1];
                if (op1.type == x86_op_type::X86_OP_IMM) {
                    if (op1.imm == 0) {
                        instInfo->setUseless(true);
                        return true;
                    } else if (op1.imm == ~0) {
                        instInfo->setRegWrite(getRegsFromName(cs_reg_name(handle, op0.reg)), true);
                        return true;
                    }
                }
            }
        }
        return false;
    }

    Regs getRegsFromName(const char *name) {
        if (name == nullptr) {
            return Regs::unknown;
        }
        switch (*(name++)) {
            case 'a':
                switch (*(name++)) {
                    case 'l':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::al;
                        }
                    case 'h':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::ah;
                        }
                    case 'x':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::ax;
                        }
                }
            case 'e':
                switch (*(name++)) {
                    case 'a':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::eax;
                                }
                        }
                    case 'b':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::ebx;
                                }
                            case 'p':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rbp;
                                }
                        }
                    case 'c':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::ecx;
                                }
                        }
                    case 'd':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::edx;
                                }
                            case 'i':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::edi;
                                }
                        }
                    case 's':
                        switch (*(name++)) {
                            case 'p':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rsp;
                                }
                            case 'i':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::esi;
                                }
                        }
                }
            case 'r':
                switch (*(name++)) {
                    case 'a':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rax;
                                }
                        }
                    case 'b':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rbx;
                                }
                            case 'p':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rbp;
                                }
                        }
                    case 'c':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rcx;
                                }
                        }
                    case 'd':
                        switch (*(name++)) {
                            case 'x':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rdx;
                                }
                            case 'i':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rdi;
                                }
                        }
                    case 's':
                        switch (*(name++)) {
                            case 'p':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rsp;
                                }
                            case 'i':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rsi;
                                }
                        }
                    case '8':
                        switch (*(name++)) {
                            case 'b':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::r8b;
                                }
                            case 'w':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::r8w;
                                }
                            case 'd':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::r8d;
                                }
                            case '\x00':
                                return Regs::r8;
                        }
                    case '9':
                        switch (*(name++)) {
                            case 'b':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::r9b;
                                }
                            case 'w':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::r9w;
                                }
                            case 'd':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::r9d;
                                }
                            case '\x00':
                                return Regs::r9;
                        }
                    case '1':
                        switch (*(name++)) {
                            case '0':
                                switch (*(name++)) {
                                    case 'b':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r10b;
                                        }
                                    case 'w':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r10w;
                                        }
                                    case 'd':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r10d;
                                        }
                                    case '\x00':
                                        return Regs::r10;
                                }
                            case '1':
                                switch (*(name++)) {
                                    case 'b':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r11b;
                                        }
                                    case 'w':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r11w;
                                        }
                                    case 'd':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r11d;
                                        }
                                    case '\x00':
                                        return Regs::r11;
                                }
                            case '2':
                                switch (*(name++)) {
                                    case 'b':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r12b;
                                        }
                                    case 'w':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r12w;
                                        }
                                    case 'd':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r12d;
                                        }
                                    case '\x00':
                                        return Regs::r12;
                                }
                            case '3':
                                switch (*(name++)) {
                                    case 'b':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r13b;
                                        }
                                    case 'w':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r13w;
                                        }
                                    case 'd':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r13d;
                                        }
                                    case '\x00':
                                        return Regs::r13;
                                }
                            case '4':
                                switch (*(name++)) {
                                    case 'b':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r14b;
                                        }
                                    case 'w':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r14w;
                                        }
                                    case 'd':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r14d;
                                        }
                                    case '\x00':
                                        return Regs::r14;
                                }
                            case '5':
                                switch (*(name++)) {
                                    case 'b':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r15b;
                                        }
                                    case 'w':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r15w;
                                        }
                                    case 'd':
                                        switch (*(name++)) {
                                            case '\x00':
                                                return Regs::r15d;
                                        }
                                    case '\x00':
                                        return Regs::r15;
                                }
                        }
                    case 'f':
                        switch (*(name++)) {
                            case 'l':
                                switch (*(name++)) {
                                    case 'a':
                                        switch (*(name++)) {
                                            case 'g':
                                                switch (*(name++)) {
                                                    case 's':
                                                        switch (*(name++)) {
                                                            case '\x00':
                                                                return Regs::eflags;
                                                        }
                                                }
                                        }
                                }
                        }
                }
            case 'b':
                switch (*(name++)) {
                    case 'l':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::bl;
                        }
                    case 'h':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::bh;
                        }
                    case 'x':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::bx;
                        }
                    case 'p':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::rbp;
                            case 'l':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rbp;
                                }
                        }
                }
            case 'c':
                switch (*(name++)) {
                    case 'l':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::cl;
                        }
                    case 'h':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::ch;
                        }
                    case 'x':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::cx;
                        }
                }
            case 'd':
                switch (*(name++)) {
                    case 'l':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::dl;
                        }
                    case 'h':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::dh;
                        }
                    case 'x':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::dx;
                        }
                    case 'i':
                        switch (*(name++)) {
                            case 'l':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::dil;
                                }
                            case '\x00':
                                return Regs::di;
                        }
                }
            case 's':
                switch (*(name++)) {
                    case 'p':
                        switch (*(name++)) {
                            case '\x00':
                                return Regs::rsp;
                            case 'l':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::rsp;
                                }
                        }
                    case 'i':
                        switch (*(name++)) {
                            case 'l':
                                switch (*(name++)) {
                                    case '\x00':
                                        return Regs::sil;
                                }
                            case '\x00':
                                return Regs::si;
                        }
                }
        }
        return Regs::unknown;
    }

}
