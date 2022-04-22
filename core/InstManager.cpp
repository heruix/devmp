#include "InstManager.h"
#include "utils.h"
#include "capstone/x86.h"
//#include ""

namespace devmp {

    InstManager::InstManager() {
        this->insts = new std::vector<InstInfo *>();
        this->insn_stack = new std::stack<std::pair<cs_insn *, size_t>>();
        cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
        cs_option(handle, cs_opt_type::CS_OPT_DETAIL, cs_opt_value::CS_OPT_ON);
    }

    InstManager::~InstManager() {
        for (auto i: *insts) {
            delete i;
        }
        delete insts;
        while (!insn_stack->empty()) {
            auto s = insn_stack->top();
            insn_stack->pop();
            cs_free(s.first, s.second);
        }
        delete insn_stack;
        cs_close(&handle);
    }

    int64_t InstManager::setAsm(const uint8_t *code, size_t code_len, size_t start_address) {
        cs_insn *old_insn = insn;
        size_t count = cs_disasm(handle, code, code_len, start_address, 0, &insn);
        if (count <= 0) {
            insn = old_insn;
            return -1;
        }
        insn_stack->emplace(insn, count);
        insn_count = count;
        insn_index = 0;
        return (int64_t) count;
    }

    void InstManager::clear() {
        for (auto i: *insts) {
            delete i;
        }
        this->insts->clear();
        while (!insn_stack->empty()) {
            auto s = insn_stack->top();
            insn_stack->pop();
            cs_free(s.first, s.second);
        }
        insn_index = 0;
        insn_count = 0;

    }


    bool InstManager::next() {
        if (insn_index >= insn_count || insn == nullptr) {
            return false;
        }
        simplified = false;
        cs_insn *current_insn = &insn[insn_index++];

        auto *instInfo = new InstInfo(current_insn);

//            判断是否是内存操作 如果是内存操作就标记keep
        if (isInstMemOp(handle, current_insn) || isJccOp(handle, current_insn)) {
            instInfo->setKeep(true);
        }

//            标记寄存器读写
        if (!specialInst(handle, current_insn, instInfo)) {
            instInfo->setEflags(current_insn->detail->x86.eflags);
            cs_regs regs_read, regs_write;
            uint8_t regs_read_count, regs_write_count;
            if (!cs_regs_access(handle, current_insn,
                                regs_read, &regs_read_count,
                                regs_write, &regs_write_count)) {
                if (regs_read_count) {
                    for (size_t i = 0; i < regs_read_count; i++) {
                        const char *reg_name = cs_reg_name(handle, regs_read[i]);
                        Regs reg = getRegsFromName(reg_name);
                        if (reg == Regs::unknown) {
                            instInfo->setKeep(true);
                        } else if (reg == Regs::eflags) {
                            continue;
                        } else {
                            instInfo->setRegRead(reg, true);
                        }
                    }
                }

                if (regs_write_count) {
                    for (size_t i = 0; i < regs_write_count; i++) {
                        const char *reg_name = cs_reg_name(handle, regs_write[i]);
                        Regs reg = getRegsFromName(reg_name);
                        if (reg == Regs::unknown) {
                            instInfo->setKeep(true);
                        } else if (reg == Regs::eflags) {
                            continue;
                        } else {
                            instInfo->setRegWrite(reg, true);
                        }
                    }
                }
            } else {
                return false;
            }
        }
        this->insts->push_back(instInfo);
        return true;
    }

    void InstManager::simplify() {
        uint64_t last_reg_write = 0;
        uint16_t last_eflags_write = 0;
        for (auto inst_ptr = insts->rbegin(); inst_ptr != insts->rend(); inst_ptr++) {
            InstInfo *inst = *inst_ptr;
            if (inst->isDeleted() || inst->isUseless()) {
                continue;
            }
            if (!inst->isKeep()) {
                bool t = (inst->regs_write & last_reg_write) || (inst->eflags_write & last_eflags_write);
                inst->regs_write &= ~last_reg_write;
                inst->eflags_write &= ~last_eflags_write;
                if (t && inst->regs_write == 0 && inst->eflags_write == 0) {
                    inst->setDeleted(true);
                    continue;
                }
            }

            last_reg_write |= inst->regs_write;
            last_reg_write &= ~inst->regs_read;
            last_eflags_write |= inst->eflags_write;
            last_eflags_write &= ~inst->eflags_read;
        }
        simplified = true;
    }

    void InstManager::getBytes(uint8_t *&ptr, size_t&size) {
        if(!simplified)
            this->simplify();
        size=0;
        for (InstInfo *inst: *insts) {
            if(inst->isDeleted()||inst->isUseless())
                continue;
            size+=inst->inst->size;
        }
        auto * result=new uint8_t [size];
        ptr=result;
        for (InstInfo *inst: *insts) {
            if(inst->isDeleted()||inst->isUseless())
                continue;
            result=std::copy(inst->inst->bytes, &inst->inst->bytes[0]+inst->inst->size, result);
        }
    }

    std::string InstManager::toString() {
        if (!simplified)
            this->simplify();
        std::string result;
        char buf[200];
        size_t deleted = 0;
        for (InstInfo *inst: *insts) {
            if (inst->isDeleted()) {
                deleted++;
                result.append("\033[41m");
            } else if (inst->isUseless()) {
                result.append("\033[33;41m");
            } else if (inst->isKeep()) {
                result.append("\033[33m");
            } else {
//                result.append("\033[1m");
            }
            sprintf(buf, "0x%" PRIx64":\t%s\t\t%s", inst->inst->address, inst->inst->mnemonic, inst->inst->op_str);
            result.append(buf);
            result.append("\033[0m\n");
        }
        sprintf(buf, "Deleted %lu from %lu", deleted, insts->size());
        result.append(buf);
        return result;
    }

    std::ostream &operator<<(std::ostream &os, InstManager &inst_manager) {
        os << inst_manager.toString();
        return os;
    }


}

