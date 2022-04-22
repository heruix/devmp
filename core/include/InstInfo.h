#pragma once

#include "capstone/capstone.h"
#include "consts.h"

namespace devmp{

    class InstInfo {
    private:
        static void setRegBitFlag(Regs reg, bool flag, uint64_t &var);

    public:
        cs_insn *inst;
        uint64_t regs_read{0}, regs_write{0};
        uint16_t eflags_read{0}, eflags_write{0};

        bool keep{false}, useless{false}, deleted{false};

        [[nodiscard]] bool isKeep() const;

        void setKeep(bool keep);

        [[nodiscard]] bool isUseless() const;

        void setUseless(bool useless);

        [[nodiscard]] bool isDeleted() const;

        void setDeleted(bool deleted);

        void setRegRead(Regs reg, bool flag);

        void setRegWrite(Regs reg, bool flag);

        void setEflags(uint64_t eflags);

        explicit InstInfo(cs_insn *inst);
    };
}