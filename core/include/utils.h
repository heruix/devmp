#pragma once

#include <cstddef>
#include <cstdint>
#include <capstone/capstone.h>
#include "InstManager.h"

namespace devmp {
    bool isInstMemOp(csh handle, cs_insn *inst);

    bool isJccOp(csh handle, cs_insn *insn);

    bool specialInst(csh handle, cs_insn *insn, InstInfo *instInfo);

    Regs getRegsFromName(const char *name);
}
