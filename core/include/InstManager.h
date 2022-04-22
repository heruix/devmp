#pragma once

#include <vector>
#include <capstone/capstone.h>
#include <string>
#include <stack>
#include "InstInfo.h"

namespace devmp {

    class InstManager {

    public:
        bool simplified=false;
        std::vector<InstInfo *> *insts;
        std::stack<std::pair<cs_insn *,size_t>> *insn_stack;
        csh handle{};
        cs_insn *insn{nullptr};
        uint64_t insn_count{0}, insn_index{0};

        InstManager();

        ~InstManager();

        bool next();

        int64_t setAsm(const uint8_t *code, size_t code_len, size_t start_address);

        void simplify();

        void clear();

        [[nodiscard]] std::string toString();

        void getBytes(uint8_t *&, size_t&);

        friend std::ostream &operator<<(std::ostream &os, InstManager &inst_manager);
    };

}
