#pragma once
#include <triton/api.hpp>
#include "MemoryRange.h"
namespace devmp {

    class TraceEngine {
        triton::API ctx;
        std::vector<MemoryRange> mem_map;
    public:
        explicit TraceEngine();
        ~TraceEngine();
        void process(size_t start_addr);

    };

}