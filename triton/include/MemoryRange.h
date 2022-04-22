#pragma once

#include <cstddef>

namespace devmp {
    class MemoryRange {
    public:
        size_t end;
        size_t start;
        char* buf;
        MemoryRange(size_t start, size_t anEnd, char *buf);
    };
}