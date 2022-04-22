#include "TraceEngine.h"

namespace devmp {
    using namespace triton;

    void TraceEngine::process(size_t start_addr) {

    }

    TraceEngine::TraceEngine() {
        ctx.setArchitecture(arch::ARCH_X86_64);
        ctx.setMode(modes::mode_e::ALIGNED_MEMORY, true);
        ctx.setMode(modes::mode_e::AST_OPTIMIZATIONS, true);
        ctx.setMode(modes::mode_e::CONSTANT_FOLDING, true);
    }

    TraceEngine::~TraceEngine() {
    }
}