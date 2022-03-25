#include <memory>
#include <GView.hpp>
#include <llvm/Demangle/Demangle.h>

using namespace llvm;

namespace GView::Utils
{
bool Demangle(const char* input, String& output, DemangleKind format)
{
    unique_ptr<char, decltype(free)*> result(nullptr, free);
    switch (format)
    {
    case DemangleKind::Itanium:
        result.reset(itaniumDemangle(input, nullptr, nullptr, nullptr));
        break;
    case DemangleKind::Microsoft:
        result.reset(microsoftDemangle(input, nullptr, nullptr, nullptr, nullptr));
        break;
    case DemangleKind::Rust:
        result.reset(rustDemangle(input, nullptr, nullptr, nullptr));
        break;
    case DemangleKind::Auto:
    {
        auto result = demangle(input);
        if (result == input)
            return false;
        output.Add(result);
        return true;
    }
    }
    if (result == nullptr)
        return false;

    output.Add(&*result);
    return true;
}
} // namespace GView::Utils