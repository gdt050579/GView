#include <GView.hpp>
#include <llvm/Demangle/Demangle.h>

using namespace llvm;

namespace GView::Utils
{
bool Demangle(const char* input, String& output, DemangleKind format)
{
    char* result{};
    switch (format)
    {
    case DemangleKind::Itanium:
        result = itaniumDemangle(input, nullptr, nullptr, nullptr);
        break;
    case DemangleKind::Microsoft:
        result = microsoftDemangle(input, nullptr, nullptr, nullptr, nullptr);
        break;
    case DemangleKind::Rust:
        result = rustDemangle(input, nullptr, nullptr, nullptr);
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

    output.Add(result);
    free(result);
    return true;
}
} // namespace GView::Utils