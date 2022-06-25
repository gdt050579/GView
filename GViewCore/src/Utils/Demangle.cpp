#include <memory>
#include <GView.hpp>
#include <llvm/Demangle/Demangle.h>

using namespace llvm;

namespace GView::Utils
{
bool Demangle(std::string_view input, String& output, DemangleKind format)
{
    LocalString<1024> temp;
    CHECK(temp.Set(input.data(), (uint32) input.size()), false, "");

    unique_ptr<char, decltype(free)*> result(nullptr, free);
    switch (format)
    {
    case DemangleKind::Itanium:
        result.reset(itaniumDemangle(temp.GetText(), nullptr, nullptr, nullptr));
        break;
    case DemangleKind::Microsoft:
        result.reset(microsoftDemangle(temp.GetText(), nullptr, nullptr, nullptr, nullptr));
        break;
    case DemangleKind::Rust:
        result.reset(rustDemangle(temp.GetText(), nullptr, nullptr, nullptr));
        break;
    case DemangleKind::Auto:
    {
        const auto sResult = demangle(temp.GetText());
        CHECK(sResult != temp.GetText(), false, "");
        CHECK(output.Add(sResult), false, "");

        return true;
    }
    }

    CHECK(result != nullptr, false, "");
    CHECK(output.Add(&*result), false, "");

    return true;
}
} // namespace GView::Utils