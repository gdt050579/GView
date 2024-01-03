#include "global.hpp"

using namespace GView::View;
using namespace GView::Utils;
using namespace GView::Java;

extern "C" {
PLUGIN_EXPORT bool Validate(const BufferView& buf, const std::string_view& extension)
{
    AppCUI::Log::ToStdErr();
    if (buf.GetLength() < sizeof(uint32))
        return false;

    uint32 magic;
    memcpy(&magic, buf.GetData(), sizeof(magic));
    return magic == Endian::NativeToBig(0xCAFEBABE);
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new ClassViewer();
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto plugin = win->GetObject()->GetContentType()->To<ClassViewer>();
    parse_class(plugin);

    BufferViewer::Settings settings;
    for (uint32 i = 0; i < plugin->areas.size(); ++i) {
        auto& current = plugin->areas[i];
        auto color    = i % 2 == 0 ? ColorPair{ Color::Yellow, Color::DarkBlue } : ColorPair{ Color::Green, Color::DarkBlue };

        settings.AddZone(current.start, current.end - current.start, color, current.name);
    }

    FCHECK(win->CreateViewer(settings));

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]  = "magic:CA FE BA BE";
    sect["Priority"] = 1;
}
}

namespace GView::Java
{
string_view ClassViewer::GetTypeName()
{
    return "class";
}

void ClassViewer::RunCommand(std::string_view)
{
}
} // namespace GView::Java

// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-7.html
// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-6.html
// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-4.html