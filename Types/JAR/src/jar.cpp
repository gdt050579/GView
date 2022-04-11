#include "global.hpp"

using namespace GView::View;
using namespace GView::Utils;
using namespace GView::Java;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const BufferView& buf, const string_view& extension)
    {
        AppCUI::Log::ToStdErr();
        if (buf.GetLength() < sizeof(uint32))
            return false;

        uint32 magic;
        memcpy(&magic, buf.GetData(), sizeof(magic));
        return magic == Endian::native_to_big(0xCAFEBABE);
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<FileCache> file)
    {
        auto buffer = file->GetEntireFile();
        if (!parse_class(buffer))
            return nullptr;
        return new JavaViewer;
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
    {
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const auto patterns = { "hex:'CA FE BA BE'" };

        sect["Pattern"]  = patterns;
        sect["Priority"] = 1;
    }
}

namespace GView::Java
{
string_view JavaViewer::GetTypeName()
{
    return "jar";
}
} // namespace GView::Java

// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-7.html
// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-6.html
// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-4.html