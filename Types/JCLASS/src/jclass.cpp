#include "jclass.hpp"

using namespace GView::View;
using namespace GView::Utils;
using namespace GView::Type::JClass;

#define FCHECK(x) CHECK(x, false, #x)

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

PLUGIN_EXPORT GView::TypeInterface* CreateInstance()
{
    return new ClassViewer();
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto plugin = win->GetObject()->GetContentType()->To<ClassViewer>();

    BufferViewer::Settings bufferViewerSettings;
    bufferViewerSettings.SetName("BufferViewer");

    DissasmViewer::Settings disasmViewerSettings;
    disasmViewerSettings.AddDisassemblyZone(0, win->GetObject()->GetData().GetSize(), 0, DissasmViewer::DisassemblyLanguage::JavaByteCode);

#ifndef DISSASM_DEV
    FCHECK(win->CreateViewer(bufferViewerSettings));
    FCHECK(win->CreateViewer(disasmViewerSettings));
#else
    FCHECK(win->CreateViewer(disasmViewerSettings));
    FCHECK(win->CreateViewer(bufferViewerSettings));
#endif

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]  = "magic:CA FE BA BE";
    sect["Priority"] = 1;
}
}

// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-7.html
// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-6.html
// https://docs.oracle.com/javase/specs/jvms/se18/html/jvms-4.html