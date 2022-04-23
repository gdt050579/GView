#include "MAM.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

#ifdef BUILD_FOR_WINDOWS
#    include <Windows.h>
#    include <VersionHelpers.h>
#    undef GetObject
#endif

namespace GView::Type::MAM
{
bool Decompress(const BufferView& compressed, Buffer& decompressed)
{
#ifdef BUILD_FOR_WINDOWS
    CHECK(IsWindows8OrGreater(), false, "Cannot perform decompression on systems older than Windows 8. ");

    const auto rtlDecompressBufferEx = (DWORD(WINAPI*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID))(
          GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlDecompressBufferEx"));
    CHECK(rtlDecompressBufferEx != nullptr, false, "");

    const auto rtlGetCompressionWorkSpaceSize =
          (DWORD(WINAPI*)(USHORT, PULONG, PULONG))(GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlGetCompressionWorkSpaceSize"));
    CHECK(rtlGetCompressionWorkSpaceSize != nullptr, false, "");

    CHECK(compressed.IsValid(), false, "");
    CHECK(decompressed.GetLength() > 8, false, "");

    ULONG workspaceSize, unkSize;
    auto err = rtlGetCompressionWorkSpaceSize(
          COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_STANDARD,
          &workspaceSize,
          &unkSize // Cannot be nullptr, or else we get an access violation error
    );
    CHECK(err == 0, false, "Error code: 0x%08X", err);

    std::unique_ptr<BYTE[]> workspaceBuffer(new BYTE[workspaceSize]);
    CHECK(workspaceBuffer, false, "");

    ULONG finalUncompressedSize;

    err = rtlDecompressBufferEx(
          COMPRESSION_FORMAT_XPRESS_HUFF,
          (BYTE*) decompressed.GetData(),
          (ULONG) decompressed.GetLength(),
          (BYTE*) compressed.GetData(),
          (ULONG) compressed.GetLength(),
          &finalUncompressedSize,
          (void*) workspaceBuffer.get());

    CHECK(err == (uint32) CompressionStatus::Success, false, "Error code: 0x%08X", err);
    CHECK(finalUncompressedSize == decompressed.GetLength(), false, "");
#else
#    ifdef __OS_MACHO__
    // TODO
#    else
    // TODO
#    endif
#endif
    return true;
}
} // namespace GView::Type::MAM

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        struct Sig
        {
            uint32 sig;
        };
        auto signature = buf.GetObject<Sig>(0);
        CHECK(signature.IsValid(), false, "");
        CHECK(signature->sig == MAM::SIGNATURE, false, "");

        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new MAM::MAMFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MAM::MAMFile> mam)
    {
        BufferViewer::Settings settings;

        settings.AddZone(0, 4, ColorPair{ Color::Pink, Color::DarkBlue }, "Signature");
        settings.AddZone(4, 4, ColorPair{ Color::Magenta, Color::DarkBlue }, "Size Uncompressed");
        settings.AddZone(8, win->GetObject()->GetData().GetSize() - 8, ColorPair{ Color::DarkGreen, Color::DarkBlue }, "Content");

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto mam = win->GetObject()->GetContentType<MAM::MAMFile>();
        mam->Update();

        // add views
        CreateBufferView(win, mam);

        // add panels
        win->AddPanel(Pointer<TabPage>(new MAM::Panels::Information(win->GetObject(), mam)), true);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]   = "hex:'4D 41 4D 04'";
        sect["Extension"] = "pf";
        sect["Priority"]  = 1;
    }
}
