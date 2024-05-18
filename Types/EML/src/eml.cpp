#include "eml.hpp"
#include <string>
#include <locale>
#include <codecvt>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

constexpr string_view EML_ICON = "1111111111111111"  // 1
                                 "1111111111111111"  // 2
                                 "1111111111111111"  // 3
                                 "1111111111111111"  // 4
                                 "wwwwwwwwwwwwwwww"  // 5
                                 "ww111111111111ww"  // 6
                                 "w1ww11111111ww1w"  // 7
                                 "w111ww1111ww111w"  // 8
                                 "w11111wwww11111w"  // 9
                                 "w11111111111111w"  // 10
                                 "w11111111111111w"  // 11
                                 "wwwwwwwwwwwwwwww"  // 12
                                 "1111111111111111"  // 13
                                 "1111111111111111"  // 14
                                 "1111111111111111"  // 15
                                 "1111111111111111"; // 16

template <typename T>
std::string toUTF8(const std::basic_string<T>& source)
{
    std::string result;

    std::wstring_convert<std::codecvt_utf8_utf16<T>, T> convertor;
    result = convertor.to_bytes(source);

    return result;
}

void CreateContainerView(Reference<GView::View::WindowInterface> win, Reference<EML::EMLFile> eml)
{
    ContainerViewer::Settings settings;

    const auto& headers = eml->GetHeaders();
    for (const auto& [name, value] : headers) {
        if (name == u"Cc") // TODO: to be removed when issues https://github.com/gdt050579/GView/issues/301 is fixed
            continue;

        std::string nameStr = toUTF8(name);
        settings.AddProperty(nameStr, value);
    }

    settings.SetIcon(EML_ICON);
    settings.SetColumns({
          "n:&Index,a:r,w:50",
          "n:&Content-Type,a:r,w:50",
          "n:&Size,a:r,w:20",
          "n:&Offset,a:r,w:20",
    });

    settings.SetEnumerateCallback(win->GetObject()->GetContentType<EML::EMLFile>().ToObjectRef<ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<EML::EMLFile>().ToObjectRef<ContainerViewer::OpenItemInterface>());

    win->CreateViewer(settings);
}

extern "C" {
PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    // no validation atm
    return true;
}
PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new EML::EMLFile();
}

PLUGIN_EXPORT bool PopulateWindow(Reference<WindowInterface> win)
{
    auto eml = win->GetObject()->GetContentType<EML::EMLFile>();

    // TODO: consider check??
    eml->ProcessData();

    CreateContainerView(win, eml);
    win->AddPanel(Pointer<TabPage>(new EML::Panels::Information(eml)), true);

    return true;
}
PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Extension"]   = { "eml" };
    sect["Priority"]    = 1;
    sect["Description"] = "Electronic Mail Format (*.eml)";
}
}

int main()
{
    return 0;
}
