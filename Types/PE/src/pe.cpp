#include "pe.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        auto dos = buf.GetObject<PE::ImageDOSHeader>();
        if (!dos)
            return false;
        if (dos->e_magic != __IMAGE_DOS_SIGNATURE)
            return false;
        auto nth32 = buf.GetObject<PE::ImageNTHeaders32>(dos->e_lfanew);
        if (!nth32)
            return false;
        return nth32->Signature == __IMAGE_NT_SIGNATURE;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new PE::PEFile(file);
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pe = reinterpret_cast<PE::PEFile*>(win->GetObject()->type);
        pe->Update();

        auto b = win->AddBufferViewer("Buffer View");
        pe->UpdateBufferViewZones(b);

        if (pe->HasPanel(PE::Panels::IDs::Information))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Information(pe)), true);
        if (pe->HasPanel(PE::Panels::IDs::Sections))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Sections(pe, win)), false);
        if (pe->HasPanel(PE::Panels::IDs::Directories))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Directories(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Imports))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Imports(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Exports))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Exports(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Resources))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Resources(pe, win)), true);
        return true;
    }
    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect.UpdateValue("Pattern", "MZ", false);
        sect.UpdateValue("Priority", 1, false);
    }
}

int main()
{
    return 0;
}
