#include "pe.hpp"

using namespace AppCUI;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;

extern "C"
{
    bool PLUGIN_EXPORT Validate(const GView::Utils::Buffer& buf, const std::string_view& extension)
    {
        if (buf.length < sizeof(PE::ImageDOSHeader))
            return false;
        auto dos = reinterpret_cast<const PE::ImageDOSHeader*>(buf.data);
        if (dos->e_magic != __IMAGE_DOS_SIGNATURE)
            return false;
        if (dos->e_lfanew + sizeof(PE::ImageNTHeaders32) > buf.length)
            return false;
        auto nth32 = reinterpret_cast<const PE::ImageNTHeaders32*>(buf.data + dos->e_lfanew);
        return nth32->Signature == __IMAGE_NT_SIGNATURE;
    }
    Instance PLUGIN_EXPORT CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new PE::PEFile(file);
    }
    void PLUGIN_EXPORT DeleteInstance(Instance instance)
    {
        if (instance)
            delete (PE::PEFile*) instance;
    }
    bool PLUGIN_EXPORT PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pe = reinterpret_cast<PE::PEFile*>(win->GetObject()->instance);
        pe->Update();

        auto b = win->AddBufferView("Buffer View");
        pe->UpdateBufferViewZones(b);

        if (pe->HasPanel(PE::Panels::IDs::Information))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Information(pe)), true);
        if (pe->HasPanel(PE::Panels::IDs::Sections))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Sections(pe,win)), false);
        if (pe->HasPanel(PE::Panels::IDs::Directories))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Directories(pe, win)), true);
        return true;
    }
}

int main()
{
    return 0;
}
