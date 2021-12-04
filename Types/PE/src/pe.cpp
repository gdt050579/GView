#include "pe.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
    {
        auto dos = buf.GetObject<PE::ImageDOSHeader>();
        if (!dos)
            return false;
        if (dos->e_magic != PE::Constants::IMAGE_DOS_SIGNATURE)
            return false;
        auto nth32 = buf.GetObject<PE::ImageNTHeaders32>(dos->e_lfanew);
        if (!nth32)
            return false;
        return nth32->Signature == PE::Constants::IMAGE_NT_SIGNATURE;
    }
    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<GView::Utils::FileCache> file)
    {
        return new PE::PEFile(file);
    }
    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PE::PEFile> pe)
    {
        LocalString<128> tempStr;
        BufferViewer::Settings settings;

        settings.AddZone(0, sizeof(pe->dos), pe->peCols.colMZ, "DOS Header");
        settings.AddZone(pe->dos.e_lfanew, sizeof(pe->nth32), pe->peCols.colPE, "NT Header");
        if (pe->nrSections > 0)
            settings.AddZone(pe->sectStart, pe->nrSections * sizeof(PE::ImageSectionHeader), pe->peCols.colSectDef, "SectDef");

        // sections
        for (uint32_t tr = 0; tr < pe->nrSections; tr++)
        {
            if ((pe->sect[tr].PointerToRawData != 0) && (pe->sect[tr].SizeOfRawData > 0))
            {
                pe->CopySectionName(tr, tempStr);
                settings.AddZone(pe->sect[tr].PointerToRawData, pe->sect[tr].SizeOfRawData, pe->peCols.colSect, tempStr);
                if (tr < 9)
                    settings.AddBookmark(tr + 1, pe->sect[tr].PointerToRawData);
            }
        }

        // directories
        auto* dr = pe->dirs;
        for (auto tr = 0; tr < 15; tr++, dr++)
        {
            if ((dr->VirtualAddress > 0) && (dr->Size > 0))
            {
                if (tr == (uint8_t) PE::DirectoryType::Security)
                {
                    settings.AddZone(dr->VirtualAddress, dr->Size, pe->peCols.colDir[tr], PE::PEFile::DirectoryIDToName(tr));
                }
                else
                {
                    const auto filePoz = pe->RVAtoFilePointer(dr->VirtualAddress);
                    if (filePoz != PE_INVALID_ADDRESS)
                    {
                        settings.AddZone(filePoz, dr->Size, pe->peCols.colDir[tr], PE::PEFile::DirectoryIDToName(tr));
                    }
                }
            }
        }

        // translation
        settings.SetOffsetTranslationList({ "RVA", "VirtAddress" }, pe.UpCast<GView::View::BufferViewer::OffsetTranslateInterface>());

        // set specific color for opcodes
        switch (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine))
        {
        case PE::MachineType::I386:
        case PE::MachineType::IA64:
        case PE::MachineType::AMD64:
            pe->x86x64ColorBuffer.memStartOffset = pe->imageBase;
            pe->x86x64ColorBuffer.memEndOffset   = pe->imageBase + pe->virtualComputedSize;
            settings.SetPositionToColorCallback(&pe->x86x64ColorBuffer);
            break;
        };

        // set entry point
        settings.SetEntryPointOffset(pe->RVAtoFilePointer(pe->nth32.OptionalHeader.AddressOfEntryPoint));

        win->CreateViewer("BufferView", settings);
    }
    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pe = reinterpret_cast<PE::PEFile*>(win->GetObject()->type);
        pe->Update();

        CreateBufferView(win, pe);

        if (pe->HasPanel(PE::Panels::IDs::Information))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Information(pe)), true);
        if (pe->HasPanel(PE::Panels::IDs::Headers))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Headers(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Sections))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Sections(pe, win)), false);
        if (pe->HasPanel(PE::Panels::IDs::Directories))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Directories(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Imports))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Imports(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Exports))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Exports(pe, win)), true);
        if (pe->HasPanel(PE::Panels::IDs::Resources))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Resources(pe, win)), false);
        if (pe->HasPanel(PE::Panels::IDs::Icons))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Icons(pe, win)), true);
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
