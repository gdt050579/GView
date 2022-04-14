#include "MachO.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;
using namespace GView::Type::MachO;
using namespace MAC;

extern "C"
{
    PLUGIN_EXPORT bool Validate(const BufferView& buf, const std::string_view& extension)
    {
        auto dword = buf.GetObject<uint32_t>();
        CHECK(dword != nullptr, false, "");
        const uint32_t magic = dword;
        CHECK(magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64, false, "Magic is [%u]!", magic);
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<DataCache> file)
    {
        return new MachOFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MachOFile> machO)
    {
        BufferViewer::Settings settings;

        const auto headerSize = sizeof(mach_header) + machO->is64 ? sizeof(mach_header::reserved) : 0;
        settings.AddZone(0, headerSize, machO->colors.header, "Header");

        LocalString<128> tmp;
        {
            auto i = 0ULL;
            for (const auto& lc : machO->loadCommands)
            {
                settings.AddZone(lc.offset, lc.value.cmdsize, machO->colors.loadCommand, tmp.Format("(#%u)LC", i));
                i++;
            }
        }

        for (const auto& segment : machO->segments)
        {
            for (const auto& s : segment.sections)
            {
                settings.AddZone(s.offset != 0 ? s.offset : s.addr /* handling __bss section */, s.size, machO->colors.section, s.sectname);
            }
        }

        if (machO->main.has_value())
        {
            settings.SetEntryPointOffset(machO->main->entryoff);
        }

        if (machO->dySymTab.has_value())
        {
            settings.AddZone(
                  machO->dySymTab->sc.symoff,
                  machO->dySymTab->sc.nsyms * (machO->is64 ? sizeof(MAC::nlist_64) : sizeof(MAC::nlist)),
                  machO->colors.section,
                  "Symbol_Table");
            settings.AddZone(machO->dySymTab->sc.stroff, machO->dySymTab->sc.strsize, machO->colors.section, "Symbol_Strings");
        }

        {
            auto i = 0ULL;
            for (const auto& linkEdit : machO->linkEditDatas)
            {
                settings.AddZone(linkEdit.dataoff, linkEdit.datasize, machO->colors.linkEdit, tmp.Format("(#%u)Link_Edit", i));
                i++;
            }
        }

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto mach = reinterpret_cast<MachO::MachOFile*>(win->GetObject()->type);
        mach->Update();

        CreateBufferView(win, mach);

        if (mach->HasPanel(MachO::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Information(mach)), true);
        }

        if (mach->HasPanel(MachO::Panels::IDs::LoadCommands))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::LoadCommands(mach, win)), false);
        }

        if (mach->HasPanel(MachO::Panels::IDs::Segments))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Segments(mach, win)), false);
        }

        if (mach->HasPanel(MachO::Panels::IDs::Sections))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Sections(mach, win)), false);
        }

        if (mach->HasPanel(MachO::Panels::IDs::DyldInfo))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::DyldInfo(mach)), true);
        }

        if (mach->HasPanel(MachO::Panels::IDs::Dylib))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::Dylib(mach, win)), false);
        }

        if (mach->HasPanel(MachO::Panels::IDs::DySymTab))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::SymTab(mach, win)), false);
        }

        if (mach->HasPanel(MachO::Panels::IDs::CodeSign))
        {
            win->AddPanel(Pointer<TabPage>(new MachO::Panels::CodeSignMagic(mach)), true);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        static const std::initializer_list<std::string> patterns = {
            "hex:'" + BinaryToHexString(MAC::MH_MAGIC, sizeof(MAC::MH_MAGIC)) + "'",
            "hex:'" + BinaryToHexString(MAC::MH_CIGAM, sizeof(MAC::MH_CIGAM)) + "'",
            "hex:'" + BinaryToHexString(MAC::MH_MAGIC_64, sizeof(MAC::MH_MAGIC_64)) + "'",
            "hex:'" + BinaryToHexString(MAC::MH_CIGAM_64, sizeof(MAC::MH_CIGAM_64)) + "'"
        };

        sect["Pattern"]  = patterns;
        sect["Priority"] = 1;
    }
}

int main()
{
    return 0;
}
