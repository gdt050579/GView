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

    PLUGIN_EXPORT TypeInterface* CreateInstance(Reference<FileCache> file)
    {
        return new MachOFile(file);
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<MachOFile> machO)
    {
        BufferViewer::Settings settings;
        uint64_t offset = 0;

        const auto headerSize = sizeof(mach_header) + machO->is64 ? sizeof(mach_header::reserved) : 0;
        settings.AddZone(offset, headerSize, machO->colors.header, "Header");
        offset += headerSize;

        LocalString<128> tmp;
        uint32_t commandsCount = 0;
        for (const auto& lc : machO->loadCommands)
        {
            settings.AddZone(lc.offset, lc.value.cmdsize, machO->colors.loadCommand, tmp.Format("LC (#%u)", commandsCount));
            offset = lc.offset + lc.value.cmdsize;
            commandsCount++;
        }

        for (const auto& segment : machO->segments)
        {
            for (const auto& s : segment.sections)
            {
                settings.AddZone(s.offset, s.size, machO->colors.section, s.sectname);
            }
        }

        if (machO->main.isSet)
        {
            settings.SetEntryPointOffset(machO->main.ep.entryoff);
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
