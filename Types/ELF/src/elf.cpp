#include "elf.hpp"

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
        CHECK(buf.GetLength() > sizeof(uint32), false, "");
        auto magic = *(uint32*) buf.GetData();
        CHECK(magic == GView::Type::ELF::MAGIC, false, "");
        return true;
    }

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new ELF::ELFFile();
    }

    static const auto HEADER_COLOR      = ColorPair{ Color::Olive, Color::Transparent };
    static const auto PHT_COLOR         = ColorPair{ Color::Magenta, Color::Transparent };
    static const auto SHT_COLOR         = ColorPair{ Color::DarkRed, Color::Transparent };
    static const auto SHT_CONTENT_COLOR = ColorPair{ Color::Silver, Color::Transparent };

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<ELF::ELFFile> elf)
    {
        BufferViewer::Settings settings;

        uint64 offset = 0;
        if (elf->is64)
        {
            settings.AddZone(offset, sizeof(ELF::Elf64_Ehdr), HEADER_COLOR, "Header64");

            offset    = elf->header64.e_phoff;
            auto size = elf->header64.e_phnum * elf->header64.e_phentsize;
            settings.AddZone(offset, size, PHT_COLOR, "PHT64");

            offset = elf->header64.e_shoff;
            size   = elf->header64.e_shnum * elf->header64.e_shentsize;
            settings.AddZone(offset, size, SHT_COLOR, "SHT64");

            auto i = 0;
            for (const auto& section : elf->sections64)
            {
                if (i >= elf->sectionNames.size()) // truncated binaries
                {
                    break;
                }
                const auto& name = elf->sectionNames.at(i++);
                settings.AddZone(section.sh_offset, section.sh_size, SHT_CONTENT_COLOR, name.c_str());
            }

            uint64 epFA = 0;
            for (const auto& segment : elf->segments64)
            {
                if (segment.p_vaddr <= elf->header64.e_entry && elf->header64.e_entry < segment.p_vaddr + segment.p_memsz)
                {
                    epFA = elf->header64.e_entry - segment.p_vaddr + segment.p_offset;
                    break;
                }
            }

            settings.SetEntryPointOffset(epFA);
        }
        else
        {
            settings.AddZone(offset, sizeof(ELF::Elf32_Ehdr), HEADER_COLOR, "Header32");

            offset    = elf->header32.e_phoff;
            auto size = elf->header32.e_phnum * elf->header32.e_phentsize;
            settings.AddZone(offset, size, PHT_COLOR, "PHT32");

            offset = elf->header32.e_shoff;
            size   = elf->header32.e_shnum * elf->header32.e_shentsize;
            settings.AddZone(offset, size, SHT_COLOR, "SHT32");

            auto i = 0;
            for (const auto& section : elf->sections32)
            {
                if (i >= elf->sectionNames.size()) // truncated binaries
                {
                    break;
                }
                const auto& name = elf->sectionNames.at(i++);
                settings.AddZone(section.sh_offset, section.sh_size, SHT_CONTENT_COLOR, name.c_str());
            }

            uint64 epFA = 0;
            for (const auto& segment : elf->segments32)
            {
                if (segment.p_vaddr <= elf->header32.e_entry && elf->header32.e_entry < segment.p_vaddr + segment.p_memsz)
                {
                    epFA = (uint64) elf->header32.e_entry - segment.p_vaddr + segment.p_offset;
                    break;
                }
            }

            settings.SetEntryPointOffset(epFA);
        }

        // translation
        settings.SetOffsetTranslationList({ "VA" }, elf.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

        // set specific color for opcodes
        const auto machine = elf->is64 ? elf->header64.e_machine : elf->header32.e_machine;
        switch (machine)
        {
        case ELF::EM_386:
        case ELF::EM_486:
        case ELF::EM_860:
        case ELF::EM_960:
        case ELF::EM_8051:
        case ELF::EM_X86_64:
            settings.SetPositionToColorCallback(elf.ToBase<GView::View::BufferViewer::PositionToColorInterface>());
            break;
        };

        elf->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto elf = win->GetObject()->GetContentType<ELF::ELFFile>();
        elf->Update();

        // add viewer
        CreateBufferView(win, elf);

        // add panels
        if (elf->HasPanel(ELF::Panels::IDs::Information))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::Information(win->GetObject(), elf)), true);
        }
        if (elf->HasPanel(ELF::Panels::IDs::Segments))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::Segments(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::Sections))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::Sections(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::GoInformation))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::GoInformation(win->GetObject(), elf)), true);
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::GoFiles(win->GetObject(), elf)), true);
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::GoFunctions(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::StaticSymbols))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::StaticSymbols(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::DynamicSymbols))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::DynamicSymbols(elf, win)), false);
        }
        if (elf->HasPanel(ELF::Panels::IDs::OpCodes))
        {
            win->AddPanel(Pointer<TabPage>(new ELF::Panels::OpCodes(win->GetObject(), elf)), true);
        }

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]      = "magic:7F 45 4C 46";
        sect["Priority"]     = 1;
        sect["Description"]  = "Executable and Linkable Format (for UNIX systems)";
        sect["OpCodes.Mask"] = (uint32) GView::Dissasembly::Opcodes::All;
    }
}
