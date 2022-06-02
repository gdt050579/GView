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

        win->CreateViewer("BufferView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto elf = win->GetObject()->GetContentType<ELF::ELFFile>();
        elf->Update();

        // add viewer
        CreateBufferView(win, elf);

        // add panels
        win->AddPanel(Pointer<TabPage>(new ELF::Panels::Information(win->GetObject(), elf)), true);
        win->AddPanel(Pointer<TabPage>(new ELF::Panels::Segments(elf, win)), false);
        win->AddPanel(Pointer<TabPage>(new ELF::Panels::Sections(elf, win)), false);

        return true;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["Pattern"]  = "hex:'7F 45 4C 46'";
        sect["Priority"] = 1;
    }
}
