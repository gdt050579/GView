#include "pe.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

constexpr auto OVERLAY_BOOKMARK_VALUE = 0;

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

    PLUGIN_EXPORT TypeInterface* CreateInstance()
    {
        return new PE::PEFile();
    }

    void CreateBufferView(Reference<GView::View::WindowInterface> win, Reference<PE::PEFile> pe)
    {
        LocalString<128> tempStr;
        BufferViewer::Settings settings;

        settings.AddZone(0, sizeof(pe->dos), pe->peCols.colMZ, "DOS Header");
        settings.AddZone(pe->dos.e_lfanew, sizeof(pe->nth32), pe->peCols.colPE, "NT Header");
        if (pe->nrSections > 0)
            settings.AddZone(pe->sectStart, pe->nrSections * sizeof(PE::ImageSectionHeader), pe->peCols.colSectDef, "SectDef");

        if (pe->hasOverlay)
        {
            settings.AddBookmark(OVERLAY_BOOKMARK_VALUE, pe->computedSize);
        }

        // sections
        for (uint32 tr = 0; tr < pe->nrSections; tr++)
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
                if (tr == (uint8) PE::DirectoryType::Security)
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
        settings.SetOffsetTranslationList({ "RVA", "VirtAddress" }, pe.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

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
        if (pe->hdr64)
            settings.SetEntryPointOffset(pe->RVAtoFilePointer(pe->nth64.OptionalHeader.AddressOfEntryPoint));
        else
            settings.SetEntryPointOffset(pe->RVAtoFilePointer(pe->nth32.OptionalHeader.AddressOfEntryPoint));

        if (pe->hdr64)
        {
            if (pe->nth64.FileHeader.PointerToSymbolTable > 0)
            {
                settings.AddZone(
                      pe->nth64.FileHeader.PointerToSymbolTable,
                      (uint64) pe->nth64.FileHeader.NumberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL,
                      pe->peCols.colSectDef,
                      "SymbolTable");

                const auto strTableOffset =
                      pe->nth64.FileHeader.PointerToSymbolTable + (uint64) pe->nth64.FileHeader.NumberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL;

                uint32 strTableSize = 0;
                pe->obj->GetData().Copy(strTableOffset, strTableSize);

                settings.AddZone(strTableOffset, strTableSize, pe->peCols.colPE, "StringsTable");
            }
        }
        else
        {
            if (pe->nth32.FileHeader.PointerToSymbolTable > 0)
            {
                settings.AddZone(
                      pe->nth32.FileHeader.PointerToSymbolTable,
                      (uint64) pe->nth32.FileHeader.NumberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL,
                      pe->peCols.colSectDef,
                      "SymbolTable");

                const auto strTableOffset =
                      pe->nth32.FileHeader.PointerToSymbolTable + (uint64) pe->nth32.FileHeader.NumberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL;

                uint32 strTableSize = 0;
                pe->obj->GetData().Copy(strTableOffset, strTableSize);

                settings.AddZone(strTableOffset, strTableSize, pe->peCols.colPE, "StringsTable");
            }
        }

        win->CreateViewer("BufferView", settings);
    }

    void CreateDissasmView(Reference<GView::View::WindowInterface> win, Reference<PE::PEFile> pe)
    {
        DissasmViewer::Settings settings;

        if (pe->HasPanel(PE::Panels::IDs::Sections))
        {
            LocalString<128> temp;

            for (auto tr = 0U; tr < pe->nrSections; tr++)
            {
                pe->CopySectionName(tr, temp);
                if (temp.CompareWith(".text") == 0)
                {
                    const uint32 entryPoint =
                          pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint;

                    settings.AddDisassemblyZone(pe->sect[tr].PointerToRawData, entryPoint, pe->sect[tr].SizeOfRawData);
                    break;
                }
            }
        }

        uint32 typeImageDOSHeader = settings.AddType(
              "ImageDOSHeader",
              R"(UInt16 e_magic;
UInt16 e_cblp;
UInt16 e_cp;
UInt16 e_crlc;
UInt16 e_res[4];)");

        //                uint32 typeImageDOSHeader = settings.AddType(
        //              "ImageDOSHeader",
        //              R"(UInt16 e_magic;
        // UInt16 e_cblp;
        // UInt16 e_cp;
        // UInt16 e_crlc;
        // UInt16 e_cparhdr;
        // UInt16 e_minalloc;
        // UInt16 e_maxalloc;
        // UInt16 e_ss;
        // UInt16 e_sp;
        // UInt16 e_csum;
        // UInt16 e_ip;
        // UInt16 e_cs;
        // UInt16 e_lfarlc;
        // UInt16 e_ovno;
        // UInt16 e_res[4];
        // UInt16 e_oemid;
        // UInt16 e_oeminfo;
        // UInt16 e_res2[10];
        // UInt32 e_lfanew;)");

        settings.AddVariable(0, "ImageDOSHeader", typeImageDOSHeader);
        settings.AddVariable(543, "ImageDOSHeader", typeImageDOSHeader);

        win->CreateViewer("DissasmView", settings);
    }

    PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
    {
        auto pe = win->GetObject()->GetContentType<PE::PEFile>();
        pe->Update();

#ifndef DISSASM_DEV
        CreateBufferView(win, pe);
        CreateDissasmView(win, pe);
#else
        CreateDissasmView(win, pe);
        CreateBufferView(win, pe);
#endif

        if (pe->HasPanel(PE::Panels::IDs::Information))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Information(win->GetObject(), pe)), true);
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
        if (pe->HasPanel(PE::Panels::IDs::Symbols))
            win->AddPanel(Pointer<TabPage>(new PE::Panels::Symbols(pe, win)), false);
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
