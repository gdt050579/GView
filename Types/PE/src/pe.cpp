#include "pe.hpp"

using namespace AppCUI;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

constexpr auto OVERLAY_BOOKMARK_VALUE = 0;

extern "C" {
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

    if (pe->hasOverlay) {
        settings.AddBookmark(OVERLAY_BOOKMARK_VALUE, pe->computedSize);
    }

    // sections
    for (uint32 tr = 0; tr < pe->nrSections; tr++) {
        if ((pe->sect[tr].PointerToRawData != 0) && (pe->sect[tr].SizeOfRawData > 0)) {
            pe->CopySectionName(tr, tempStr);
            settings.AddZone(pe->sect[tr].PointerToRawData, pe->sect[tr].SizeOfRawData, pe->peCols.colSect, tempStr);
            if (tr < 9)
                settings.AddBookmark(tr + 1, pe->sect[tr].PointerToRawData);
        }
    }

    // directories
    auto* dr = pe->dirs;
    for (auto tr = 0; tr < 15; tr++, dr++) {
        if ((dr->VirtualAddress > 0) && (dr->Size > 0)) {
            if (tr == (uint8) PE::DirectoryType::Security) {
                settings.AddZone(dr->VirtualAddress, dr->Size, pe->peCols.colDir[tr], PE::PEFile::DirectoryIDToName(tr));
            } else {
                const auto FA = pe->RVAToFA(dr->VirtualAddress);
                if (FA != PE_INVALID_ADDRESS) {
                    settings.AddZone(FA, dr->Size, pe->peCols.colDir[tr], PE::PEFile::DirectoryIDToName(tr));
                }
            }
        }
    }

    // translation
    settings.SetOffsetTranslationList({ "RVA", "VA" }, pe.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

    // set specific color for opcodes
    switch (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine)) {
    case PE::MachineType::I386:
    case PE::MachineType::IA64:
    case PE::MachineType::AMD64: {
        settings.SetPositionToColorCallback(pe.ToBase<GView::View::BufferViewer::PositionToColorInterface>());
    } break;
    };

    // set entry point
    const uint32 addressOfEntryPoint = pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint;
    settings.SetEntryPointOffset(pe->RVAToFA(addressOfEntryPoint));

    const uint32 pointerToSymbolTable = pe->hdr64 ? pe->nth64.FileHeader.PointerToSymbolTable : pe->nth32.FileHeader.PointerToSymbolTable;
    if (pointerToSymbolTable > 0) {
        const uint64 numberOfSymbols = (uint64) (pe->hdr64 ? pe->nth64.FileHeader.NumberOfSymbols : pe->nth32.FileHeader.NumberOfSymbols);
        settings.AddZone(pointerToSymbolTable, numberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL, pe->peCols.colSectDef, "SymbolTable");

        const auto stringsTableOffset = pointerToSymbolTable + numberOfSymbols * PE::IMAGE_SIZEOF_SYMBOL;
        uint32 stringsTableSize       = 0;
        pe->obj->GetData().Copy(stringsTableOffset, stringsTableSize);

        settings.AddZone(stringsTableOffset, stringsTableSize, pe->peCols.colPE, "StringsTable");
    }

    switch (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine)) {
    case PE::MachineType::I386:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x86);
        settings.SetDesign(GView::Dissasembly::Design::Intel);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
        break;
    case PE::MachineType::IA64:
    case PE::MachineType::AMD64:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x64);
        settings.SetDesign(GView::Dissasembly::Design::Intel);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
        break;
    case PE::MachineType::ARM:
    case PE::MachineType::ARMNT:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x86);
        settings.SetDesign(GView::Dissasembly::Design::ARM);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
        break;
    case PE::MachineType::ARM64:
        settings.SetArchitecture(GView::Dissasembly::Architecture::x64);
        settings.SetDesign(GView::Dissasembly::Design::ARM);
        settings.SetEndianess(GView::Dissasembly::Endianess::Little);
    default:
        break;
    }

    pe->selectionZoneInterface = win->GetSelectionZoneInterfaceFromViewerCreation(settings);
}

void CreateDissasmView(Reference<GView::View::WindowInterface> win, Reference<PE::PEFile> pe)
{
    DissasmViewer::Settings settings;

    if (pe->HasPanel(PE::Panels::IDs::Sections)) {
        LocalString<128> temp;

        for (auto tr = 0U; tr < pe->nrSections; tr++) {
            pe->CopySectionName(tr, temp);
            if (temp.CompareWith(".text") == 0) {
                uint64 entryPoint = pe->hdr64 ? pe->nth64.OptionalHeader.AddressOfEntryPoint : pe->nth32.OptionalHeader.AddressOfEntryPoint;
                entryPoint        = pe->RVAToFA(entryPoint);

                DissasmViewer::DisassemblyLanguage language = pe->hdr64 ? DissasmViewer::DisassemblyLanguage::x64 : DissasmViewer::DisassemblyLanguage::x86;

                settings.AddDisassemblyZone(pe->sect[tr].PointerToRawData, pe->sect[tr].SizeOfRawData, entryPoint, language);
                break;
            }
        }
    }

    // translation
    settings.SetOffsetTranslationList({ "RVA", "VA" }, pe.ToBase<GView::View::BufferViewer::OffsetTranslateInterface>());

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

    // LocalString<128> processedName;

    for (const auto& [RVA, dllIndex, Name] : pe->impFunc) {
        // processedName.SetFormat("%s:%s", pe->impDLL[dllIndex].Name.GetText(), Name.GetText());
        settings.AddMemoryMapping(RVA, Name, DissasmViewer::MemoryMappingType::FunctionMapping);
    }

    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    auto pe = win->GetObject()->GetContentType<PE::PEFile>();
    pe->Update();

    GView::View::YaraViewer::Settings settings;
    settings.SetAnalysisLevel(3);
    win->CreateViewer(settings);

#ifdef DISSASM_DEV
    CreateDissasmView(win, pe);
    CreateBufferView(win, pe);
#else
    CreateBufferView(win, pe);
    CreateDissasmView(win, pe);
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
    if (pe->HasPanel(PE::Panels::IDs::GoInformation)) {
        win->AddPanel(Pointer<TabPage>(new PE::Panels::GoInformation(win->GetObject(), pe)), true);
        win->AddPanel(Pointer<TabPage>(new PE::Panels::GoFiles(win->GetObject(), pe)), true);
        win->AddPanel(Pointer<TabPage>(new PE::Panels::GoFunctions(pe, win)), false);
    }
    if (pe->HasPanel(PE::Panels::IDs::OpCodes)) {
        win->AddPanel(Pointer<TabPage>(new PE::Panels::OpCodes(win->GetObject(), pe)), true);
    }

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Pattern"]                  = "magic:4D 5A";
    sect["Priority"]                 = 1;
    sect["Description"]              = "Portable executable format for Windows OS binaries";
    sect["OpCodes.Mask"]             = (uint32) GView::Dissasembly::Opcodes::All;

    LocalString<128> buffer;
    for (const auto& command : PE::PE_COMMANDS) {

        buffer.SetFormat("Command.%s", command.Caption);
        sect[buffer.GetText()] = command.Key;
    }
}
}

int main()
{
    return 0;
}
