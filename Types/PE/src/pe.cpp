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

GVIEW_PLUGIN_ENTRY_POINTS {
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

// The known starts of functions: the deep scan of the disassembly labels them even when nothing calls them directly
void AddDissasmFunctionEntries(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    if (pe->dirs == nullptr)
        return;

    // exports (a forwarded export points to a "dll.function" text inside the export directory, not to code)
    const auto& exportDir = pe->GetDirectory(PE::DirectoryType::Export);
    for (const auto& item : pe->exp) {
        if (item.RVA >= exportDir.VirtualAddress && item.RVA < static_cast<uint64>(exportDir.VirtualAddress) + exportDir.Size)
            continue;
        const auto fa = pe->RVAToFA(item.RVA);
        if (fa != PE_INVALID_ADDRESS)
            settings.AddFunctionEntry(fa, item.Name, DissasmViewer::FunctionEntryType::Export);
    }

    // ARM64 exception data (.pdata): 8 bytes entries, the start of a function and its unwind data: packed (the function length in its bits
    // 2..12, in instructions) or the RVA of its .xdata record (the function length in the bits 0..17 of its first word)
    if (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine) == PE::MachineType::ARM64) {
        struct Arm64RuntimeFunction {
            uint32 BeginAddress;
            uint32 UnwindData;
        };
        constexpr uint32 MAX_RUNTIME_FUNCTIONS = 0x100000;
        const auto& exceptionDir               = pe->GetDirectory(PE::DirectoryType::Exception);
        const auto start                       = exceptionDir.VirtualAddress != 0 ? pe->RVAToFA(exceptionDir.VirtualAddress) : PE_INVALID_ADDRESS;
        const uint32 count = start != PE_INVALID_ADDRESS ? std::min<uint32>(exceptionDir.Size / sizeof(Arm64RuntimeFunction), MAX_RUNTIME_FUNCTIONS) : 0;
        for (uint32 index = 0; index < count; index++) {
            Arm64RuntimeFunction function;
            if (!data.Copy<Arm64RuntimeFunction>(start + static_cast<uint64>(index) * sizeof(Arm64RuntimeFunction), function))
                break;
            if (function.BeginAddress == 0)
                continue;
            uint64 length    = 0;
            const uint32 flag = function.UnwindData & 3;
            if (flag == 1 || flag == 2) // packed unwind data
                length = static_cast<uint64>((function.UnwindData >> 2) & 0x7FF) * 4;
            else if (flag == 0) {
                uint32 header       = 0;
                const auto xdataFa = pe->RVAToFA(function.UnwindData);
                if (xdataFa != PE_INVALID_ADDRESS && data.Copy<uint32>(xdataFa, header))
                    length = static_cast<uint64>(header & 0x3FFFF) * 4;
            } else
                continue; // 3: a reserved form
            const auto fa = pe->RVAToFA(function.BeginAddress);
            if (fa != PE_INVALID_ADDRESS)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::ExceptionData, length);
        }
    }
    // x64 exception data (.pdata): a RUNTIME_FUNCTION for nearly every function that is not a leaf, with its size
    else if (pe->hdr64) {
        struct RuntimeFunction {
            uint32 BeginAddress;
            uint32 EndAddress;
            uint32 UnwindInfoAddress;
        };
        constexpr uint32 MAX_RUNTIME_FUNCTIONS = 0x100000;
        constexpr uint8 UNW_FLAG_CHAININFO     = 0x4;
        const auto& exceptionDir               = pe->GetDirectory(PE::DirectoryType::Exception);
        const auto start                       = exceptionDir.VirtualAddress != 0 ? pe->RVAToFA(exceptionDir.VirtualAddress) : PE_INVALID_ADDRESS;
        const uint32 count = start != PE_INVALID_ADDRESS ? std::min<uint32>(exceptionDir.Size / sizeof(RuntimeFunction), MAX_RUNTIME_FUNCTIONS) : 0;
        for (uint32 index = 0; index < count; index++) {
            RuntimeFunction function;
            if (!data.Copy<RuntimeFunction>(start + static_cast<uint64>(index) * sizeof(RuntimeFunction), function))
                break;
            if (function.BeginAddress == 0 || function.EndAddress <= function.BeginAddress)
                continue;
            // a chained entry (or an indirect one, odd unwind address) is a part of the function of another entry, not a function start
            if (function.UnwindInfoAddress & 1)
                continue;
            uint8 versionAndFlags = 0;
            const auto unwindInfo = pe->RVAToFA(function.UnwindInfoAddress);
            if (unwindInfo != PE_INVALID_ADDRESS && data.Copy<uint8>(unwindInfo, versionAndFlags) && ((versionAndFlags >> 3) & UNW_FLAG_CHAININFO))
                continue;
            const auto fa = pe->RVAToFA(function.BeginAddress);
            if (fa != PE_INVALID_ADDRESS)
                settings.AddFunctionEntry(fa, {}, DissasmViewer::FunctionEntryType::ExceptionData, function.EndAddress - function.BeginAddress);
        }
    }

    // TLS callbacks: run before the entry point (IDA names them TlsCallback_N); the directory fields are 64 bit for PE32+
    const auto& tlsDir = pe->GetDirectory(PE::DirectoryType::TLS);
    const auto tlsFa   = (tlsDir.VirtualAddress != 0 && tlsDir.Size != 0) ? pe->RVAToFA(tlsDir.VirtualAddress) : PE_INVALID_ADDRESS;
    if (tlsFa == PE_INVALID_ADDRESS)
        return;
    const uint32 pointerSize = pe->hdr64 ? 8 : 4;
    auto readPointer         = [&data, pointerSize](uint64 offset, uint64& value) {
        if (pointerSize == 8)
            return data.Copy<uint64>(offset, value);
        uint32 value32 = 0;
        const bool ok  = data.Copy<uint32>(offset, value32);
        value          = value32;
        return ok;
    };
    uint64 callbacksVA = 0;
    if (!readPointer(tlsFa + 3ull * pointerSize, callbacksVA) || callbacksVA == 0) // StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex
        return;
    const auto callbacks = pe->VAtoFA(callbacksVA);
    if (callbacks == PE_INVALID_ADDRESS)
        return;
    constexpr uint32 MAX_TLS_CALLBACKS = 64;
    LocalString<32> name;
    for (uint32 index = 0; index < MAX_TLS_CALLBACKS; index++) {
        uint64 callbackVA = 0;
        if (!readPointer(callbacks + static_cast<uint64>(index) * pointerSize, callbackVA) || callbackVA == 0)
            break;
        const auto fa = pe->VAtoFA(callbackVA);
        if (fa != PE_INVALID_ADDRESS && name.SetFormat("TlsCallback_%u", index))
            settings.AddFunctionEntry(fa, name.ToStringView(), DissasmViewer::FunctionEntryType::TlsCallback);
    }
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
                if (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine) == PE::MachineType::ARM64)
                    language = DissasmViewer::DisassemblyLanguage::ARM64;

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
    AddDissasmFunctionEntries(settings, pe, win->GetObject()->GetData());

    win->CreateViewer(settings);
}

PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    auto pe = win->GetObject()->GetContentType<PE::PEFile>();
    pe->Update();

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
        sect[buffer.GetText()] = command.DefaultKey;
    }
}
}
