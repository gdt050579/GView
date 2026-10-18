#include "pe.hpp"

#include <set>

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

    // ARM64 / ARM (Thumb-2) exception data (.pdata): 8 bytes entries, the start of a function and its unwind data: packed (the function
    // length in its bits 2..12) or the RVA of its .xdata record (the function length in the bits 0..17 of its first word); the length is in
    // 4 bytes units for ARM64, in 2 bytes units for ARM, whose function starts have the Thumb bit
    const auto machine = static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine);
    if (machine == PE::MachineType::ARM64 || machine == PE::MachineType::ARMNT) {
        const uint64 lengthUnit = machine == PE::MachineType::ARM64 ? 4 : 2;
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
            if ((function.BeginAddress & ~1u) == 0)
                continue;
            uint64 length    = 0;
            const uint32 flag = function.UnwindData & 3;
            if (flag == 1 || flag == 2) // packed unwind data
                length = static_cast<uint64>((function.UnwindData >> 2) & 0x7FF) * lengthUnit;
            else if (flag == 0) {
                uint32 header       = 0;
                const auto xdataFa = pe->RVAToFA(function.UnwindData);
                if (xdataFa != PE_INVALID_ADDRESS && data.Copy<uint32>(xdataFa, header))
                    length = static_cast<uint64>(header & 0x3FFFF) * lengthUnit;
            } else
                continue; // 3: a reserved form
            const auto fa = pe->RVAToFA(function.BeginAddress & ~1u);
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

// a pointer of the image (4 or 8 bytes) at a file offset
static bool ReadImagePointer(GView::Utils::DataCache& data, uint64 offset, bool is64, uint64& value)
{
    if (is64)
        return data.Copy<uint64>(offset, value);
    uint32 value32 = 0;
    const bool ok  = data.Copy<uint32>(offset, value32);
    value          = value32;
    return ok;
}

// The delay loaded imports (IMAGE_DELAYLOAD_DESCRIPTOR): the code calls them through their own IAT (call [__imp_Name]), whose slots hold
// the address of a load thunk until the first call (__imp_load_Name: lea rax, [__imp_Name]; jmp __tailMerge_dll). The slots are named
// like the imports, the load thunks and the __tailMerge_ helpers of every DLL are functions (IDA names).
void AddDissasmDelayImports(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    struct DelayLoadDescriptor {
        uint32 Attributes; // bit 0: the fields are RVAs (VC 6 used VAs)
        uint32 DllNameRVA;
        uint32 ModuleHandleRVA;
        uint32 ImportAddressTableRVA;
        uint32 ImportNameTableRVA;
        uint32 BoundImportAddressTableRVA;
        uint32 UnloadInformationTableRVA;
        uint32 TimeDateStamp;
    };
    constexpr uint32 MAX_DELAY_DLLS      = 1024;
    constexpr uint32 MAX_DELAY_FUNCTIONS = 0x10000;
    constexpr uint32 MAX_NAME_SIZE       = 512;
    const auto& directory                = pe->GetDirectory(PE::DirectoryType::DelayImport);
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(DelayLoadDescriptor))
        return;
    const auto start = pe->RVAToFA(directory.VirtualAddress);
    if (start == PE_INVALID_ADDRESS)
        return;
    const bool is64           = pe->hdr64;
    const uint32 pointerSize  = is64 ? 8 : 4;
    const uint64 ordinalFlag  = is64 ? 0x8000000000000000ull : 0x80000000ull;
    const auto machine        = static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine);
    const bool isX86          = machine != PE::MachineType::ARM64 && machine != PE::MachineType::ARMNT;
    std::set<uint64> namedFunctions; // the file offsets of the thunks / helpers already named
    LocalString<128> text;
    String demangled;

    for (uint32 dll = 0; dll < MAX_DELAY_DLLS; dll++) {
        DelayLoadDescriptor descriptor{};
        if (!data.Copy<DelayLoadDescriptor>(start + static_cast<uint64>(dll) * sizeof(DelayLoadDescriptor), descriptor) || descriptor.DllNameRVA == 0)
            break;
        // VC 6: the fields are VAs (32 bit images)
        const uint64 fieldBase = (descriptor.Attributes & 1) ? 0 : pe->imageBase;
        const auto toRVA       = [fieldBase](uint32 value) -> uint64 { return value >= fieldBase ? value - fieldBase : 0; };
        const uint64 iat       = toRVA(descriptor.ImportAddressTableRVA);
        const uint64 names     = toRVA(descriptor.ImportNameTableRVA);
        const auto namesFa     = names != 0 ? pe->RVAToFA(names) : PE_INVALID_ADDRESS;
        if (iat == 0 || namesFa == PE_INVALID_ADDRESS)
            continue;
        // __tailMerge_ + the name of the DLL ('.' and '-' become '_'): certenroll.dll -> __tailMerge_certenroll_dll
        const auto dllName        = pe->ReadString(static_cast<uint32>(toRVA(descriptor.DllNameRVA)), MAX_NAME_SIZE);
        std::string tailMergeName = "__tailMerge_";
        for (const char c : dllName)
            tailMergeName.push_back(c == '.' || c == '-' ? '_' : c);
        // the thunks of the imports by ordinal: __imp_load_certenroll_Ordinal_42 (the ordinals of two DLLs are not the same functions)
        std::string ordinalPrefix = "__imp_load_";
        for (const char c : dllName.substr(0, std::min(dllName.size(), dllName.rfind('.'))))
            ordinalPrefix.push_back(c == '-' ? '_' : c);
        ordinalPrefix += "_Ordinal_";

        for (uint32 index = 0; index < MAX_DELAY_FUNCTIONS; index++) {
            uint64 nameEntry = 0;
            if (!ReadImagePointer(data, namesFa + static_cast<uint64>(index) * pointerSize, is64, nameEntry) || nameEntry == 0)
                break;
            const uint64 slot = iat + static_cast<uint64>(index) * pointerSize;
            std::string rawName;
            if (nameEntry & ordinalFlag) {
                text.SetFormat("Ordinal:%u", static_cast<uint32>(nameEntry & 0xFFFF));
                rawName = text.GetText();
            } else
                rawName = std::string(pe->ReadString(static_cast<uint32>(toRVA(static_cast<uint32>(nameEntry)) + 2), MAX_NAME_SIZE)); // after the hint
            if (rawName.empty())
                continue;
            // the slot, named like a regular import (demangled C++ names)
            if (GView::Utils::Demangle(rawName.c_str(), demangled))
                settings.AddMemoryMapping(slot, demangled.GetText(), DissasmViewer::MemoryMappingType::FunctionMapping);
            else
                settings.AddMemoryMapping(slot, rawName, DissasmViewer::MemoryMappingType::FunctionMapping);

            // the load thunk: the first value of the slot
            const auto slotFa = pe->RVAToFA(slot);
            uint64 thunkVA    = 0;
            if (slotFa == PE_INVALID_ADDRESS || !ReadImagePointer(data, slotFa, is64, thunkVA) || thunkVA < pe->imageBase)
                continue;
            const auto thunkFa = pe->RVAToFA(thunkVA - pe->imageBase);
            if (thunkFa == PE_INVALID_ADDRESS || !namedFunctions.insert(thunkFa).second)
                continue;
            const std::string thunkName = (nameEntry & ordinalFlag) ? ordinalPrefix + std::to_string(nameEntry & 0xFFFF) : "__imp_load_" + rawName;
            settings.AddFunctionEntry(thunkFa, thunkName, DissasmViewer::FunctionEntryType::Symbol);

            // the helper the thunk jumps to: x64 lea rax, [rip + slot]; jmp rel32 - x86 mov eax, slot; jmp rel32
            if (!isX86)
                continue;
            uint8 code[12]{};
            const uint32 codeSize = is64 ? 12 : 10;
            bool readCode         = true;
            for (uint32 byte = 0; byte < codeSize && readCode; byte++)
                readCode = data.Copy<uint8>(thunkFa + byte, code[byte]);
            if (!readCode)
                continue;
            const auto dword = [&code](uint32 at) {
                return static_cast<uint32>(code[at]) | (static_cast<uint32>(code[at + 1]) << 8) | (static_cast<uint32>(code[at + 2]) << 16) |
                       (static_cast<uint32>(code[at + 3]) << 24);
            };
            uint64 tailMergeVA = 0;
            if (is64 && code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x05 && code[7] == 0xE9 &&
                thunkVA + 7 + static_cast<int64>(static_cast<int32>(dword(3))) == pe->imageBase + slot)
                tailMergeVA = thunkVA + 12 + static_cast<int64>(static_cast<int32>(dword(8)));
            else if (!is64 && code[0] == 0xB8 && code[5] == 0xE9 && dword(1) == pe->imageBase + slot)
                tailMergeVA = (thunkVA + 10 + static_cast<int64>(static_cast<int32>(dword(6)))) & 0xFFFFFFFFull;
            if (tailMergeVA < pe->imageBase)
                continue;
            const auto tailMergeFa = pe->RVAToFA(tailMergeVA - pe->imageBase);
            if (tailMergeFa != PE_INVALID_ADDRESS && namedFunctions.insert(tailMergeFa).second)
                settings.AddFunctionEntry(tailMergeFa, tailMergeName, DissasmViewer::FunctionEntryType::Symbol);
        }
    }
}

// The pointers of the Control Flow Guard (load config directory): every indirect call of a CFG image goes through them
// (call [__guard_dispatch_icall_fptr]), named like IDA
void AddDissasmGuardPointers(DissasmViewer::Settings& settings, Reference<PE::PEFile> pe, GView::Utils::DataCache& data)
{
    const auto& directory = pe->GetDirectory(PE::DirectoryType::Config);
    const auto start      = directory.VirtualAddress != 0 ? pe->RVAToFA(directory.VirtualAddress) : PE_INVALID_ADDRESS;
    uint32 size           = 0; // the first field: the size of the structure (it grows with the Windows versions)
    if (start == PE_INVALID_ADDRESS || !data.Copy<uint32>(start, size))
        return;
    const bool is64 = pe->hdr64;
    struct GuardPointer {
        uint32 offset32, offset64;
        std::string_view name;
    };
    constexpr GuardPointer pointers[] = {
        { 72, 112, "__guard_check_icall_fptr" },
        { 76, 120, "__guard_dispatch_icall_fptr" },
        { 172, 280, "__guard_xfg_check_icall_fptr" },
        { 176, 288, "__guard_xfg_dispatch_icall_fptr" },
        { 180, 296, "__guard_xfg_table_dispatch_icall_fptr" },
    };
    for (const auto& pointer : pointers) {
        const uint32 offset = is64 ? pointer.offset64 : pointer.offset32;
        uint64 va           = 0;
        if (offset + (is64 ? 8u : 4u) > size || !ReadImagePointer(data, start + offset, is64, va) || va <= pe->imageBase)
            continue;
        settings.AddMemoryMapping(va - pe->imageBase, pointer.name, DissasmViewer::MemoryMappingType::FunctionMapping);
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
                else if (static_cast<PE::MachineType>(pe->nth32.FileHeader.Machine) == PE::MachineType::ARMNT) {
                    language   = DissasmViewer::DisassemblyLanguage::Thumb; // Windows on ARM 32: Thumb-2 only
                    entryPoint = pe->RVAToFA(pe->nth32.OptionalHeader.AddressOfEntryPoint & ~1u);
                }

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
    AddDissasmDelayImports(settings, pe, win->GetObject()->GetData());
    AddDissasmGuardPointers(settings, pe, win->GetObject()->GetData());

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
