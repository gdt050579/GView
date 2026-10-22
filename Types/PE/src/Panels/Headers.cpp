#include "pe.hpp"

using namespace GView::Type::PE;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr uint32 PE_HEADERS_GOTO = 1;

static constexpr std::pair<uint32, std::string_view> fileCharacteristics[] = {
    { __IMAGE_FILE_RELOCS_STRIPPED, "Relocations stripped" },
    { __IMAGE_FILE_EXECUTABLE_IMAGE, "Executable image" },
    { __IMAGE_FILE_LINE_NUMS_STRIPPED, "Line numbers stripped" },
    { __IMAGE_FILE_LOCAL_SYMS_STRIPPED, "Local symbols stripped" },
    { __IMAGE_FILE_AGGRESIVE_WS_TRIM, "Aggressive working set trim" },
    { __IMAGE_FILE_LARGE_ADDRESS_AWARE, "Large address aware" },
    { __IMAGE_FILE_BYTES_REVERSED_LO, "Bytes reversed (low)" },
    { __IMAGE_FILE_32BIT_MACHINE, "32 bit machine" },
    { __IMAGE_FILE_DEBUG_STRIPPED, "Debug info stripped" },
    { __IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "Removable run from swap" },
    { __IMAGE_FILE_NET_RUN_FROM_SWAP, "Net run from swap" },
    { __IMAGE_FILE_SYSTEM, "System file" },
    { __IMAGE_FILE_DLL, "DLL" },
    { __IMAGE_FILE_UP_SYSTEM_ONLY, "Uniprocessor only" },
    { __IMAGE_FILE_BYTES_REVERSED_HI, "Bytes reversed (high)" },
};

static constexpr std::pair<uint32, std::string_view> dllCharacteristics[] = {
    { __IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "High entropy VA" },
    { __IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "Dynamic base (ASLR)" },
    { __IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "Force integrity" },
    { __IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "NX compatible (DEP)" },
    { __IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "No isolation" },
    { __IMAGE_DLLCHARACTERISTICS_NO_SEH, "No SEH" },
    { __IMAGE_DLLCHARACTERISTICS_NO_BIND, "No bind" },
    { __IMAGE_DLLCHARACTERISTICS_APPCONTAINER, "AppContainer" },
    { __IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM driver" },
    { __IMAGE_DLLCHARACTERISTICS_GUARD_CF, "Control Flow Guard" },
    { __IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "Terminal server aware" },
};

static constexpr std::pair<uint32, std::string_view> sectionCharacteristics[] = {
    { 0x00000008, "No padding" },
    { __IMAGE_SCN_CNT_CODE, "Code" },
    { __IMAGE_SCN_CNT_INITIALIZED_DATA, "Initialized data" },
    { __IMAGE_SCN_CNT_UNINITIALIZED_DATA, "Uninitialized data" },
    { 0x00000100, "Link other" },
    { 0x00000200, "Link info" },
    { 0x00000800, "Link remove" },
    { 0x00001000, "COMDAT" },
    { 0x00004000, "No defer spec exceptions" },
    { 0x00008000, "GP relative" },
    { 0x00020000, "Purgeable / 16 bit" },
    { 0x00040000, "Locked" },
    { 0x00080000, "Preload" },
    { 0x01000000, "Extended relocations" },
    { 0x02000000, "Discardable" },
    { 0x04000000, "Not cached" },
    { 0x08000000, "Not paged" },
    { __IMAGE_SCN_MEM_SHARED, "Shared" },
    { __IMAGE_SCN_MEM_EXECUTE, "Execute" },
    { __IMAGE_SCN_MEM_READ, "Read" },
    { __IMAGE_SCN_MEM_WRITE, "Write" },
};

Panels::Headers::Headers(Reference<GView::Type::PE::PEFile> _pe, Reference<GView::View::WindowInterface> _win) : TabPage("&Headers")
{
    pe  = _pe;
    win = _win;

    list = Factory::ListView::Create(this, "d:c", { "n:Field,w:33", "n:Value,w:60" }, ListViewFlags::None);

    Update();
}
ListViewItem Panels::Headers::AddHeader(std::string_view name, uint64 fileOffset)
{
    auto item = list->AddItem(name);
    item.SetType(ListViewItem::Type::Category);
    item.SetData(fileOffset);
    return item;
}
ListViewItem Panels::Headers::AddNumber(std::string_view name, uint64 value, uint64 fileOffset)
{
    LocalString<128> temp;
    return AddItem(name, temp.Format("0x%llX (Dec:%llu)", value, value), fileOffset);
}
ListViewItem Panels::Headers::AddItem(std::string_view name, std::string_view value, uint64 fileOffset)
{
    auto item = list->AddItem({ name, value });
    item.SetData(fileOffset);
    return item;
}
ListViewItem Panels::Headers::AddTimeDateStamp(std::string_view name, uint32 value, uint64 fileOffset)
{
    LocalString<128> temp;
    if (value == 0)
        return AddItem(name, "0", fileOffset);
    PEFile::TimeDateStampToString(value, temp);
    return AddItem(name, temp, fileOffset);
}
void Panels::Headers::AddFlags(std::string_view name, uint32 value, const std::pair<uint32, std::string_view>* flags, uint32 count, uint64 fileOffset, uint32 xOffset)
{
    LocalString<64> temp;
    AddItem(name, temp.Format("0x%X", value), fileOffset).SetXOffset(xOffset);

    uint32 known = 0;
    for (uint32 tr = 0; tr < count; tr++) {
        if ((value & flags[tr].first) == flags[tr].first) {
            AddItem(flags[tr].second, temp.Format("0x%X", flags[tr].first), fileOffset).SetXOffset(xOffset + 2);
            known |= flags[tr].first;
        }
    }
    if ((value & ~known) != 0) {
        AddItem("Other flags", temp.Format("0x%X", value & ~known), fileOffset).SetXOffset(xOffset + 2);
    }
}
ListViewItem Panels::Headers::AddMagic(uint8* offset, uint32 size, uint64 fileOffset)
{
    LocalString<128> temp;
    temp.Set("\"");
    for (uint32 tr = 0; tr < size; tr++) {
        if (offset[tr] > 32)
            temp.AddChar(offset[tr]);
        else
            temp.AddChar('.');
    }
    temp.Add("\"  ");
    for (uint32 tr = 0; tr < size; tr++)
        temp.AddFormat("%02X ", offset[tr]);
    return AddItem("Magic", temp, fileOffset);
}

void Panels::Headers::AddDOSHeader()
{
    LocalString<128> temp;
    const auto& dos = pe->dos;

#define DOS_FIELD(field) offsetof(ImageDOSHeader, field)
    AddHeader("DOS Header", 0);
    AddMagic((uint8*) &dos.e_magic, 2, DOS_FIELD(e_magic));
    AddNumber("Bytes on last page of file", dos.e_cblp, DOS_FIELD(e_cblp));
    AddNumber("Pages in file", dos.e_cp, DOS_FIELD(e_cp));
    AddNumber("Relocations", dos.e_crlc, DOS_FIELD(e_crlc));
    AddNumber("Size of header in paragraphs", dos.e_cparhdr, DOS_FIELD(e_cparhdr));
    AddNumber("Minimum extra paragraphs needed", dos.e_minalloc, DOS_FIELD(e_minalloc));
    AddNumber("Maximum extra paragraphs needed", dos.e_maxalloc, DOS_FIELD(e_maxalloc));
    AddNumber("Initial (relative) SS value", dos.e_ss, DOS_FIELD(e_ss));
    AddNumber("Initial SP value", dos.e_sp, DOS_FIELD(e_sp));
    AddNumber("Checksum", dos.e_csum, DOS_FIELD(e_csum));
    AddNumber("Initial IP value", dos.e_ip, DOS_FIELD(e_ip));
    AddNumber("Initial (relative) CS value", dos.e_cs, DOS_FIELD(e_cs));
    AddNumber("File address of relocation table", dos.e_lfarlc, DOS_FIELD(e_lfarlc));
    AddNumber("Overlay number", dos.e_ovno, DOS_FIELD(e_ovno));
    temp.Clear();
    for (auto value : dos.e_res)
        temp.AddFormat("%04X ", value);
    AddItem("Reserved words", temp, DOS_FIELD(e_res));
    AddNumber("OEM identifier", dos.e_oemid, DOS_FIELD(e_oemid));
    AddNumber("OEM information", dos.e_oeminfo, DOS_FIELD(e_oeminfo));
    temp.Clear();
    for (auto value : dos.e_res2)
        temp.AddFormat("%04X ", value);
    AddItem("Reserved words (2)", temp, DOS_FIELD(e_res2));
    AddNumber("PE Header offset", dos.e_lfanew, DOS_FIELD(e_lfanew));
#undef DOS_FIELD

    // the DOS stub program sits between the DOS header and the Rich header (or the PE header)
    const uint64 stubEnd = pe->rich.Present ? pe->rich.Offset : dos.e_lfanew;
    if (stubEnd > sizeof(ImageDOSHeader)) {
        const uint64 stubSize = stubEnd - sizeof(ImageDOSHeader);
        AddItem("DOS Stub", temp.Format("0x%llX - 0x%llX (%llu bytes)", (uint64) sizeof(ImageDOSHeader), stubEnd, stubSize), sizeof(ImageDOSHeader));
    }
}

void Panels::Headers::AddRichHeader()
{
    LocalString<128> temp;
    const auto& rich = pe->rich;

    if (!rich.Present) {
        AddHeader("Rich Header");
        AddItem("Status", "Not present");
        return;
    }

    AddHeader("Rich Header", rich.Offset);
    AddNumber("Offset", rich.Offset, rich.Offset);
    AddNumber("Size", rich.Size, rich.Offset);
    AddItem("XOR Key", temp.Format("0x%08X", rich.Key), rich.Offset + rich.Size - 4);
    if (rich.ComputedChecksum == rich.Key) {
        AddItem("Checksum", temp.Format("0x%08X (valid)", rich.ComputedChecksum), rich.Offset + rich.Size - 4);
    } else {
        AddItem("Checksum", temp.Format("0x%08X (invalid, key is 0x%08X)", rich.ComputedChecksum, rich.Key), rich.Offset + rich.Size - 4)
              .SetType(ListViewItem::Type::ErrorInformation);
    }
    AddNumber("Entries", rich.Entries.size(), rich.Offset + 16);

    uint64 entryOffset = rich.Offset + 16;
    for (const auto& e : rich.Entries) {
        auto name = PEFile::RichProductIDToName(e.ProductID);
        LocalString<32> unknownName;
        if (name.empty())
            name = unknownName.Format("ProdID 0x%04X", e.ProductID);
        AddItem(name, temp.Format("Build: %u, Count: %u (ProdID: 0x%04X)", e.Build, e.Count, e.ProductID), entryOffset).SetXOffset(2);
        entryOffset += 8;
    }
}

void Panels::Headers::AddNTHeaders()
{
    AddHeader("PE Header", pe->peStart);
    AddMagic((uint8*) &pe->nth32.Signature, 4, pe->peStart);
    AddNumber("Offset", pe->peStart, pe->peStart);
}

void Panels::Headers::AddFileHeader()
{
    const auto& fh    = pe->nth32.FileHeader; // same layout for PE32 and PE32+
    const uint64 base = pe->peStart + sizeof(pe->nth32.Signature);
    LocalString<128> temp;

#define FH_FIELD(field) (base + offsetof(ImageFileHeader, field))
    AddHeader("File Header", base);
    AddItem("Machine", temp.Format("%s (0x%04X)", pe->GetMachine().data(), fh.Machine), FH_FIELD(Machine));
    AddNumber("NumberOfSections", fh.NumberOfSections, FH_FIELD(NumberOfSections));
    auto item = AddTimeDateStamp("TimeDateStamp", fh.TimeDateStamp, FH_FIELD(TimeDateStamp));
    if (pe->IsReproducibleBuild())
        item.SetText(1, temp.Format("0x%08X (reproducible build hash)", fh.TimeDateStamp));
    AddNumber("PointerToSymbolTable", fh.PointerToSymbolTable, FH_FIELD(PointerToSymbolTable));
    AddNumber("NumberOfSymbols", fh.NumberOfSymbols, FH_FIELD(NumberOfSymbols));
    AddNumber("SizeOfOptionalHeader", fh.SizeOfOptionalHeader, FH_FIELD(SizeOfOptionalHeader));
    AddFlags("Characteristics", fh.Characteristics, fileCharacteristics, ARRAY_LEN(fileCharacteristics), FH_FIELD(Characteristics));
#undef FH_FIELD
}

void Panels::Headers::AddOptionalHeader()
{
    const uint64 base = pe->peStart + sizeof(pe->nth32.Signature) + sizeof(ImageFileHeader);

    auto addFields = [&](const auto& oh) {
        using T = std::decay_t<decltype(oh)>;
        LocalString<128> temp;

#define OH_FIELD(field) (base + offsetof(T, field))
        AddHeader("Optional Header", base);
        AddItem("Magic", temp.Format("0x%X (%s)", oh.Magic, pe->hdr64 ? "PE32+" : "PE32"), OH_FIELD(Magic));
        AddItem("LinkerVersion", temp.Format("%u.%u", oh.MajorLinkerVersion, oh.MinorLinkerVersion), OH_FIELD(MajorLinkerVersion));
        AddNumber("SizeOfCode", oh.SizeOfCode, OH_FIELD(SizeOfCode));
        AddNumber("SizeOfInitializedData", oh.SizeOfInitializedData, OH_FIELD(SizeOfInitializedData));
        AddNumber("SizeOfUninitializedData", oh.SizeOfUninitializedData, OH_FIELD(SizeOfUninitializedData));
        AddNumber("AddressOfEntryPoint", oh.AddressOfEntryPoint, OH_FIELD(AddressOfEntryPoint));
        AddNumber("BaseOfCode", oh.BaseOfCode, OH_FIELD(BaseOfCode));
        if constexpr (std::is_same_v<T, ImageOptionalHeader32>) {
            AddNumber("BaseOfData", oh.BaseOfData, OH_FIELD(BaseOfData));
        }
        AddNumber("ImageBase", oh.ImageBase, OH_FIELD(ImageBase));
        AddNumber("SectionAlignment", oh.SectionAlignment, OH_FIELD(SectionAlignment));
        AddNumber("FileAlignment", oh.FileAlignment, OH_FIELD(FileAlignment));
        AddItem(
              "OperatingSystemVersion",
              temp.Format("%u.%u", oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion),
              OH_FIELD(MajorOperatingSystemVersion));
        AddItem("ImageVersion", temp.Format("%u.%u", oh.MajorImageVersion, oh.MinorImageVersion), OH_FIELD(MajorImageVersion));
        AddItem("SubsystemVersion", temp.Format("%u.%u", oh.MajorSubsystemVersion, oh.MinorSubsystemVersion), OH_FIELD(MajorSubsystemVersion));
        AddNumber("Win32VersionValue", oh.Win32VersionValue, OH_FIELD(Win32VersionValue));
        AddNumber("SizeOfImage", oh.SizeOfImage, OH_FIELD(SizeOfImage));
        AddNumber("SizeOfHeaders", oh.SizeOfHeaders, OH_FIELD(SizeOfHeaders));
        AddNumber("CheckSum", oh.CheckSum, OH_FIELD(CheckSum));
        AddItem("Subsystem", temp.Format("%s (%u)", pe->GetSubsystem().data(), oh.Subsystem), OH_FIELD(Subsystem));
        AddFlags("DllCharacteristics", oh.DllCharacteristics, dllCharacteristics, ARRAY_LEN(dllCharacteristics), OH_FIELD(DllCharacteristics));
        AddNumber("SizeOfStackReserve", oh.SizeOfStackReserve, OH_FIELD(SizeOfStackReserve));
        AddNumber("SizeOfStackCommit", oh.SizeOfStackCommit, OH_FIELD(SizeOfStackCommit));
        AddNumber("SizeOfHeapReserve", oh.SizeOfHeapReserve, OH_FIELD(SizeOfHeapReserve));
        AddNumber("SizeOfHeapCommit", oh.SizeOfHeapCommit, OH_FIELD(SizeOfHeapCommit));
        AddNumber("LoaderFlags", oh.LoaderFlags, OH_FIELD(LoaderFlags));
        AddNumber("NumberOfRvaAndSizes", oh.NumberOfRvaAndSizes, OH_FIELD(NumberOfRvaAndSizes));
        AddDataDirectories(OH_FIELD(DataDirectory));
#undef OH_FIELD
    };

    if (pe->hdr64)
        addFields(pe->nth64.OptionalHeader);
    else
        addFields(pe->nth32.OptionalHeader);
}

void Panels::Headers::AddDataDirectories(uint64 fileOffset)
{
    LocalString<128> temp;

    AddHeader("Data Directories", fileOffset);
    for (uint32 tr = 0; tr < __IMAGE_NUMBEROF_DIRECTORY_ENTRIES; tr++, fileOffset += sizeof(ImageDataDirectory)) {
        const auto& dir = pe->dirs[tr];
        auto name       = PEFile::DirectoryIDToName(tr);
        if (name.empty())
            name = "Reserved";
        auto item = AddItem(name, temp.Format("RVA: 0x%08X, Size: 0x%X", dir.VirtualAddress, dir.Size), fileOffset);
        if ((dir.VirtualAddress == 0) && (dir.Size == 0))
            item.SetType(ListViewItem::Type::GrayedOut);
    }
}

void Panels::Headers::AddSectionHeaders()
{
    LocalString<128> temp;
    LocalString<16> name;

    AddHeader("Section Headers", pe->sectStart);
    AddNumber("Count", pe->nrSections, pe->sectStart);
    for (uint32 tr = 0; tr < pe->nrSections; tr++) {
        const auto& s     = pe->sect[tr];
        const uint64 base = pe->sectStart + tr * sizeof(ImageSectionHeader);
        pe->CopySectionName(tr, name);

#define SH_FIELD(field) (base + offsetof(ImageSectionHeader, field))
        AddItem(name, temp.Format("#%u", tr + 1), base).SetType(ListViewItem::Type::Emphasized_1);
        AddNumber("VirtualSize", s.Misc.VirtualSize, SH_FIELD(Misc)).SetXOffset(2);
        AddNumber("VirtualAddress", s.VirtualAddress, SH_FIELD(VirtualAddress)).SetXOffset(2);
        AddNumber("SizeOfRawData", s.SizeOfRawData, SH_FIELD(SizeOfRawData)).SetXOffset(2);
        AddNumber("PointerToRawData", s.PointerToRawData, SH_FIELD(PointerToRawData)).SetXOffset(2);
        AddNumber("PointerToRelocations", s.PointerToRelocations, SH_FIELD(PointerToRelocations)).SetXOffset(2);
        AddNumber("PointerToLinenumbers", s.PointerToLinenumbers, SH_FIELD(PointerToLinenumbers)).SetXOffset(2);
        AddNumber("NumberOfRelocations", s.NumberOfRelocations, SH_FIELD(NumberOfRelocations)).SetXOffset(2);
        AddNumber("NumberOfLinenumbers", s.NumberOfLinenumbers, SH_FIELD(NumberOfLinenumbers)).SetXOffset(2);
        AddFlags("Characteristics", s.Characteristics, sectionCharacteristics, ARRAY_LEN(sectionCharacteristics), SH_FIELD(Characteristics), 2);
        const uint32 align = (s.Characteristics >> 20) & 0xF;
        if (align != 0)
            AddItem("Alignment", temp.Format("%u bytes", 1U << (align - 1)), SH_FIELD(Characteristics)).SetXOffset(4);
#undef SH_FIELD
    }
}

void Panels::Headers::AddImportDescriptors()
{
    CHECKRET(pe->impDLL.empty() == false, "");
    LocalString<128> temp;

    std::vector<uint32> functionsCount(pe->impDLL.size(), 0);
    for (const auto& f : pe->impFunc) {
        if (f.dllIndex < functionsCount.size())
            functionsCount[f.dllIndex]++;
    }

    AddHeader("Import Descriptors", pe->impDLL[0].DescriptorFileOffset);
    AddNumber("Count", pe->impDLL.size(), pe->impDLL[0].DescriptorFileOffset);
    for (size_t tr = 0; tr < pe->impDLL.size(); tr++) {
        const auto& dll   = pe->impDLL[tr];
        const auto& d     = dll.Descriptor;
        const uint64 base = dll.DescriptorFileOffset;

#define ID_FIELD(field) (base + offsetof(ImageImportDescriptor, field))
        AddItem(dll.Name, temp.Format("%u function(s)", functionsCount[tr]), base).SetType(ListViewItem::Type::Emphasized_1);
        AddNumber("OriginalFirstThunk", d.OriginalFirstThunk, ID_FIELD(OriginalFirstThunk)).SetXOffset(2);
        if (d.TimeDateStamp == 0xFFFFFFFF)
            AddItem("TimeDateStamp", "0xFFFFFFFF (bound, see Bound Import)", ID_FIELD(TimeDateStamp)).SetXOffset(2);
        else
            AddTimeDateStamp("TimeDateStamp", d.TimeDateStamp, ID_FIELD(TimeDateStamp)).SetXOffset(2);
        AddNumber("ForwarderChain", d.ForwarderChain, ID_FIELD(ForwarderChain)).SetXOffset(2);
        AddNumber("Name", d.Name, ID_FIELD(Name)).SetXOffset(2);
        AddNumber("FirstThunk", d.FirstThunk, ID_FIELD(FirstThunk)).SetXOffset(2);
#undef ID_FIELD
    }
}

void Panels::Headers::AddExportDirectory()
{
    const auto& dir = pe->GetDirectory(DirectoryType::Export);
    CHECKRET((dir.VirtualAddress != 0) && (dir.Size != 0), "");
    const uint64 base = pe->RVAToFA(dir.VirtualAddress);
    CHECKRET(base != PE_INVALID_ADDRESS, "");
    ImageExportDirectory ed{};
    CHECKRET(pe->obj->GetData().Copy<ImageExportDirectory>(base, ed), "");

    LocalString<128> temp;
#define ED_FIELD(field) (base + offsetof(ImageExportDirectory, field))
    AddHeader("Export Directory", base);
    AddNumber("Characteristics", ed.Characteristics, ED_FIELD(Characteristics));
    AddTimeDateStamp("TimeDateStamp", ed.TimeDateStamp, ED_FIELD(TimeDateStamp));
    AddItem("Version", temp.Format("%u.%u", ed.MajorVersion, ed.MinorVersion), ED_FIELD(MajorVersion));
    const auto name = pe->ReadString(ed.Name, MAX_DLL_NAME);
    AddItem("Name", temp.Format("0x%X (%.*s)", ed.Name, (int) name.size(), name.data()), ED_FIELD(Name));
    AddNumber("Base", ed.Base, ED_FIELD(Base));
    AddNumber("NumberOfFunctions", ed.NumberOfFunctions, ED_FIELD(NumberOfFunctions));
    AddNumber("NumberOfNames", ed.NumberOfNames, ED_FIELD(NumberOfNames));
    AddNumber("AddressOfFunctions", ed.AddressOfFunctions, ED_FIELD(AddressOfFunctions));
    AddNumber("AddressOfNames", ed.AddressOfNames, ED_FIELD(AddressOfNames));
    AddNumber("AddressOfNameOrdinals", ed.AddressOfNameOrdinals, ED_FIELD(AddressOfNameOrdinals));
#undef ED_FIELD
}

void Panels::Headers::AddDebugDirectory()
{
    CHECKRET(pe->debugData.empty() == false, "");
    const uint64 start = pe->RVAToFA(pe->GetDirectory(DirectoryType::Debug).VirtualAddress);
    CHECKRET(start != PE_INVALID_ADDRESS, "");

    LocalString<128> temp;
    AddHeader("Debug Directory", start);
    for (size_t tr = 0; tr < pe->debugData.size(); tr++) {
        const auto& d     = pe->debugData[tr];
        const uint64 base = start + tr * sizeof(ImageDebugDirectory);
        auto name         = PEFile::DebugTypeToName(d.Type);
        if (name.empty())
            name = "Type";

#define DD_FIELD(field) (base + offsetof(ImageDebugDirectory, field))
        AddItem(name, temp.Format("Type: %u", d.Type), base).SetType(ListViewItem::Type::Emphasized_1);
        AddNumber("Characteristics", d.Characteristics, DD_FIELD(Characteristics)).SetXOffset(2);
        if (pe->IsReproducibleBuild())
            AddItem("TimeDateStamp", temp.Format("0x%08X", d.TimeDateStamp), DD_FIELD(TimeDateStamp)).SetXOffset(2);
        else
            AddTimeDateStamp("TimeDateStamp", d.TimeDateStamp, DD_FIELD(TimeDateStamp)).SetXOffset(2);
        AddItem("Version", temp.Format("%u.%u", d.MajorVersion, d.MinorVersion), DD_FIELD(MajorVersion)).SetXOffset(2);
        AddNumber("SizeOfData", d.SizeOfData, DD_FIELD(SizeOfData)).SetXOffset(2);
        AddNumber("AddressOfRawData", d.AddressOfRawData, DD_FIELD(AddressOfRawData)).SetXOffset(2);
        AddNumber("PointerToRawData", d.PointerToRawData, DD_FIELD(PointerToRawData)).SetXOffset(2);
#undef DD_FIELD
    }
}

void Panels::Headers::Update()
{
    list->DeleteAllItems();

    AddDOSHeader();
    AddRichHeader();
    AddNTHeaders();
    AddFileHeader();
    AddOptionalHeader();
    AddSectionHeaders();
    AddImportDescriptors();
    AddExportDirectory();
    AddDebugDirectory();
}

void Panels::Headers::GoToSelectedItem()
{
    const auto addr = list->GetCurrentItem().GetData(GView::Utils::INVALID_OFFSET);
    if (addr != GView::Utils::INVALID_OFFSET)
        win->GetCurrentView()->GoTo(addr);
}

bool Panels::Headers::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", PE_HEADERS_GOTO);
    return true;
}

bool Panels::Headers::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (TabPage::OnEvent(ctrl, evnt, controlID))
        return true;
    if ((evnt == Event::ListViewItemPressed) || ((evnt == Event::Command) && (controlID == PE_HEADERS_GOTO))) {
        GoToSelectedItem();
        return true;
    }
    return false;
}
