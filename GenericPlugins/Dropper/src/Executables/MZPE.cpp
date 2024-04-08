#include "Executables.hpp"

namespace GView::GenericPlugins::Droppper::Executables
{
constexpr uint16 IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr uint32 IMAGE_NT_SIGNATURE  = 0x00004550;

#define __IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define __IMAGE_SIZEOF_SHORT_NAME          8

#pragma pack(push, 2)

struct ImageDOSHeader {
    uint16 e_magic;    // Magic number
    uint16 e_cblp;     // Bytes on last page of file
    uint16 e_cp;       // Pages in file
    uint16 e_crlc;     // Relocations
    uint16 e_cparhdr;  // Size of header in paragraphs
    uint16 e_minalloc; // Minimum extra paragraphs needed
    uint16 e_maxalloc; // Maximum extra paragraphs needed
    uint16 e_ss;       // Initial (relative) SS value
    uint16 e_sp;       // Initial SP value
    uint16 e_csum;     // Checksum
    uint16 e_ip;       // Initial IP value
    uint16 e_cs;       // Initial (relative) CS value
    uint16 e_lfarlc;   // File address of relocation table
    uint16 e_ovno;     // Overlay number
    uint16 e_res[4];   // Reserved words
    uint16 e_oemid;    // OEM identifier (for e_oeminfo)
    uint16 e_oeminfo;  // OEM information; e_oemid specific
    uint16 e_res2[10]; // Reserved words
    uint32 e_lfanew;   // File address of new exe header
};

#pragma pack(pop) // Back to 4 byte packing.

struct ImageFileHeader {
    uint16 Machine;
    uint16 NumberOfSections;
    uint32 TimeDateStamp;
    uint32 PointerToSymbolTable;
    uint32 NumberOfSymbols;
    uint16 SizeOfOptionalHeader;
    uint16 Characteristics;
};

struct ImageDataDirectory {
    uint32 VirtualAddress;
    uint32 Size;
};

struct ImageOptionalHeader32 {
    uint16 Magic;
    uint8 MajorLinkerVersion;
    uint8 MinorLinkerVersion;
    uint32 SizeOfCode;
    uint32 SizeOfInitializedData;
    uint32 SizeOfUninitializedData;
    uint32 AddressOfEntryPoint;
    uint32 BaseOfCode;
    uint32 BaseOfData;
    uint32 ImageBase;
    uint32 SectionAlignment;
    uint32 FileAlignment;
    uint16 MajorOperatingSystemVersion;
    uint16 MinorOperatingSystemVersion;
    uint16 MajorImageVersion;
    uint16 MinorImageVersion;
    uint16 MajorSubsystemVersion;
    uint16 MinorSubsystemVersion;
    uint32 Win32VersionValue;
    uint32 SizeOfImage;
    uint32 SizeOfHeaders;
    uint32 CheckSum;
    uint16 Subsystem;
    uint16 DllCharacteristics;
    uint32 SizeOfStackReserve;
    uint32 SizeOfStackCommit;
    uint32 SizeOfHeapReserve;
    uint32 SizeOfHeapCommit;
    uint32 LoaderFlags;
    uint32 NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[__IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct ImageNTHeaders32 {
    uint32 Signature;
    ImageFileHeader FileHeader;
    ImageOptionalHeader32 OptionalHeader;
};

struct ImageSectionHeader {
    uint8 Name[__IMAGE_SIZEOF_SHORT_NAME];
    union {
        uint32 PhysicalAddress;
        uint32 VirtualSize;
    } Misc;
    uint32 VirtualAddress;
    uint32 SizeOfRawData;
    uint32 PointerToRawData;
    uint32 PointerToRelocations;
    uint32 PointerToLinenumbers;
    uint16 NumberOfRelocations;
    uint16 NumberOfLinenumbers;
    uint32 Characteristics;
};

const char* MZPE::GetName()
{
    return "MZPE";
}

ObjectCategory MZPE::GetGroup()
{
    return ObjectCategory::Executables;
}

const char* MZPE::GetOutputExtension()
{
    return "mzpe";
}

Priority MZPE::GetPriority()
{
    return Priority::Binary;
}

bool MZPE::ShouldGroupInOneFile()
{
    return false;
}

Result MZPE::Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end)
{
    CHECK(IsMagicU16(precachedBuffer, IMAGE_DOS_SIGNATURE), Result::NotFound, "");

    auto buffer = file.CopyToBuffer(offset, 0x200, true);
    CHECK(buffer.IsValid(), Result::NotFound, "");

    auto dos = buffer.GetObject<ImageDOSHeader>();
    CHECK(dos, Result::NotFound, "");
    CHECK(dos->e_magic == IMAGE_DOS_SIGNATURE, Result::NotFound, "");

    auto nth32 = buffer.GetObject<ImageNTHeaders32>(dos->e_lfanew);
    CHECK(nth32, Result::NotFound, "");
    CHECK(nth32->Signature == IMAGE_NT_SIGNATURE, Result::NotFound, "");

    const auto count    = nth32->FileHeader.NumberOfSections;
    const auto position = static_cast<uint64>(dos->e_lfanew) + nth32->FileHeader.SizeOfOptionalHeader + sizeof(nth32->Signature) + sizeof(ImageFileHeader);

    const auto b = file.Get(position + count * sizeof(ImageSectionHeader) - 1, sizeof(ImageSectionHeader), true);
    auto obj     = b.GetObject<ImageSectionHeader>(0);

    const auto computedSize = obj->PointerToRawData + obj->SizeOfRawData;

    start = offset;
    end   = offset + computedSize;

    return Result::Buffer;
}

} // namespace GView::GenericPlugins::Droppper::Executables
