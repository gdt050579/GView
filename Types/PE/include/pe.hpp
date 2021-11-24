#pragma once

#include "GView.hpp"

#define MAX_NR_SECTIONS    256
#define MAX_DLL_NAME       64
#define MAX_PDB_NAME       128
#define MAX_EXPORTFNC_SIZE 128
#define MAX_IMPORTFNC_SIZE 128
#define MAX_RES_NAME       64

#define MAX_DESCRIPTION_SIZE 256
#define MAX_VERNAME_SIZE     64

#define MAX_VERVERSION_SIZE 32
#define MAX_VERSION_BUFFER  16386

#define PE_INVALID_ADDRESS     0xFFFFFFFFFFFFFFFF
#define MAX_IMPORTED_FUNCTIONS 4096

#define ADDR_FA  0
#define ADDR_RVA 1
#define ADDR_VA  2

#define MAX_ADDR_TYPES 3

#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER                0x1000
#define IMAGE_DLLCHARACTERISTICS_NO_LEGACY_BIOS_DEPENDENCIES 0x2000

#define __IMAGE_DOS_SIGNATURE              0x5A4D
#define __IMAGE_NT_SIGNATURE               0x00004550
#define __IMAGE_NT_OPTIONAL_HDR32_MAGIC    0x10b
#define __IMAGE_NT_OPTIONAL_HDR64_MAGIC    0x20b
#define __IMAGE_ROM_OPTIONAL_HDR_MAGIC     0x107
#define __IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define __IMAGE_SIZEOF_SHORT_NAME          8

#define __IMAGE_FILE_RELOCS_STRIPPED         0x0001 // Relocation info stripped from file.
#define __IMAGE_FILE_EXECUTABLE_IMAGE        0x0002 // File is executable  (i.e. no unresolved external references).
#define __IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004 // Line nunbers stripped from file.
#define __IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008 // Local symbols stripped from file.
#define __IMAGE_FILE_AGGRESIVE_WS_TRIM       0x0010 // Aggressively trim working set
#define __IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020 // App can handle >2gb addresses
#define __IMAGE_FILE_BYTES_REVERSED_LO       0x0080 // Bytes of machine word are reversed.
#define __IMAGE_FILE_32BIT_MACHINE           0x0100 // 32 bit word machine.
#define __IMAGE_FILE_DEBUG_STRIPPED          0x0200 // Debugging info stripped from file in .DBG file
#define __IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400 // If Image is on removable media, copy and run from the swap file.
#define __IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800 // If Image is on Net, copy and run from the swap file.
#define __IMAGE_FILE_SYSTEM                  0x1000 // System File.
#define __IMAGE_FILE_DLL                     0x2000 // File is a DLL.
#define __IMAGE_FILE_UP_SYSTEM_ONLY          0x4000 // File should only be run on a UP machine
#define __IMAGE_FILE_BYTES_REVERSED_HI       0x8000 // Bytes of machine word are reversed.
#define __IMAGE_FILE_MACHINE_UNKNOWN         0
#define __IMAGE_FILE_MACHINE_I386            0x014c // Intel 386.
#define __IMAGE_FILE_MACHINE_R3000           0x0162 // MIPS little-endian, 0x160 big-endian
#define __IMAGE_FILE_MACHINE_R4000           0x0166 // MIPS little-endian
#define __IMAGE_FILE_MACHINE_R10000          0x0168 // MIPS little-endian
#define __IMAGE_FILE_MACHINE_WCEMIPSV2       0x0169 // MIPS little-endian WCE v2
#define __IMAGE_FILE_MACHINE_ALPHA           0x0184 // Alpha_AXP
#define __IMAGE_FILE_MACHINE_SH3             0x01a2 // SH3 little-endian
#define __IMAGE_FILE_MACHINE_SH3DSP          0x01a3
#define __IMAGE_FILE_MACHINE_SH3E            0x01a4 // SH3E little-endian
#define __IMAGE_FILE_MACHINE_SH4             0x01a6 // SH4 little-endian
#define __IMAGE_FILE_MACHINE_SH5             0x01a8 // SH5
#define __IMAGE_FILE_MACHINE_ARM             0x01c0 // ARM Little-Endian
#define __IMAGE_FILE_MACHINE_THUMB           0x01c2 // ARM Thumb/Thumb-2 Little-Endian
#define __IMAGE_FILE_MACHINE_ARMNT           0x01c4 // ARM Thumb-2 Little-Endian
#define __IMAGE_FILE_MACHINE_AM33            0x01d3
#define __IMAGE_FILE_MACHINE_POWERPC         0x01F0 // IBM PowerPC Little-Endian
#define __IMAGE_FILE_MACHINE_POWERPCFP       0x01f1
#define __IMAGE_FILE_MACHINE_IA64            0x0200 // Intel 64
#define __IMAGE_FILE_MACHINE_MIPS16          0x0266 // MIPS
#define __IMAGE_FILE_MACHINE_ALPHA64         0x0284 // ALPHA64
#define __IMAGE_FILE_MACHINE_MIPSFPU         0x0366 // MIPS
#define __IMAGE_FILE_MACHINE_MIPSFPU16       0x0466 // MIPS
#define __IMAGE_FILE_MACHINE_AXP64           __IMAGE_FILE_MACHINE_ALPHA64
#define __IMAGE_FILE_MACHINE_TRICORE         0x0520 // Infineon
#define __IMAGE_FILE_MACHINE_CEF             0x0CEF
#define __IMAGE_FILE_MACHINE_EBC             0x0EBC // EFI Byte Code
#define __IMAGE_FILE_MACHINE_AMD64           0x8664 // AMD64 (K8)
#define __IMAGE_FILE_MACHINE_M32R            0x9041 // M32R little-endian
#define __IMAGE_FILE_MACHINE_CEE             0xC0EE

#define __IMAGE_SUBSYSTEM_UNKNOWN                  0  // Unknown subsystem.
#define __IMAGE_SUBSYSTEM_NATIVE                   1  // Image doesn't require a subsystem.
#define __IMAGE_SUBSYSTEM_WINDOWS_GUI              2  // Image runs in the Windows GUI subsystem.
#define __IMAGE_SUBSYSTEM_WINDOWS_CUI              3  // Image runs in the Windows character subsystem.
#define __IMAGE_SUBSYSTEM_OS2_CUI                  5  // image runs in the OS/2 character subsystem.
#define __IMAGE_SUBSYSTEM_POSIX_CUI                7  // image runs in the Posix character subsystem.
#define __IMAGE_SUBSYSTEM_NATIVE_WINDOWS           8  // image is a native Win9x driver.
#define __IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           9  // Image runs in the Windows CE subsystem.
#define __IMAGE_SUBSYSTEM_EFI_APPLICATION          10 //
#define __IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11 //
#define __IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       12 //
#define __IMAGE_SUBSYSTEM_EFI_ROM                  13
#define __IMAGE_SUBSYSTEM_XBOX                     14
#define __IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16

#define __IMAGE_DIRECTORY_ENTRY_EXPORT    0 // Export Directory
#define __IMAGE_DIRECTORY_ENTRY_IMPORT    1 // Import Directory
#define __IMAGE_DIRECTORY_ENTRY_RESOURCE  2 // Resource Directory
#define __IMAGE_DIRECTORY_ENTRY_EXCEPTION 3 // Exception Directory
#define __IMAGE_DIRECTORY_ENTRY_SECURITY  4 // Security Directory
#define __IMAGE_DIRECTORY_ENTRY_BASERELOC 5 // Base Relocation Table
#define __IMAGE_DIRECTORY_ENTRY_DEBUG     6 // Debug Directory
//      __IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define __IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   7  // Architecture Specific Data
#define __IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8  // RVA of GP
#define __IMAGE_DIRECTORY_ENTRY_TLS            9  // TLS Directory
#define __IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10 // Load Configuration Directory
#define __IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11 // Bound Import Directory in headers
#define __IMAGE_DIRECTORY_ENTRY_IAT            12 // Import Address Table
#define __IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13 // Delay Load Import Descriptors
#define __IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14 // COM Runtime descriptor

#define __IMAGE_DEBUG_TYPE_UNKNOWN       0
#define __IMAGE_DEBUG_TYPE_COFF          1
#define __IMAGE_DEBUG_TYPE_CODEVIEW      2
#define __IMAGE_DEBUG_TYPE_FPO           3
#define __IMAGE_DEBUG_TYPE_MISC          4
#define __IMAGE_DEBUG_TYPE_EXCEPTION     5
#define __IMAGE_DEBUG_TYPE_FIXUP         6
#define __IMAGE_DEBUG_TYPE_OMAP_TO_SRC   7
#define __IMAGE_DEBUG_TYPE_OMAP_FROM_SRC 8
#define __IMAGE_DEBUG_TYPE_BORLAND       9
#define __IMAGE_DEBUG_TYPE_RESERVED10    10
#define __IMAGE_DEBUG_TYPE_CLSID         11

#define __IMAGE_SCN_CNT_CODE               0x00000020 // Section contains code.
#define __IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040 // Section contains initialized data.
#define __IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080 // Section contains uninitialized data.
#define __IMAGE_SCN_MEM_SHARED             0x10000000 // Section is shareable.
#define __IMAGE_SCN_MEM_EXECUTE            0x20000000 // Section is executable.
#define __IMAGE_SCN_MEM_READ               0x40000000 // Section is readable.
#define __IMAGE_SCN_MEM_WRITE              0x80000000 // Section is writeable.

#define __IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       0x0020 // Image can handle a high entropy 64-bit virtual address space.
#define __IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          0x0040 // DLL can move.
#define __IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       0x0080 // Code Integrity Image
#define __IMAGE_DLLCHARACTERISTICS_NX_COMPAT             0x0100 // Image is NX compatible
#define __IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          0x0200 // Image understands isolation and doesn't want it
#define __IMAGE_DLLCHARACTERISTICS_NO_SEH                0x0400 // Image does not use SEH.  No SE handler may reside in this image
#define __IMAGE_DLLCHARACTERISTICS_NO_BIND               0x0800 // Do not bind this image.
#define __IMAGE_DLLCHARACTERISTICS_APPCONTAINER          0x1000 // Image should execute in an AppContainer
#define __IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            0x2000 // Driver uses WDM model
#define __IMAGE_DLLCHARACTERISTICS_GUARD_CF              0x4000 // Image supports Control Flow Guard.
#define __IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

#define __MAKEINITRESOURCE(i) ((uint32_t*) (i))
#define __RT_CURSOR           1
#define __RT_BITMAP           2
#define __RT_ICON             3
#define __RT_MENU             4
#define __RT_DIALOG           5
#define __RT_STRING           6
#define __RT_FONTDIR          7
#define __RT_FONT             8
#define __RT_ACCELERATOR      9
#define __RT_RCDATA           10
#define __RT_MESSAGETABLE     11
#define __DIFFERENCE          11

#define __RT_GROUP_CURSOR ((__RT_CURSOR) + __DIFFERENCE)
#define __RT_GROUP_ICON   ((__RT_ICON) + __DIFFERENCE)

#define __RT_VERSION    16
#define __RT_DLGINCLUDE 17
#define __RT_PLUGPLAY   19
#define __RT_VXD        20
#define __RT_ANICURSOR  21
#define __RT_ANIICON    22
#define __RT_HTML       23
#define __RT_MANIFEST   24

#define __BI_RGB       0L
#define __BI_RLE8      1L
#define __BI_RLE4      2L
#define __BI_BITFIELDS 3L
#define __BI_JPEG      4L
#define __BI_PNG       5L

#define __IMAGE_ORDINAL_FLAG32 0x80000000
#define __IMAGE_ORDINAL_FLAG64 0x8000000000000000

#define __ANYSIZE_ARRAY 1

#define MAX_VERION_PAIRS    64
#define MAX_VERSION_UNICODE 128
#define VERSION_VSFIX_SIG   0xFEEF04BD

namespace GView
{
namespace Type
{
    namespace PE
    {
        namespace Panels
        {
            enum class IDs : unsigned char
            {
                Information = 0,
                Directories,
                Exports,
                Sections,
                Headers,
                Resources,
                Icons,
                Imports,
                TLS,
            };
        };
        class VersionInformation
        {
#pragma pack(push, 1)
            struct VersionString
            {
                uint16_t wLength;
                uint16_t wValueLength;
                uint16_t wType;
                uint16_t Key[1];
            };
            struct VS_FIXEDFILEINFO
            {
                uint32_t dwSignature;
                uint32_t dwStrucVersion;
                uint32_t dwFileVersionMS;
                uint32_t dwFileVersionLS;
                uint32_t dwProductVersionMS;
                uint32_t dwProductVersionLS;
                uint32_t dwFileFlagsMask;
                uint32_t dwFileFlags;
                uint32_t dwFileOS;
                uint32_t dwFileType;
                uint32_t dwFileSubtype;
                uint32_t dwFileDateMS;
                uint32_t dwFileDateLS;
            };
#pragma pack(pop)
            struct VersionPair
            {
                String Key, Value;
                uint16_t Unicode[MAX_VERSION_UNICODE];
            };
            VersionPair Pairs[MAX_VERION_PAIRS];
            int nrPairs;

            int AddPair(const unsigned char* Buffer, int size, int poz);
            bool TestIfValidKey(const unsigned char* Buffer, int size, int poz);

          public:
            VersionInformation(void);
            ~VersionInformation(void);

            bool ComputeVersionInformation(const unsigned char* Buffer, int size);
            int GetNrItems()
            {
                return nrPairs;
            }
            String* GetKey(int index)
            {
                return &Pairs[index].Key;
            }
            String* GetValue(int index)
            {
                return &Pairs[index].Value;
            }
            uint16_t* GetUnicode(int index)
            {
                return &Pairs[index].Unicode[0];
            }
        };
        struct Guid
        {
            uint32_t Data1;
            uint16_t Data2;
            uint16_t Data3;
            uint8_t Data4[8];
        };

#pragma pack(push, 4)

        struct ImageTLSDirectory32
        {
            uint32_t StartAddressOfRawData;
            uint32_t EndAddressOfRawData;
            uint32_t AddressOfIndex;     // PDWORD
            uint32_t AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *
            uint32_t SizeOfZeroFill;
            union
            {
                uint32_t Characteristics;
                struct
                {
                    uint32_t Reserved0 : 20;
                    uint32_t Alignment : 4;
                    uint32_t Reserved1 : 8;
                };
            };
        };

        struct ImageDebugDirectory
        {
            uint32_t Characteristics;
            uint32_t TimeDateStamp;
            uint16_t MajorVersion;
            uint16_t MinorVersion;
            uint32_t Type;
            uint32_t SizeOfData;
            uint32_t AddressOfRawData;
            uint32_t PointerToRawData;
        };

        struct ImageExportDirectory
        {
            uint32_t Characteristics;
            uint32_t TimeDateStamp;
            uint16_t MajorVersion;
            uint16_t MinorVersion;
            uint32_t Name;
            uint32_t Base;
            uint32_t NumberOfFunctions;
            uint32_t NumberOfNames;
            uint32_t AddressOfFunctions;    // RVA from base of image
            uint32_t AddressOfNames;        // RVA from base of image
            uint32_t AddressOfNameOrdinals; // RVA from base of image
        };

#pragma pack(push, 2)

        struct ImageDOSHeader
        {
            uint16_t e_magic;    // Magic number
            uint16_t e_cblp;     // Bytes on last page of file
            uint16_t e_cp;       // Pages in file
            uint16_t e_crlc;     // Relocations
            uint16_t e_cparhdr;  // Size of header in paragraphs
            uint16_t e_minalloc; // Minimum extra paragraphs needed
            uint16_t e_maxalloc; // Maximum extra paragraphs needed
            uint16_t e_ss;       // Initial (relative) SS value
            uint16_t e_sp;       // Initial SP value
            uint16_t e_csum;     // Checksum
            uint16_t e_ip;       // Initial IP value
            uint16_t e_cs;       // Initial (relative) CS value
            uint16_t e_lfarlc;   // File address of relocation table
            uint16_t e_ovno;     // Overlay number
            uint16_t e_res[4];   // Reserved words
            uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
            uint16_t e_oeminfo;  // OEM information; e_oemid specific
            uint16_t e_res2[10]; // Reserved words
            uint32_t e_lfanew;   // File address of new exe header
        };

#pragma pack(pop) // Back to 4 byte packing.

        struct ImageFileHeader
        {
            uint16_t Machine;
            uint16_t NumberOfSections;
            uint32_t TimeDateStamp;
            uint32_t PointerToSymbolTable;
            uint32_t NumberOfSymbols;
            uint16_t SizeOfOptionalHeader;
            uint16_t Characteristics;
        };

        struct ImageDataDirectory
        {
            uint32_t VirtualAddress;
            uint32_t Size;
        };

        struct ImageOptionalHeader32
        {
            uint16_t Magic;
            uint8_t MajorLinkerVersion;
            uint8_t MinorLinkerVersion;
            uint32_t SizeOfCode;
            uint32_t SizeOfInitializedData;
            uint32_t SizeOfUninitializedData;
            uint32_t AddressOfEntryPoint;
            uint32_t BaseOfCode;
            uint32_t BaseOfData;
            uint32_t ImageBase;
            uint32_t SectionAlignment;
            uint32_t FileAlignment;
            uint16_t MajorOperatingSystemVersion;
            uint16_t MinorOperatingSystemVersion;
            uint16_t MajorImageVersion;
            uint16_t MinorImageVersion;
            uint16_t MajorSubsystemVersion;
            uint16_t MinorSubsystemVersion;
            uint32_t Win32VersionValue;
            uint32_t SizeOfImage;
            uint32_t SizeOfHeaders;
            uint32_t CheckSum;
            uint16_t Subsystem;
            uint16_t DllCharacteristics;
            uint32_t SizeOfStackReserve;
            uint32_t SizeOfStackCommit;
            uint32_t SizeOfHeapReserve;
            uint32_t SizeOfHeapCommit;
            uint32_t LoaderFlags;
            uint32_t NumberOfRvaAndSizes;
            ImageDataDirectory DataDirectory[__IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        };

        struct ImageNTHeaders32
        {
            uint32_t Signature;
            ImageFileHeader FileHeader;
            ImageOptionalHeader32 OptionalHeader;
        };

        struct ImageOptionalHeader64
        {
            uint16_t Magic;
            uint8_t MajorLinkerVersion;
            uint8_t MinorLinkerVersion;
            uint32_t SizeOfCode;
            uint32_t SizeOfInitializedData;
            uint32_t SizeOfUninitializedData;
            uint32_t AddressOfEntryPoint;
            uint32_t BaseOfCode;
            uint64_t ImageBase;
            uint32_t SectionAlignment;
            uint32_t FileAlignment;
            uint16_t MajorOperatingSystemVersion;
            uint16_t MinorOperatingSystemVersion;
            uint16_t MajorImageVersion;
            uint16_t MinorImageVersion;
            uint16_t MajorSubsystemVersion;
            uint16_t MinorSubsystemVersion;
            uint32_t Win32VersionValue;
            uint32_t SizeOfImage;
            uint32_t SizeOfHeaders;
            uint32_t CheckSum;
            uint16_t Subsystem;
            uint16_t DllCharacteristics;
            uint64_t SizeOfStackReserve;
            uint64_t SizeOfStackCommit;
            uint64_t SizeOfHeapReserve;
            uint64_t SizeOfHeapCommit;
            uint32_t LoaderFlags;
            uint32_t NumberOfRvaAndSizes;
            ImageDataDirectory DataDirectory[__IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        };

        struct ImageNTHeaders64
        {
            uint32_t Signature;
            ImageFileHeader FileHeader;
            ImageOptionalHeader64 OptionalHeader;
        };

        struct ImageSectionHeader
        {
            uint8_t Name[__IMAGE_SIZEOF_SHORT_NAME];
            union
            {
                uint32_t PhysicalAddress;
                uint32_t VirtualSize;
            } Misc;
            uint32_t VirtualAddress;
            uint32_t SizeOfRawData;
            uint32_t PointerToRawData;
            uint32_t PointerToRelocations;
            uint32_t PointerToLinenumbers;
            uint16_t NumberOfRelocations;
            uint16_t NumberOfLinenumbers;
            uint32_t Characteristics;
        };

        struct ImageImportDescriptor
        {
            union
            {
                uint32_t Characteristics;    // 0 for terminating null import descriptor
                uint32_t OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
            };
            uint32_t TimeDateStamp; // 0 if not bound,
            // -1 if bound, and real date\time stamp
            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
            // O.W. date/time stamp of DLL bound to (Old BIND)

            uint32_t ForwarderChain; // -1 if no forwarders
            uint32_t Name;
            uint32_t FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
        };

        struct ImageResourceDataEntry
        {
            uint32_t OffsetToData;
            uint32_t Size;
            uint32_t CodePage;
            uint32_t Reserved;
        };

        struct ImageResourceDirectory
        {
            uint32_t Characteristics;
            uint32_t TimeDateStamp;
            uint16_t MajorVersion;
            uint16_t MinorVersion;
            uint16_t NumberOfNamedEntries;
            uint16_t NumberOfIdEntries;
            //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
        };

        struct ImageResourceDirectoryEntry
        {
            union
            {
                struct
                {
                    uint32_t NameOffset : 31;
                    uint32_t NameIsString : 1;
                };
                uint32_t Name;
                uint16_t Id;
            };
            union
            {
                uint32_t OffsetToData;
                struct
                {
                    uint32_t OffsetToDirectory : 31;
                    uint32_t DataIsDirectory : 1;
                };
            };
        };

        struct ImageThunkData32
        {
            union
            {
                uint32_t ForwarderString; // PBYTE
                uint32_t Function;        // PDWORD
                uint32_t Ordinal;
                uint32_t AddressOfData; // PIMAGE_IMPORT_BY_NAME
            } u1;
        };

#pragma pack(push, 8)

        struct ImageThunkData64
        {
            union
            {
                uint64_t ForwarderString; // PBYTE
                uint64_t Function;        // PDWORD
                uint64_t Ordinal;
                uint64_t AddressOfData; // PIMAGE_IMPORT_BY_NAME
            } u1;
        };

#pragma pack(pop) // Pack to 4 byte packing.

#pragma pack(pop) // Back to default packing.

        struct BitmapInfoHeader
        {
            uint32_t biSize;
            uint32_t biWidth;
            uint32_t biHeight;
            uint16_t biPlanes;
            uint16_t biBitCount;
            uint32_t biCompression;
            uint32_t biSizeImage;
            uint32_t biXPelsPerMeter;
            uint32_t biYPelsPerMeter;
            uint32_t biClrUsed;
            uint32_t biClrImportant;
        };

        struct RGBQuad
        {
            uint8_t rgbBlue;
            uint8_t rgbGreen;
            uint8_t rgbRed;
            uint8_t rgbReserved;
        };
        class PEFile : public TypeInterface
        {
          public:
            struct LANGANDCODEPAGE
            {
                uint16_t wLanguage;
                uint16_t wCodePage;
            };
            struct ExportedFunction
            {
                uint32_t RVA;
                uint16_t Ordinal;
                FixSizeString<125> Name;
            };
            struct PEColors
            {
                ColorPair colMZ, colPE, colSectDef;
                ColorPair colSect;
                ColorPair colDir[15];
            };
            struct ResourceInformation
            {
                uint32_t Type;
                uint32_t ID;
                uint32_t CodePage;
                uint32_t Language;
                uint64_t Start;
                uint64_t Size;
                FixSizeString<61> Name;
            };

            struct ImportDllInformation
            {
                uint64_t RVA;
                FixSizeString<117> Name;
            };
            struct ImportFunctionInformation
            {
                uint64_t RVA;
                uint32_t dllIndex;
                FixSizeString<111> Name;
            };
            enum
            {
                SHOW_JUMPS  = 1,
                SHOW_CALLS  = 2,
                SHOW_FSTART = 4,
                SHOW_FEND   = 8,
                SHOW_MZPE   = 16,
                SHOW_INT3   = 32
            };

          public:
            Reference<GView::Utils::FileCache> file;
            Reference<GView::View::WindowInterface> win_interface;
            // PE informations
            ImageDOSHeader dos;
            union
            {
                ImageNTHeaders32 nth32;
                ImageNTHeaders64 nth64;
            };
            uint32_t nrSections;
            uint64_t computedSize, virtualComputedSize, computedWithCertificate;
            uint64_t imageBase;
            uint64_t rvaEntryPoint;
            uint64_t fileAlign;
            FixSizeString<61> dllName;
            FixSizeString<125> pdbName;
            ImageSectionHeader sect[MAX_NR_SECTIONS];
            ImageExportDirectory exportDir;
            ImageDataDirectory* dirs;
            GView::Utils::ErrorList errList;
            std::vector<ExportedFunction> exp;
            std::vector<ResourceInformation> res;
            std::vector<ImportDllInformation> impDLL;
            std::vector<ImageDebugDirectory> debugData;
            std::vector<ImportFunctionInformation> impFunc;

            ImageTLSDirectory32 tlsDir;
            PEColors peCols;
            VersionInformation Ver;
            uint32_t asmShow;
            uint32_t sectStart, peStart;
            uint64_t panelsMask;

            bool hdr64;
            bool isMetroApp;
            bool hasTLS;

            
            std::string_view ReadString(uint32_t RVA, unsigned int maxSize);
            bool ReadUnicodeLengthString(uint32_t FileAddress, char* text, int maxSize);

          public:
            PEFile(Reference<GView::Utils::FileCache> file);
            virtual ~PEFile()
            {
            }

            bool Update();

            std::string_view GetMachine();
            std::string_view GetSubsystem();
            uint64_t RVAtoFilePointer(uint64_t RVA);
            int RVAToSectionIndex(uint64_t RVA);
            uint64_t FilePointerToRVA(uint64_t fileAddress);
            uint64_t FilePointerToVA(uint64_t fileAddress);
            uint64_t ConvertAddress(uint64_t address, unsigned int fromAddressType, unsigned int toAddressType);
            bool BuildExport();
            void BuildVersionInfo();
            bool ProcessResourceDataEntry(uint64_t relAddress, uint64_t startRes, uint32_t* level, uint32_t indexLevel, char* resName);
            bool ProcessResourceDirTable(uint64_t relAddress, uint64_t startRes, uint32_t* level, uint32_t indexLevel, char* parentName);
            bool BuildResources();
            bool BuildImportDLLFunctions(uint32_t index, ImageImportDescriptor* impD);
            bool BuildImport();
            bool BuildTLS();
            bool BuildDebugData();

            bool HasPanel(Panels::IDs id);

            void UpdateBufferViewZones(Reference<GView::View::BufferViewerInterface> bufferView);

            void CopySectionName(uint32_t index, String& name);

            std::string_view GetTypeName() override
            {
                return "PE";
            }


            static std::string_view ResourceIDToName(uint32_t resID);
            static std::string_view LanguageIDToName(uint32_t langID);
            static std::string_view DirectoryIDToName(uint32_t dirID);
        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;
                Reference<AppCUI::Controls::ListView> version;

                void UpdateGeneralInformation();
                void UpdateVersionInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::PE::PEFile> pe);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
            class Sections : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                int Base;

                std::string_view GetValue(NumericFormatter& n, unsigned int value);
                void GoToSelectedSection();
                void SelectCurrentSection();

              public:
                Sections(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
            class Directories : public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                void GoToSelectedDirectory();
                void SelectCurrentDirectory();

              public:
                Directories(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
            class Imports: public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                Reference<AppCUI::Controls::ListView> info;
                Reference<AppCUI::Controls::ListView> dlls;

              public:
                Imports(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                void OnAfterResize(int newWidth, int newHeight) override;
            };
            class Exports : public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;

              public:
                Exports(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
            class Resources : public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;


                void SaveCurrentResource();
                void GoToSelectedResource();
                void SelectCurrentResource();
              public:
                Resources(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
        }; // namespace Panels
    }      // namespace PE
} // namespace Type
} // namespace GView
