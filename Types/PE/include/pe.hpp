#pragma once

#include "GView.hpp"

constexpr auto MAX_NR_SECTIONS    = 256;
constexpr auto MAX_DLL_NAME       = 64;
constexpr auto MAX_PDB_NAME       = 128;
constexpr auto MAX_EXPORTFNC_SIZE = 128;
constexpr auto MAX_IMPORTFNC_SIZE = 128;
constexpr auto MAX_RES_NAME       = 64;

#define MAX_DESCRIPTION_SIZE 256
#define MAX_VERNAME_SIZE     64

#define MAX_VERVERSION_SIZE 32
#define MAX_VERSION_BUFFER  16386

#define PE_INVALID_ADDRESS     0xFFFFFFFFFFFFFFFF
#define MAX_IMPORTED_FUNCTIONS 4096

#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER                0x1000
#define IMAGE_DLLCHARACTERISTICS_NO_LEGACY_BIOS_DEPENDENCIES 0x2000

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
        namespace Constants
        {
            constexpr uint16 IMAGE_DOS_SIGNATURE = 0x5A4D;
            constexpr uint32 IMAGE_NT_SIGNATURE  = 0x00004550;
        }; // namespace Constants
        namespace Panels
        {
            enum class IDs : uint8
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
                Symbols,
                GoInformation,
                OpCodes
            };
        };
        class VersionInformation
        {
#pragma pack(push, 1)
            struct VersionString
            {
                uint16 wLength;
                uint16 wValueLength;
                uint16 wType;
                uint16 Key[1];
            };
            struct VS_FIXEDFILEINFO
            {
                uint32 dwSignature;
                uint32 dwStrucVersion;
                uint32 dwFileVersionMS;
                uint32 dwFileVersionLS;
                uint32 dwProductVersionMS;
                uint32 dwProductVersionLS;
                uint32 dwFileFlagsMask;
                uint32 dwFileFlags;
                uint32 dwFileOS;
                uint32 dwFileType;
                uint32 dwFileSubtype;
                uint32 dwFileDateMS;
                uint32 dwFileDateLS;
            };
#pragma pack(pop)
            struct VersionPair
            {
                String Key, Value;
                uint16 Unicode[MAX_VERSION_UNICODE];
            };
            VersionPair Pairs[MAX_VERION_PAIRS];
            int nrPairs;

            int AddPair(const uint8* Buffer, int size, int poz);
            bool TestIfValidKey(const uint8* Buffer, int size, int poz);

          public:
            VersionInformation(void);
            ~VersionInformation(void);

            bool ComputeVersionInformation(const uint8* Buffer, int size);
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
            uint16* GetUnicode(int index)
            {
                return &Pairs[index].Unicode[0];
            }
        };

        struct WinCertificate
        {
            uint32 dwLength;
            uint16 wRevision;
            uint16 wCertificateType; // WIN_CERT_TYPE_xxx
            uint8 bCertificate[__ANYSIZE_ARRAY];
        };

        constexpr auto __WIN_CERT_REVISION_1_0 = 0x0100;
        constexpr auto __WIN_CERT_REVISION_2_0 = 0x0200;

        constexpr auto __WIN_CERT_TYPE_X509             = 0x0001; // bCertificate contains an X.509 Certificate
        constexpr auto __WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002; // bCertificate contains a PKCS SignedData structure
        constexpr auto __WIN_CERT_TYPE_RESERVED_1       = 0x0003; // Reserved
        constexpr auto __WIN_CERT_TYPE_TS_STACK_SIGNED  = 0x0004; // Terminal Server Protocol Stack Certificate signing

        struct Guid
        {
            uint32 Data1;
            uint16 Data2;
            uint16 Data3;
            uint8 Data4[8];
        };

#pragma pack(push, 4)

        struct ImageTLSDirectory32
        {
            uint32 StartAddressOfRawData;
            uint32 EndAddressOfRawData;
            uint32 AddressOfIndex;     // PDWORD
            uint32 AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *
            uint32 SizeOfZeroFill;
            union
            {
                uint32 Characteristics;
                struct
                {
                    uint32 Reserved0 : 20;
                    uint32 Alignment : 4;
                    uint32 Reserved1 : 8;
                };
            };
        };

        struct ImageDebugDirectory
        {
            uint32 Characteristics;
            uint32 TimeDateStamp;
            uint16 MajorVersion;
            uint16 MinorVersion;
            uint32 Type;
            uint32 SizeOfData;
            uint32 AddressOfRawData;
            uint32 PointerToRawData;
        };

        struct ImageExportDirectory
        {
            uint32 Characteristics;
            uint32 TimeDateStamp;
            uint16 MajorVersion;
            uint16 MinorVersion;
            uint32 Name;
            uint32 Base;
            uint32 NumberOfFunctions;
            uint32 NumberOfNames;
            uint32 AddressOfFunctions;    // RVA from base of image
            uint32 AddressOfNames;        // RVA from base of image
            uint32 AddressOfNameOrdinals; // RVA from base of image
        };

#pragma pack(push, 2)

        struct ImageDOSHeader
        {
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

        struct ImageFileHeader
        {
            uint16 Machine;
            uint16 NumberOfSections;
            uint32 TimeDateStamp;
            uint32 PointerToSymbolTable;
            uint32 NumberOfSymbols;
            uint16 SizeOfOptionalHeader;
            uint16 Characteristics;
        };

        struct ImageDataDirectory
        {
            uint32 VirtualAddress;
            uint32 Size;
        };

        struct ImageOptionalHeader32
        {
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

        struct ImageNTHeaders32
        {
            uint32 Signature;
            ImageFileHeader FileHeader;
            ImageOptionalHeader32 OptionalHeader;
        };

        struct ImageOptionalHeader64
        {
            uint16 Magic;
            uint8 MajorLinkerVersion;
            uint8 MinorLinkerVersion;
            uint32 SizeOfCode;
            uint32 SizeOfInitializedData;
            uint32 SizeOfUninitializedData;
            uint32 AddressOfEntryPoint;
            uint32 BaseOfCode;
            uint64 ImageBase;
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
            uint64 SizeOfStackReserve;
            uint64 SizeOfStackCommit;
            uint64 SizeOfHeapReserve;
            uint64 SizeOfHeapCommit;
            uint32 LoaderFlags;
            uint32 NumberOfRvaAndSizes;
            ImageDataDirectory DataDirectory[__IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        };

        struct ImageNTHeaders64
        {
            uint32 Signature;
            ImageFileHeader FileHeader;
            ImageOptionalHeader64 OptionalHeader;
        };

        struct ImageSectionHeader
        {
            uint8 Name[__IMAGE_SIZEOF_SHORT_NAME];
            union
            {
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

        struct ImageImportDescriptor
        {
            union
            {
                uint32 Characteristics;    // 0 for terminating null import descriptor
                uint32 OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
            };
            uint32 TimeDateStamp; // 0 if not bound,
            // -1 if bound, and real date\time stamp
            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
            // O.W. date/time stamp of DLL bound to (Old BIND)

            uint32 ForwarderChain; // -1 if no forwarders
            uint32 Name;
            uint32 FirstThunk; // RVA to IAT (if bound this IAT has actual addresses)
        };

        struct ImageResourceDataEntry
        {
            uint32 OffsetToData;
            uint32 Size;
            uint32 CodePage;
            uint32 Reserved;
        };

        struct ImageResourceDirectory
        {
            uint32 Characteristics;
            uint32 TimeDateStamp;
            uint16 MajorVersion;
            uint16 MinorVersion;
            uint16 NumberOfNamedEntries;
            uint16 NumberOfIdEntries;
            //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
        };

        struct ImageResourceDirectoryEntry
        {
            union
            {
                struct
                {
                    uint32 NameOffset : 31;
                    uint32 NameIsString : 1;
                };
                uint32 Name;
                uint16 Id;
            };
            union
            {
                uint32 OffsetToData;
                struct
                {
                    uint32 OffsetToDirectory : 31;
                    uint32 DataIsDirectory : 1;
                };
            };
        };

        struct ImageThunkData32
        {
            union
            {
                uint32 ForwarderString; // PBYTE
                uint32 Function;        // PDWORD
                uint32 Ordinal;
                uint32 AddressOfData; // PIMAGE_IMPORT_BY_NAME
            } u1;
        };

#pragma pack(push, 1)
        struct ImageSymbol
        {
            union
            {
                uint8 ShortName[__IMAGE_SIZEOF_SHORT_NAME];
                struct
                {
                    uint32 Short; // if 0, use LongName
                    uint32 Long;  // offset into string table
                } Name;
                uint32 LongName[2]; // PBYTE [2]
            } N;
            uint32 Value;
            int16 SectionNumber;
            uint16 Type;
            uint8 StorageClass;
            uint8 NumberOfAuxSymbols;
        };
#pragma pack(pop) // Back to 4 byte packing.

        constexpr auto IMAGE_SIZEOF_SYMBOL = 18U;
        static_assert(sizeof(ImageSymbol) == IMAGE_SIZEOF_SYMBOL, "");

        constexpr auto SYM_NOT_A_FUNCTION = 0;
        constexpr auto SYM_FUNCTION       = 0x20;

        constexpr auto IMAGE_SYM_UNDEFINED      = (uint16) 0;  // Symbol is undefined or is common.
        constexpr auto IMAGE_SYM_ABSOLUTE       = (uint16) -1; // Symbol is an absolute value.
        constexpr auto IMAGE_SYM_DEBUG          = (uint16) -2; // Symbol is a special debug item.
        constexpr auto IMAGE_SYM_SECTION_MAX    = 0xFEFF;      // Values 0xFF00-0xFFFF are special
        constexpr auto MAXLONG                  = 0x7fffffff;
        constexpr auto IMAGE_SYM_SECTION_MAX_EX = MAXLONG;

        // Storage classes.
        constexpr auto IMAGE_SYM_CLASS_END_OF_FUNCTION  = (uint8) -1;
        constexpr auto IMAGE_SYM_CLASS_NULL             = 0x0000;
        constexpr auto IMAGE_SYM_CLASS_AUTOMATIC        = 0x0001;
        constexpr auto IMAGE_SYM_CLASS_EXTERNAL         = 0x0002;
        constexpr auto IMAGE_SYM_CLASS_STATIC           = 0x0003;
        constexpr auto IMAGE_SYM_CLASS_REGISTER         = 0x0004;
        constexpr auto IMAGE_SYM_CLASS_EXTERNAL_DEF     = 0x0005;
        constexpr auto IMAGE_SYM_CLASS_LABEL            = 0x0006;
        constexpr auto IMAGE_SYM_CLASS_UNDEFINED_LABEL  = 0x0007;
        constexpr auto IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 0x0008;
        constexpr auto IMAGE_SYM_CLASS_ARGUMENT         = 0x0009;
        constexpr auto IMAGE_SYM_CLASS_STRUCT_TAG       = 0x000A;
        constexpr auto IMAGE_SYM_CLASS_MEMBER_OF_UNION  = 0x000B;
        constexpr auto IMAGE_SYM_CLASS_UNION_TAG        = 0x000C;
        constexpr auto IMAGE_SYM_CLASS_TYPE_DEFINITION  = 0x000D;
        constexpr auto IMAGE_SYM_CLASS_UNDEFINED_STATIC = 0x000E;
        constexpr auto IMAGE_SYM_CLASS_ENUM_TAG         = 0x000F;
        constexpr auto IMAGE_SYM_CLASS_MEMBER_OF_ENUM   = 0x0010;
        constexpr auto IMAGE_SYM_CLASS_REGISTER_PARAM   = 0x0011;
        constexpr auto IMAGE_SYM_CLASS_BIT_FIELD        = 0x0012;
        constexpr auto IMAGE_SYM_CLASS_FAR_EXTERNAL     = 0x0044;
        constexpr auto IMAGE_SYM_CLASS_BLOCK            = 0x0064;
        constexpr auto IMAGE_SYM_CLASS_FUNCTION         = 0x0065;
        constexpr auto IMAGE_SYM_CLASS_END_OF_STRUCT    = 0x0066;
        constexpr auto IMAGE_SYM_CLASS_FILE             = 0x0067;
        constexpr auto IMAGE_SYM_CLASS_SECTION          = 0x0068;
        constexpr auto IMAGE_SYM_CLASS_WEAK_EXTERNAL    = 0x0069;
        constexpr auto IMAGE_SYM_CLASS_CLR_TOKEN        = 0x006B;

#pragma pack(push, 8)

        struct ImageThunkData64
        {
            union
            {
                uint64 ForwarderString; // PBYTE
                uint64 Function;        // PDWORD
                uint64 Ordinal;
                uint64 AddressOfData; // PIMAGE_IMPORT_BY_NAME
            } u1;
        };

#pragma pack(pop) // Pack to 4 byte packing.

#pragma pack(pop) // Back to default packing.

        struct DIBInfoHeader
        {
            uint32 sizeOfHeader;
            uint32 width;
            uint32 height;
            uint16 colorPlanes;
            uint16 bitsPerPixel;
            uint32 comppresionMethod;
            uint32 imageSize;
            uint32 horizontalResolution;
            uint32 verticalResolution;
            uint32 numberOfColors;
            uint32 numberOfImportantColors;
        };
        struct PNGHeader
        {
            uint32 magic;
            uint32 reserved;
            uint32 ihdrLength;
            uint32 ihdrMagic;
            uint32 width;
            uint32 height;
        };

        enum class AddressType : uint8
        {
            FileOffset = 0,
            RVA        = 1,
            VA         = 2
        };

        enum class MachineType : uint16
        {
            Unknown   = 0,
            I386      = 0x014c, // Intel 386.
            R3000     = 0x0162, // MIPS little-endian, 0x160 big-endian
            R4000     = 0x0166, // MIPS little-endian
            R10000    = 0x0168, // MIPS little-endian
            WCEMIPSV2 = 0x0169, // MIPS little-endian WCE v2
            ALPHA     = 0x0184, // Alpha_AXP
            SH3       = 0x01a2, // SH3 little-endian
            SH3DSP    = 0x01a3,
            SH3E      = 0x01a4, // SH3E little-endian
            SH4       = 0x01a6, // SH4 little-endian
            SH5       = 0x01a8, // SH5
            ARM       = 0x01c0, // ARM Little-Endian
            THUMB     = 0x01c2, // ARM Thumb/Thumb-2 Little-Endian
            ARMNT     = 0x01c4, // ARM Thumb-2 Little-Endian
            AM33      = 0x01d3,
            POWERPC   = 0x01F0, // IBM PowerPC Little-Endian
            POWERPCFP = 0x01f1,
            PPCBE     = 0x01f2, // Xbox 360 (aka Xenon)
            IA64      = 0x0200, // Intel 64
            MIPS16    = 0x0266, // MIPS
            ALPHA64   = 0x0284, // ALPHA64
            MIPSFPU   = 0x0366, // MIPS
            MIPSFPU16 = 0x0466, // MIPS
            TRICORE   = 0x0520, // Infineon
            CEF       = 0x0CEF,
            EBC       = 0x0EBC, // EFI Byte Code
            AMD64     = 0x8664, // AMD64 (K8)
            M32R      = 0x9041, // M32R little-endian
            ARM64     = 0xAA64,
            CEE       = 0xC0EE,
        };

        enum class SubsystemType : uint16
        {
            Unknown                = 0,  // Unknown subsystem.
            Native                 = 1,  // Image doesn't require a subsystem.
            WindowGUI              = 2,  // Image runs in the Windows GUI subsystem.
            WindowsCUI             = 3,  // Image runs in the Windows character subsystem.
            OS2CUI                 = 5,  // image runs in the OS/2 character subsystem.
            PosixCUI               = 7,  // image runs in the Posix character subsystem.
            WindowsNative          = 8,  // image is a native Win9x driver.
            WindowsCEGUI           = 9,  // Image runs in the Windows CE subsystem.
            EFIApplication         = 10, //
            EFIBootServiceDriver   = 11, //
            EFIRuntimeDriver       = 12, //
            EFIROM                 = 13,
            XBOX                   = 14,
            WindowsBootApplication = 16,
        };
        enum class DirectoryType : uint8
        {
            Export        = 0,
            Import        = 1,
            Resource      = 2,
            Exception     = 3,
            Security      = 4,
            BaseRelloc    = 5,
            Debug         = 6,
            Architecture  = 7,
            GlobalPTR     = 8,
            TLS           = 9,
            Config        = 10,
            BoundImport   = 11,
            IAT           = 12,
            DelayImport   = 13,
            COMDescriptor = 14
        };
        enum class ResourceType : uint32
        {
            Cursor       = 1,
            Bitmap       = 2,
            Icon         = 3,
            Menu         = 4,
            Dialog       = 5,
            String       = 6,
            FontDir      = 7,
            Font         = 8,
            Accelerator  = 9,
            RCData       = 10,
            MessageTable = 11,
            CursorGroup  = 12, // 11+Cursor
            IconGroup    = 14, // 11+Icon
            Version      = 16,
            DLGInclude   = 17,
            PlugPlay     = 19,
            VXD          = 20,
            ANICursor    = 21,
            ANIIcon      = 22,
            HTML         = 23,
            Manifest     = 24
        };

        static constexpr auto INS_CALL_COLOR       = ColorPair{ Color::White, Color::Silver };
        static constexpr auto INS_LCALL_COLOR      = ColorPair{ Color::Red, Color::DarkGreen };
        static constexpr auto INS_JUMP_COLOR       = ColorPair{ Color::White, Color::DarkRed };
        static constexpr auto INS_LJUMP_COLOR      = ColorPair{ Color::Yellow, Color::DarkRed };
        static constexpr auto INS_BREAKPOINT_COLOR = ColorPair{ Color::Magenta, Color::DarkBlue }; // Gray
        static constexpr auto START_FUNCTION_COLOR = ColorPair{ Color::Yellow, Color::Olive };
        static constexpr auto END_FUNCTION_COLOR   = ColorPair{ Color::Black, Color::Olive };
        static constexpr auto EXE_MARKER_COLOR     = ColorPair{ Color::Yellow, Color::DarkRed };

        class PEFile : public TypeInterface,
                       public GView::View::BufferViewer::OffsetTranslateInterface,
                       public GView::View::BufferViewer::PositionToColorInterface
        {
          public:
            struct ExportedFunction
            {
                uint32 RVA;
                uint16 Ordinal;
                String Name;
            };
            struct PEColors
            {
                ColorPair colMZ, colPE, colSectDef;
                ColorPair colSect;
                ColorPair colDir[15];
            };
            enum class ImageType : uint8
            {
                DIB = 0,
                PNG,
                Unknwown = 0xFF
            };
            struct ResourceInformation
            {
                ResourceType Type;
                uint32 ID;
                uint32 CodePage;
                uint32 Language;
                uint64 Start;
                uint64 Size;
                FixSizeString<61> Name;
                struct
                {
                    uint32 width, height;
                    uint8 bitsPerPixel;
                    ImageType type;
                } Image;
            };

            struct ImportDllInformation
            {
                uint64 RVA;
                FixSizeString<117> Name;
            };
            struct ImportFunctionInformation
            {
                uint64 RVA;
                uint32 dllIndex;
                String Name;
            };

            struct SymbolInformation
            {
                String name; // this can be either short or long name that needs to be located
                ImageSymbol is;
            };

          public:
            // PE informations
            ImageDOSHeader dos;
            union
            {
                ImageNTHeaders32 nth32;
                ImageNTHeaders64 nth64;
            };
            uint32 nrSections;
            uint64 computedSize, virtualComputedSize, computedWithCertificate;
            uint64 imageBase;
            uint64 rvaEntryPoint;
            uint64 fileAlign;
            FixSizeString<61> dllName;
            FixSizeString<MAX_PDB_NAME> pdbName;
            ImageSectionHeader sect[MAX_NR_SECTIONS];
            ImageExportDirectory exportDir;
            ImageDataDirectory* dirs;
            GView::Utils::ErrorList errList;
            std::vector<ExportedFunction> exp;
            std::vector<ResourceInformation> res;
            std::vector<ImportDllInformation> impDLL;
            std::vector<ImageDebugDirectory> debugData;
            std::vector<ImportFunctionInformation> impFunc;
            std::vector<SymbolInformation> symbols;

            ImageTLSDirectory32 tlsDir;
            PEColors peCols;
            VersionInformation Ver;
            uint32 asmShow;
            uint32 sectStart, peStart;
            uint64 panelsMask;

            uint32 showOpcodesMask{ 0 };
            std::vector<std::pair<uint64, uint64>> executableZonesFAs;
            GView::Dissasembly::DissasemblerIntel dissasembler{};

            bool hdr64;
            bool isMetroApp;
            bool hasTLS;
            bool hasOverlay;

            std::string_view ReadString(uint32 RVA, uint32 maxSize);
            bool ReadUnicodeLengthString(uint32 FileAddress, char* text, uint32 maxSize);

            // GO
            uint32 nameSize = 0;
            uint32 valSize  = 0;
            uint32 tag      = 0;
            std::string noteName{};
            Golang::PcLnTab pcLnTab{};

            // digital signature
            bool signatureChecked{ false };
            std::optional<DigitalSignature::AuthenticodeMS> signatureData{};

          public:
            PEFile();
            virtual ~PEFile() = default;

            bool Update();

            constexpr inline ImageDataDirectory& GetDirectory(DirectoryType dirType)
            {
                return dirs[(uint8) dirType];
            }

            std::string_view GetMachine();
            std::string_view GetSubsystem();
            uint64 VAtoFA(uint64 va) const;
            uint64 RVAtoFilePointer(uint64 RVA);
            int32 RVAToSectionIndex(uint64 RVA);
            uint64 FilePointerToRVA(uint64 fileAddress);
            uint64 FilePointerToVA(uint64 fileAddress);

            uint64 TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex) override;
            uint64 TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex) override;

            uint64 ConvertAddress(uint64 address, AddressType fromAddressType, AddressType toAddressType);
            bool BuildExport();
            void BuildVersionInfo();
            bool ProcessResourceImageInformation(ResourceInformation& res);
            bool ProcessResourceDataEntry(uint64 relAddress, uint64 startRes, uint32* level, uint32 indexLevel, char* resName);
            bool ProcessResourceDirTable(uint64 relAddress, uint64 startRes, uint32* level, uint32 indexLevel, char* parentName);
            bool BuildResources();
            bool BuildImportDLLFunctions(uint32 index, ImageImportDescriptor* impD);
            bool BuildImport();
            bool BuildTLS();
            bool BuildDebugData();
            bool BuildSymbols();

            // GO
            bool ParseGoData();
            bool ParseGoBuild();
            bool ParseGoBuildInfo();
            std::vector<uint64> FindPcLnTabSigsCandidates() const;

            bool HasPanel(Panels::IDs id);

            void CopySectionName(uint32 index, String& name);
            void GetSectionName(uint32 index, String& name);

            bool GetResourceImageInformation(const ResourceInformation& r, String& info);
            bool LoadIcon(const ResourceInformation& r, Image& img);

            bool GetColorForBuffer(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result) override;
            bool GetColorForBufferIntel(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result);

            std::string_view GetTypeName() override
            {
                return "PE";
            }
            void RunCommand(std::string_view) override;

            static std::string_view ResourceIDToName(ResourceType resType);
            static std::string_view LanguageIDToName(uint32 langID);
            static std::string_view DirectoryIDToName(uint32 dirID);

          public:
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

            uint32 GetSelectionZonesCount() override
            {
                CHECK(selectionZoneInterface.IsValid(), 0, "");
                return selectionZoneInterface->GetSelectionZonesCount();
            }

            TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
            {
                static auto d = TypeInterface::SelectionZone{ 0, 0 };
                CHECK(selectionZoneInterface.IsValid(), d, "");
                CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

                return selectionZoneInterface->GetSelectionZone(index);
            }
        };

        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<Object> object;
                Reference<GView::Type::PE::PEFile> pe;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;
                Reference<AppCUI::Controls::ImageView> imageView;
                int32 iconSize = 0;

                void UpdateGeneralInformation();
                void SetLanguage();
                void SetCertificate();
                void SetStringTable();
                void ChooseIcon();
                void UpdateIssues();
                void RecomputePanelsPositions();
                void SetIcon(const PEFile::ResourceInformation& ri);

              public:
                Information(Reference<Object> _object, Reference<GView::Type::PE::PEFile> pe);

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

                std::string_view GetValue(NumericFormatter& n, uint32 value);
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
            class Imports : public TabPage
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
            class Symbols : public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                int Base;

                std::string_view GetValue(NumericFormatter& n, uint32 value);

                void GetSymbolType(uint32 sectionNumber, String& name);
                void GetStorageClass(uint16 storageclass, String& name);

              public:
                Symbols(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

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
            class Icons : public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ComboBox> iconsList;
                Reference<AppCUI::Controls::ImageView> imageView;

                void UpdateCurrentIcon();

              public:
                Icons(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
            class Headers : public TabPage
            {
                Reference<GView::Type::PE::PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;

                void AddHeader(std::string_view name);
                void AddNumber(std::string_view name, uint32 value);
                void AddMagic(uint8* offset, uint32 size);
                void AddItem(std::string_view name, std::string_view value);

              public:
                Headers(Reference<GView::Type::PE::PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
            };

            class GoInformation : public TabPage
            {
                inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
                inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

                const std::string_view format            = "%-16s (%s)";
                const std::string_view formatDescription = "%-16s (%s) %s";

                Reference<Object> object;
                Reference<PEFile> pe;
                Reference<AppCUI::Controls::ListView> list;

              public:
                GoInformation(Reference<Object> _object, Reference<PEFile> _pe);

                template <typename T>
                ListViewItem AddDecAndHexElement(
                      std::string_view name, std::string_view format, T value, ListViewItem::Type type = ListViewItem::Type::Normal)
                {
                    LocalString<1024> ls;
                    NumericFormatter nf;
                    NumericFormatter nf2;

                    // static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ', sizeof(T) * 2 };
                    static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ' };

                    const auto v    = nf.ToString(value, dec);
                    const auto vHex = nf2.ToString(value, hexBySize);
                    auto it         = list->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
                    it.SetType(type);

                    return it;
                }

                void Update();
                void UpdateGoInformation();
                void OnAfterResize(int newWidth, int newHeight) override;
            };

            class GoFiles : public TabPage
            {
                inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
                inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

                const std::string_view format            = "%-16s (%s)";
                const std::string_view formatDescription = "%-16s (%s) %s";

                Reference<Object> object;
                Reference<PEFile> pe;
                Reference<AppCUI::Controls::ListView> list;

              public:
                GoFiles(Reference<Object> _object, Reference<PEFile> _pe);

                template <typename T>
                ListViewItem AddDecAndHexElement(
                      std::string_view name, std::string_view format, T value, ListViewItem::Type type = ListViewItem::Type::Normal)
                {
                    LocalString<1024> ls;
                    NumericFormatter nf;
                    NumericFormatter nf2;

                    // static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ', sizeof(T) * 2 };
                    static const auto hexBySize = NumericFormat{ NumericFormatFlags::HexPrefix, 16, 0, ' ' };

                    const auto v    = nf.ToString(value, dec);
                    const auto vHex = nf2.ToString(value, hexBySize);
                    auto it         = list->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
                    it.SetType(type);

                    return it;
                }

                void Update();
                void UpdateGoFiles();
                void OnAfterResize(int newWidth, int newHeight) override;
            };

            class GoFunctions : public AppCUI::Controls::TabPage
            {
                Reference<PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> list;
                int32 Base;

                std::string_view GetValue(NumericFormatter& n, uint64 value);
                void GoToSelectedSection();
                void SelectCurrentSection();

              public:
                GoFunctions(Reference<PEFile> pe, Reference<GView::View::WindowInterface> win);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };

            class OpCodes : public AppCUI::Controls::TabPage
            {
                Reference<PEFile> pe;
                Reference<Object> object;

                Reference<AppCUI::Controls::Label> value;
                Reference<AppCUI::Controls::ListView> list;
                AppCUI::Controls::ListViewItem all;
                AppCUI::Controls::ListViewItem header;
                AppCUI::Controls::ListViewItem call;
                AppCUI::Controls::ListViewItem lcall;
                AppCUI::Controls::ListViewItem jmp;
                AppCUI::Controls::ListViewItem ljmp;
                AppCUI::Controls::ListViewItem bp;
                AppCUI::Controls::ListViewItem fstart;
                AppCUI::Controls::ListViewItem fend;

                inline bool AllChecked();
                inline bool AllUnChecked();
                inline void SetMaskText();
                inline void SetConfig(bool checked, uint16 position);

              public:
                OpCodes(Reference<Object> object, Reference<GView::Type::PE::PEFile> pe);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
        }; // namespace Panels

        namespace Commands
        {
            class DigitalSignature : public AppCUI::Controls::Window
            {
              private:
                Reference<PEFile> pe;
                Reference<GView::View::WindowInterface> win;
                Reference<AppCUI::Controls::ListView> general;

                ListViewItem humanReadable;
                ListViewItem PEMs;

                inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
                inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

                void MoreInfo();

              public:
                DigitalSignature(Reference<PEFile> pe);

                void Update();
                bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
                bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
            };
        } // namespace Commands
    }     // namespace PE
} // namespace Type
} // namespace GView
