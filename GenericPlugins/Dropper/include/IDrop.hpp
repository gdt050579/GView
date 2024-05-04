#pragma once

#include "GView.hpp"

using namespace GView::Utils;

namespace GView::GenericPlugins::Droppper
{
static const uint8 MAX_PRECACHED_BUFFER_SIZE = 8;

enum class Result : uint32 {
    NotFound = 0, // -> nothing found
    Buffer,       // -> artefact found -> drop it as a buffer
    Ascii,        // -> artefact found -> drop it as ascii
    Unicode,      // -> artefact found -> drop it as unicode (skip 0)
};

static const std::map<Result, std::string_view> RESULT_MAP{
    { Result::NotFound, "Not Found" },
    { Result::Buffer, "Buffer" },
    { Result::Ascii, "Ascii" },
    { Result::Unicode, "Unicode" },
};

enum class Priority : uint32 { Binary = 0, Text = 1, Count = 2 };

enum class Category : uint32 {
    Archives       = 0,
    Cryptographic  = 1,
    Executables    = 2,
    HtmlObjects    = 3,
    Image          = 4,
    Multimedia     = 5,
    SpecialStrings = 6,
};

enum class Subcategory : uint32 {
    // invalid/none
    None = 0,

    // Archives
    MSCAB = 1,
    RAR   = 2,
    ZIP   = 3,

    // Cryptographic
    CRC16Table,
    CRC16Table8bit1,
    CRC16Table8bit2,
    CRC32Table,
    CRC64Table,
    MD5InitValues,
    SHA1InitValues,
    ZinflateLengthStarts,
    ZinflateLengthExtraBits,
    ZinflateDistanceStarts,
    ZinflateDistanceExtraBits,
    ZdeflateLengthCodes,
    BlowfishPInit,
    BlowfishSInit,
    RijndaelTe0,
    RijndaelTe1,
    RijndaelTe2,
    RijndaelTe3,
    RijndaelTe4,
    RijndaelTd0,
    RijndaelTd1,
    RijndaelTd2,
    RijndaelTd3,
    RijndaelTd4,
    RC2PITABLE,
    PKCSDigestDecorationMD2,
    PKCSDigestDecorationMD5,
    PKCSDigestDecorationRIPEMD160,
    PKCSDigestDecorationTiger,
    PKCSDigestDecorationSHA256,
    PKCSDigestDecorationSHA384,
    PKCSDigestDecorationSHA512,
    RC6Stub,

    // Executables
    MZPE,
    MachO,
    MachOFat,
    COFF,
    ELF,

    // HTML Objects
    IFrame,
    Script,
    XML,

    // Images
    BMP,
    JPG,
    PNG,
    GIF,

    // Multimedia
    RIFF,
    SWF,

    // Special Strings
    Email,
    Filepath,
    IP,
    Registry,
    URL,
    Wallet,

    // Plain simple text
    Text,
};

static const std::map<Category, std::string_view> OBJECT_CATEGORY_MAP{
    { Category::Archives, "Archives" },
    { Category::Cryptographic, "Cryptographic" },
    { Category::Executables, "Executables" },
    { Category::HtmlObjects, "HtmlObjects" },
    { Category::Image, "Image" },
    { Category::Multimedia, "Multimedia" },
    { Category::SpecialStrings, "Special Strings" },
};

static const std::map<Category, std::string_view> OBJECT_DECRIPTION_MAP{
    { Category::Archives, "Identifies various archive formats." },
    { Category::Cryptographic, "Identifies various cryptographic tables or magics." },
    { Category::Executables, "Identifies various executables formats." },
    { Category::HtmlObjects, "Identifies various objects usually embedded into HTMLs files." },
    { Category::Image, "Indentifies various image file formats." },
    { Category::Multimedia, "Identifies various multimedia formats." },
    { Category::SpecialStrings, "Identifies special string classes (IPs, URLs, etc.)." },
};

static const std::map<Category, ColorPair> OBJECT_CATEGORY_COLOR_MAP{
    { Category::Archives, ColorPair{ .Foreground = Color::White, .Background = Color::Black } },
    { Category::Cryptographic, ColorPair{ .Foreground = Color::White, .Background = Color::DarkGreen } },
    { Category::Executables, ColorPair{ .Foreground = Color::White, .Background = Color::Teal } },
    { Category::HtmlObjects, ColorPair{ .Foreground = Color::White, .Background = Color::DarkRed } },
    { Category::Image, ColorPair{ .Foreground = Color::White, .Background = Color::Magenta } },
    { Category::Multimedia, ColorPair{ .Foreground = Color::White, .Background = Color::Olive } },
    { Category::SpecialStrings, ColorPair{ .Foreground = Color::Black, .Background = Color::Silver } },
};

struct Metadata {
    const std::string_view name;
    const std::string_view description;
    const bool availability;
};

typedef std::map<Subcategory, Metadata> TypesMap;

static const std::string_view DEFAULT_CRC_DESCRIPTION{ "A cyclic redundancy check (CRC) is an error-detecting code commonly used in digital networks and "
                                                       "storage devices to detect accidental changes to digital data." };
static const std::string_view MISSING_DESCRIPTION{ "Missing description." };

static const TypesMap TYPES_MAP{

    // archives
    { Subcategory::MSCAB,
      { "MSCAB",
        "Cabinet (or CAB) is an archive-file format for Microsoft Windows that supports lossless data compression and embedded digital certificates used for "
        "maintaining archive integrity.",
        false } },
    { Subcategory::RAR, { "RAR", "RAR is a proprietary archive file format that supports data compression, error correction and file spanning.", false } },
    { Subcategory::ZIP, { "ZIP", "ZIP is an archive file format that supports lossless data compression.", false } },

    // cryptographic
    { Subcategory::CRC16Table, { "CRC 16 Table", DEFAULT_CRC_DESCRIPTION, false } },
    { Subcategory::CRC16Table8bit1, { "CRC 16 Table (8 bit - 1)", DEFAULT_CRC_DESCRIPTION, false } },
    { Subcategory::CRC16Table8bit2, { "CRC 16 Table (8 bit - 2)", DEFAULT_CRC_DESCRIPTION, false } },
    { Subcategory::CRC32Table, { "CRC 32 Table", DEFAULT_CRC_DESCRIPTION, false } },
    { Subcategory::CRC64Table, { "CRC 64 Table", DEFAULT_CRC_DESCRIPTION, false } },
    { Subcategory::MD5InitValues, { "MD5 Init Values", MISSING_DESCRIPTION, false } },
    { Subcategory::SHA1InitValues, { "SHA1 Init Values", MISSING_DESCRIPTION, false } },
    { Subcategory::ZinflateLengthStarts, { "Zinflate LengthStarts", MISSING_DESCRIPTION, false } },
    { Subcategory::ZinflateLengthExtraBits, { "Zinflate LengthExtraBits", MISSING_DESCRIPTION, false } },
    { Subcategory::ZinflateDistanceStarts, { "Zinflate DistanceStarts", MISSING_DESCRIPTION, false } },
    { Subcategory::ZinflateDistanceExtraBits, { "Zinflate DistanceExtraBits", MISSING_DESCRIPTION, false } },
    { Subcategory::ZdeflateLengthCodes, { "Zdeflate LengthCodes", MISSING_DESCRIPTION, false } },
    { Subcategory::BlowfishPInit, { "Blowfish P-Init", MISSING_DESCRIPTION, false } },
    { Subcategory::BlowfishSInit, { "Blowfish S-Init", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTe0, { "Rijndael Te0", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTe1, { "Rijndael Te1", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTe2, { "Rijndael Te2", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTe3, { "Rijndael Te3", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTe4, { "Rijndael Te4", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTd0, { "Rijndael Td0", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTd1, { "Rijndael Td1", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTd2, { "Rijndael Td2", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTd3, { "Rijndael Td3", MISSING_DESCRIPTION, false } },
    { Subcategory::RijndaelTd4, { "Rijndael Td4", MISSING_DESCRIPTION, false } },
    { Subcategory::RC2PITABLE, { "RC2 PITABLE", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationMD2, { "PKCS DigestDecoration MD2", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationMD5, { "PKCS DigestDecoration MD5", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationRIPEMD160, { "PKCS DigestDecoration RIPEMD160", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationTiger, { "PKCS DigestDecoration Tiger", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationSHA256, { "PKCS DigestDecoration SHA256", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationSHA384, { "PKCS DigestDecoration SHA384", MISSING_DESCRIPTION, false } },
    { Subcategory::PKCSDigestDecorationSHA512, { "PKCS DigestDecoration SHA512", MISSING_DESCRIPTION, false } },
    { Subcategory::RC6Stub, { "RC6 Stub", MISSING_DESCRIPTION, false } },

    // Executables
    { Subcategory::MZPE,
      { "MZPE",
        "Portable Executable (PE) format is a file format for executables, object code, DLLs and others used in 32-bit and 64-bit versions of Windows "
        "operating systems, and in UEFI environments.",
        true } },
    { Subcategory::MachO,
      { "Mach-O",
        "Mach-O, short for Mach object file format, is a file format for executables, object code, shared libraries, dynamically loaded code, and core dumps. "
        "It was developed to replace the a.out format. Mach-O is used by some systems based on the Mach kernel.NeXTSTEP, macOS, and iOS.",
        false } },
    { Subcategory::MachOFat,
      { "Mach-O Fat", "A fat binary is an uncompressed archive format to embed more than one standalone Mach-O object in a single file.", false } },
    { Subcategory::COFF,
      { "COFF",
        "The Common Object File Format (COFF) is a format for executable, object code, and shared library computer files used on Unix systems. It was "
        "introduced in Unix System V, replaced the previously used a.out format, and formed the basis for extended specifications such as XCOFF and ECOFF, "
        "before being largely replaced by ELF, introduced with SVR4. COFF and its variants continue to be used on some Unix-like systems, on Microsoft Windows "
        "(Portable Executable), in UEFI environments and in some embedded development systems.",
        false } },
    { Subcategory::ELF,
      { "ELF",
        "ELF is short for Executable and Linkable Format. It's a format used for storing binaries, libraries, and core dumps on disks in Linux and Unix-based "
        "systems.",
        false } },

    // html objects
    { Subcategory::IFrame,
      { "IFrame",
        "An inline frame (iframe) is a HTML element that loads another HTML page within the document. It essentially puts another webpage within the parent "
        "page.",
        true } },
    { Subcategory::Script,
      { "Script", "The <script> HTML element is used to embed executable code or data; this is typically used to embed or refer to JavaScript code. ", true } },
    { Subcategory::XML,
      { "XML", "Extensible Markup Language (XML) is a markup language and file format for storing, transmitting, and reconstructing arbitrary data.", true } },

    // images
    { Subcategory::BMP,
      { "BMP",
        "The BMP file format or bitmap, is a raster graphics image file format used to store bitmap digital images, independently of the display device.",
        false } },
    { Subcategory::JPG,
      { "JPG",
        "JP(E)G (Joint Photographic Experts Group) is a commonly used method of lossy compression for digital images, particularly "
        "for those images produced by digital photography.",
        false } },
    { Subcategory::PNG, { "PNG", "Portable Network Graphics is a raster-graphics file format that supports lossless data compression.", true } },
    { Subcategory::GIF,
      { "GIF",
        "GIF stands for Graphics Interchange Format. GIF is a raster file format designed for relatively basic images that appear mainly on the internet.",
        false } },

    // multimedia
    { Subcategory::RIFF,
      { "RIFF",
        "Resource Interchange File Format (RIFF) is a generic file container format for storing data in tagged chunks. It is primarily used for audio and "
        "video, though it can be used for arbitrary data.",
        false } },
    { Subcategory::SWF, { "SWF", "SWF is a defunct Adobe Flash file format that was used for multimedia, vector graphics and ActionScript.", false } },

    // special strings
    { Subcategory::Email, { "Email address", "An email address identifies an email box to which messages are delivered.", true } },
    { Subcategory::Filepath, { "Filepath", "A path is a string of characters used to uniquely identify a location in a directory structure.", true } },
    { Subcategory::IP,
      { "IP address",
        "An Internet Protocol address is a numerical label such as 192.0.2.1 that is assigned to a device connected to a computer network that uses the "
        "Internet Protocol for communication.",
        true } },
    { Subcategory::Registry,
      { "Registry entry",
        "The Windows Registry is a hierarchical database that stores low-level settings for the Microsoft Windows operating system and for applications that "
        "opt to use the registry.",
        true } },
    { Subcategory::URL,
      { "URL",
        "A uniform resource locator, colloquially known as an address on the Web, is a reference to a resource that specifies its location on a computer "
        "network and a mechanism for retrieving it.",
        true } },
    { Subcategory::Wallet,
      { "Wallet address",
        "A wallet address, a unique identifier in the blockchain, is a randomly generated series of alphanumeric characters that corresponds to a specific "
        "cryptocurrency stored in a blockchain wallet.",
        true } },
};

static const std::map<Category, std::vector<Subcategory>> CATEGORY_TO_SUBCATEGORY_MAP{
    { Category::Archives, { Subcategory::MSCAB, Subcategory::RAR, Subcategory::ZIP } },
    { Category::Cryptographic,
      {
            Subcategory::CRC16Table,
            Subcategory::CRC16Table8bit1,
            Subcategory::CRC16Table8bit2,
            Subcategory::CRC32Table,
            Subcategory::CRC64Table,
            Subcategory::MD5InitValues,
            Subcategory::SHA1InitValues,
            Subcategory::ZinflateLengthStarts,
            Subcategory::ZinflateLengthExtraBits,
            Subcategory::ZinflateDistanceStarts,
            Subcategory::ZinflateDistanceExtraBits,
            Subcategory::ZdeflateLengthCodes,
            Subcategory::BlowfishPInit,
            Subcategory::BlowfishSInit,
            Subcategory::RijndaelTe0,
            Subcategory::RijndaelTe1,
            Subcategory::RijndaelTe2,
            Subcategory::RijndaelTe3,
            Subcategory::RijndaelTe4,
            Subcategory::RijndaelTd0,
            Subcategory::RijndaelTd1,
            Subcategory::RijndaelTd2,
            Subcategory::RijndaelTd3,
            Subcategory::RijndaelTd4,
            Subcategory::RC2PITABLE,
            Subcategory::PKCSDigestDecorationMD2,
            Subcategory::PKCSDigestDecorationMD5,
            Subcategory::PKCSDigestDecorationRIPEMD160,
            Subcategory::PKCSDigestDecorationTiger,
            Subcategory::PKCSDigestDecorationSHA256,
            Subcategory::PKCSDigestDecorationSHA384,
            Subcategory::PKCSDigestDecorationSHA512,
            Subcategory::RC6Stub,
      } },
    { Category::Executables, { Subcategory::MZPE, Subcategory::MachO, Subcategory::MachOFat, Subcategory::COFF, Subcategory::ELF } },
    { Category::HtmlObjects, { Subcategory::IFrame, Subcategory::Script, Subcategory::XML } },
    { Category::Image, { Subcategory::BMP, Subcategory::JPG, Subcategory::PNG, Subcategory::GIF } },
    { Category::Multimedia, { Subcategory::RIFF, Subcategory::SWF } },
    { Category::SpecialStrings, { Subcategory::Email, Subcategory::Filepath, Subcategory::IP, Subcategory::Registry, Subcategory::URL, Subcategory::Wallet } },
};

class IDrop
{
  public:
    // virtual methods
    virtual const std::string_view GetName() const            = 0; // specific dropper mini-plugin name
    virtual Category GetGroup() const                         = 0; // archive type recognizer, executables type, etc
    virtual Subcategory GetSubGroup() const                   = 0; // specific subgroup from each category
    virtual const std::string_view GetOutputExtension() const = 0; // dropped file extension
    virtual Priority GetPriority() const                      = 0; // get plugin priority
    virtual bool ShouldGroupInOneFile() const                 = 0; // URLs, IPs, etc

    // prechachedBufferSize -> max 8
    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) = 0;

    // helpers
    inline bool IsMagicU16(BufferView precachedBuffer, uint16 magic) const
    {
        if (precachedBuffer.GetLength() >= 2) {
            return *reinterpret_cast<const uint16*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline bool IsMagicU32(BufferView precachedBuffer, uint32 magic) const
    {
        if (precachedBuffer.GetLength() >= 4) {
            return *reinterpret_cast<const uint32*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline bool IsMagicU64(BufferView precachedBuffer, uint64 magic) const
    {
        if (precachedBuffer.GetLength() >= 8) {
            return *reinterpret_cast<const uint64*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline static bool IsAsciiPrintable(char c)
    {
        return 0x20 <= c && c <= 0x7e;
    }
};
} // namespace GView::GenericPlugins::Droppper
