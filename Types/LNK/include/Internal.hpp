#pragma once

#include <GView.hpp>

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943?redirectedfrom=MSDN

namespace GView::Type::LNK
{
#define GET_PAIR_FROM_ENUM(x)                                                                                                              \
    {                                                                                                                                      \
        x, (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))                                                       \
    }

constexpr uint32 SIGNATURE           = 0x0000004C;
constexpr uint8 CLASS_IDENTIFIER[16] = { 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };

enum class FileAttributeFlags : uint32
{
    ReadOnly            = 0x00000001,
    Hidden              = 0x00000002,
    System              = 0x00000004,
    VolumeLabel         = 0x00000008,
    Directory           = 0x00000010,
    Archive             = 0x00000020,
    Device              = 0x00000040,
    Normal              = 0x00000080,
    Temporary           = 0x00000100,
    SparseFile          = 0x00000200,
    ReparsePoint        = 0x00000400,
    Compressed          = 0x00000800,
    Offline             = 0x00001000,
    NotContentIndexed   = 0x00002000,
    Encrypted           = 0x00004000,
    UnknownWindows95FAT = 0x00008000,
    Virtual             = 0x00010000,
};

static const std::map<FileAttributeFlags, std::string_view> FileAttributeFlagsNames{
    GET_PAIR_FROM_ENUM(FileAttributeFlags::ReadOnly),     GET_PAIR_FROM_ENUM(FileAttributeFlags::Hidden),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::System),       GET_PAIR_FROM_ENUM(FileAttributeFlags::VolumeLabel),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::Directory),    GET_PAIR_FROM_ENUM(FileAttributeFlags::Archive),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::Device),       GET_PAIR_FROM_ENUM(FileAttributeFlags::Normal),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::Temporary),    GET_PAIR_FROM_ENUM(FileAttributeFlags::SparseFile),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::ReparsePoint), GET_PAIR_FROM_ENUM(FileAttributeFlags::Compressed),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::Offline),      GET_PAIR_FROM_ENUM(FileAttributeFlags::NotContentIndexed),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::Encrypted),    GET_PAIR_FROM_ENUM(FileAttributeFlags::UnknownWindows95FAT),
    GET_PAIR_FROM_ENUM(FileAttributeFlags::Virtual)
};

static const std::map<FileAttributeFlags, std::string_view> FileAttributeFlagsDescriptions{
    { FileAttributeFlags::ReadOnly,
      "The file or directory is read-only. For a file, if this bit is set, applications can read the file but cannot write to it or delete "
      "it.For a directory, if this bit is set, applications cannot delete the directory" },
    { FileAttributeFlags::Hidden,
      "The file or directory is hidden. If this bit is set, the file or folder is not included in an ordinary directory listing." },
    { FileAttributeFlags::System, "The file or directory is part of the operating system or is used exclusively by the operating system." },
    { FileAttributeFlags::VolumeLabel, "A bit that MUST be zero. Is a volume label." },
    { FileAttributeFlags::Directory, "The link target is a directory instead of a file." },
    { FileAttributeFlags::Archive,
      "The file or directory is an archive file. Applications use this flag to mark files for backup or removal." },
    { FileAttributeFlags::Device, "A bit that MUST be zero. Is a device." },
    { FileAttributeFlags::Normal,
      "The file or directory has no other flags set. If this bit is 1, all other bits in this structure MUST be clear." },
    { FileAttributeFlags::Temporary, "The file is being used for temporary storage." },
    { FileAttributeFlags::SparseFile, "The file is a sparse file." },
    { FileAttributeFlags::ReparsePoint, "The file or directory has an associated reparse point." },
    { FileAttributeFlags::Compressed,
      "The file or directory is compressed. For a file, this means that all data in the file is compressed.For a directory, this means "
      "that compression is the default for newly created files and subdirectories." },
    { FileAttributeFlags::Offline, "The data of the file is not immediately available. It is stored on an offline storage." },
    { FileAttributeFlags::NotContentIndexed, "The contents of the file need to be indexed." },
    { FileAttributeFlags::Encrypted,
      "The file or directory is encrypted. For a file, this means that all data in the file is encrypted.For a directory, this means that "
      "encryption is the default for newly created files and subdirectories." },
    { FileAttributeFlags::UnknownWindows95FAT, "Unknown (seen on Windows 95 FAT)." },
    { FileAttributeFlags::Virtual, "Is virtual. Currently reserved for future use, not used by the LNK format." },
};

static const std::vector<FileAttributeFlags> GetFileAttributeFlags(uint32 flags)
{
    std::vector<FileAttributeFlags> output;

    for (const auto& data : FileAttributeFlagsNames)
    {
        const auto flag = static_cast<FileAttributeFlags>(static_cast<decltype(flags)>(data.first) & flags);
        if (flag == data.first)
        {
            output.emplace_back(flag);
        }
    }

    return output;
}

enum class ShowWindow : uint32
{
    Hide            = 0,
    Normal          = 1,
    ShowMinimized   = 2,
    Maximize        = 3,
    ShowNoActivate  = 4,
    Show            = 5,
    Minimize        = 6,
    ShowMinNoActive = 7,
    ShowNA          = 8,
    Restore         = 9,
    ShowDefault     = 10,
    ForceMinimize   = 11,
    NormalNA        = 12
};

static const std::map<ShowWindow, std::string_view> ShowWindowNames{
    GET_PAIR_FROM_ENUM(ShowWindow::Hide),           GET_PAIR_FROM_ENUM(ShowWindow::Normal),
    GET_PAIR_FROM_ENUM(ShowWindow::ShowMinimized),  GET_PAIR_FROM_ENUM(ShowWindow::Maximize),
    GET_PAIR_FROM_ENUM(ShowWindow::ShowNoActivate), GET_PAIR_FROM_ENUM(ShowWindow::Show),
    GET_PAIR_FROM_ENUM(ShowWindow::Minimize),       GET_PAIR_FROM_ENUM(ShowWindow::ShowMinNoActive),
    GET_PAIR_FROM_ENUM(ShowWindow::ShowNA),         GET_PAIR_FROM_ENUM(ShowWindow::Restore),
    GET_PAIR_FROM_ENUM(ShowWindow::ShowDefault),    GET_PAIR_FROM_ENUM(ShowWindow::ForceMinimize),
    GET_PAIR_FROM_ENUM(ShowWindow::NormalNA)
};

static const std::map<ShowWindow, std::string_view> ShowWindowDescriptions{
    { ShowWindow::Hide, "Hides the window and activates another window." },
    { ShowWindow::Normal,
      "Activates and displays the window. The window is restored to its original size and position if the window is minimized or "
      "maximized." },
    { ShowWindow::ShowMinimized, "Activates and minimizes the window." },
    { ShowWindow::Maximize, "Activates and maximizes the window" },
    { ShowWindow::ShowNoActivate, "Display the window in its most recent position and size without activating it." },
    { ShowWindow::Show, "Activates the window and displays it in its current size and position." },
    { ShowWindow::Minimize, "Minimizes the window and activates the next top-level windows (in order of depth (Z order))." },
    { ShowWindow::ShowMinNoActive, "Display the window as minimized without activating it." },
    { ShowWindow::ShowNA, "Display the window in its current size and position without activating it." },
    { ShowWindow::Restore,
      "Activates and displays the window. The window is restored to its original size and position if the window is minimized or "
      "maximized." },
    { ShowWindow::ShowDefault, "Set the show state based on the ShowWindow values specified during the creation of the process." },
    { ShowWindow::ForceMinimize, "Minimizes a window, even if the thread that owns the window is not responding." },
    { ShowWindow::NormalNA, "Undocumented according to wine project." },
};

enum class HotKeyHigh : uint8
{
    NONE    = 0x00,
    SHIFT   = 0x01,
    CONTROL = 0x02,
    ALT     = 0x04,
};

static const std::map<HotKeyHigh, std::string_view> HotKeyHighNames{ GET_PAIR_FROM_ENUM(HotKeyHigh::NONE),
                                                                     GET_PAIR_FROM_ENUM(HotKeyHigh::SHIFT),
                                                                     GET_PAIR_FROM_ENUM(HotKeyHigh::CONTROL),
                                                                     GET_PAIR_FROM_ENUM(HotKeyHigh::ALT) };

static const std::string GetHotKeyHighFromFlags(uint8 flags)
{
    static const std::initializer_list<HotKeyHigh> types{ HotKeyHigh::NONE, HotKeyHigh::SHIFT, HotKeyHigh::CONTROL, HotKeyHigh::ALT };

    std::string high;
    for (const auto& t : types)
    {
        if ((flags & static_cast<uint8>(t)) == static_cast<uint8>(t))
        {
            if (high.empty())
            {
                high += HotKeyHighNames.at(t);
            }
            else
            {
                high += " | ";
                high += HotKeyHighNames.at(t);
            }
        }
    }

    if (HotKeyHighNames.empty())
    {
        high = "NONE";
    }

    return high;
};

enum class HotKeyLow : uint8
{
    NONE    = 0x00,
    _0      = 0x30,
    _1      = 0x31,
    _2      = 0x32,
    _3      = 0x33,
    _4      = 0x34,
    _5      = 0x35,
    _6      = 0x36,
    _7      = 0x37,
    _8      = 0x38,
    _9      = 0x39,
    A       = 0x41,
    B       = 0x42,
    C       = 0x43,
    D       = 0x44,
    E       = 0x45,
    F       = 0x46,
    G       = 0x47,
    H       = 0x48,
    I       = 0x49,
    J       = 0x4A,
    K       = 0x4B,
    L       = 0x4C,
    M       = 0x4D,
    N       = 0x4E,
    O       = 0x4F,
    P       = 0x50,
    Q       = 0x51,
    R       = 0x52,
    S       = 0x53,
    T       = 0x54,
    U       = 0x55,
    V       = 0x56,
    W       = 0x57,
    X       = 0x58,
    Y       = 0x59,
    Z       = 0x5A,
    F1      = 0x70,
    F2      = 0x71,
    F3      = 0x72,
    F4      = 0x73,
    F5      = 0x74,
    F6      = 0x75,
    F7      = 0x76,
    F8      = 0x77,
    F9      = 0x78,
    F10     = 0x79,
    F11     = 0x7A,
    F12     = 0x7B,
    F13     = 0x7C,
    F14     = 0x7D,
    F15     = 0x7E,
    F16     = 0x7F,
    F17     = 0x80,
    F18     = 0x81,
    F19     = 0x82,
    F20     = 0x83,
    F21     = 0x84,
    F22     = 0x85,
    F23     = 0x86,
    F24     = 0x87,
    NumLock = 0x90,
    Scroll  = 0x91,
};

static const std::map<HotKeyLow, std::string_view> HotKeyLowNames{
    GET_PAIR_FROM_ENUM(HotKeyLow::NONE), GET_PAIR_FROM_ENUM(HotKeyLow::_0),      GET_PAIR_FROM_ENUM(HotKeyLow::_1),
    GET_PAIR_FROM_ENUM(HotKeyLow::_2),   GET_PAIR_FROM_ENUM(HotKeyLow::_3),      GET_PAIR_FROM_ENUM(HotKeyLow::_4),
    GET_PAIR_FROM_ENUM(HotKeyLow::_5),   GET_PAIR_FROM_ENUM(HotKeyLow::_6),      GET_PAIR_FROM_ENUM(HotKeyLow::_7),
    GET_PAIR_FROM_ENUM(HotKeyLow::_8),   GET_PAIR_FROM_ENUM(HotKeyLow::_9),      GET_PAIR_FROM_ENUM(HotKeyLow::A),
    GET_PAIR_FROM_ENUM(HotKeyLow::B),    GET_PAIR_FROM_ENUM(HotKeyLow::C),       GET_PAIR_FROM_ENUM(HotKeyLow::D),
    GET_PAIR_FROM_ENUM(HotKeyLow::E),    GET_PAIR_FROM_ENUM(HotKeyLow::F),       GET_PAIR_FROM_ENUM(HotKeyLow::G),
    GET_PAIR_FROM_ENUM(HotKeyLow::H),    GET_PAIR_FROM_ENUM(HotKeyLow::I),       GET_PAIR_FROM_ENUM(HotKeyLow::J),
    GET_PAIR_FROM_ENUM(HotKeyLow::K),    GET_PAIR_FROM_ENUM(HotKeyLow::L),       GET_PAIR_FROM_ENUM(HotKeyLow::M),
    GET_PAIR_FROM_ENUM(HotKeyLow::N),    GET_PAIR_FROM_ENUM(HotKeyLow::O),       GET_PAIR_FROM_ENUM(HotKeyLow::P),
    GET_PAIR_FROM_ENUM(HotKeyLow::Q),    GET_PAIR_FROM_ENUM(HotKeyLow::R),       GET_PAIR_FROM_ENUM(HotKeyLow::S),
    GET_PAIR_FROM_ENUM(HotKeyLow::T),    GET_PAIR_FROM_ENUM(HotKeyLow::U),       GET_PAIR_FROM_ENUM(HotKeyLow::V),
    GET_PAIR_FROM_ENUM(HotKeyLow::W),    GET_PAIR_FROM_ENUM(HotKeyLow::X),       GET_PAIR_FROM_ENUM(HotKeyLow::Y),
    GET_PAIR_FROM_ENUM(HotKeyLow::Z),    GET_PAIR_FROM_ENUM(HotKeyLow::F1),      GET_PAIR_FROM_ENUM(HotKeyLow::F2),
    GET_PAIR_FROM_ENUM(HotKeyLow::F3),   GET_PAIR_FROM_ENUM(HotKeyLow::F4),      GET_PAIR_FROM_ENUM(HotKeyLow::F5),
    GET_PAIR_FROM_ENUM(HotKeyLow::F6),   GET_PAIR_FROM_ENUM(HotKeyLow::F7),      GET_PAIR_FROM_ENUM(HotKeyLow::F8),
    GET_PAIR_FROM_ENUM(HotKeyLow::F9),   GET_PAIR_FROM_ENUM(HotKeyLow::F10),     GET_PAIR_FROM_ENUM(HotKeyLow::F11),
    GET_PAIR_FROM_ENUM(HotKeyLow::F12),  GET_PAIR_FROM_ENUM(HotKeyLow::F13),     GET_PAIR_FROM_ENUM(HotKeyLow::F14),
    GET_PAIR_FROM_ENUM(HotKeyLow::F15),  GET_PAIR_FROM_ENUM(HotKeyLow::F16),     GET_PAIR_FROM_ENUM(HotKeyLow::F17),
    GET_PAIR_FROM_ENUM(HotKeyLow::F18),  GET_PAIR_FROM_ENUM(HotKeyLow::F19),     GET_PAIR_FROM_ENUM(HotKeyLow::F20),
    GET_PAIR_FROM_ENUM(HotKeyLow::F21),  GET_PAIR_FROM_ENUM(HotKeyLow::F22),     GET_PAIR_FROM_ENUM(HotKeyLow::F23),
    GET_PAIR_FROM_ENUM(HotKeyLow::F24),  GET_PAIR_FROM_ENUM(HotKeyLow::NumLock), GET_PAIR_FROM_ENUM(HotKeyLow::Scroll)
};

struct HotKey
{
    uint8 high;
    HotKeyLow low;
};

enum class LinkFlags : uint32
{
    HasTargetIDList             = 0x00000001,
    HasLinkInfo                 = 0x00000002,
    HasName                     = 0x00000004,
    HasRelativePath             = 0x00000008,
    HasWorkingDir               = 0x00000010,
    HasArguments                = 0x00000020,
    HasIconLocation             = 0x00000040,
    IsUnicode                   = 0x00000080,
    ForceNoLinkInfo             = 0x00000100,
    HasExpString                = 0x00000200,
    RunInSeparateProcess        = 0x00000400,
    Unknown0                    = 0x00000800,
    HasDarwinID                 = 0x00001000,
    RunAsUser                   = 0x00002000,
    HasExpIcon                  = 0x00004000,
    NoPidlAlias                 = 0x00008000,
    Unknown1                    = 0x00010000,
    RunWithShimLayer            = 0x00020000,
    ForceNoLinkTrack            = 0x00040000,
    EnableTargetMetadata        = 0x00080000,
    DisableLinkPathTracking     = 0x00100000,
    DisableKnownFolderTracking  = 0x00200000,
    DisableKnownFolderAlias     = 0x00400000,
    AllowLinkToLink             = 0x00800000,
    UnaliasOnSave               = 0x01000000,
    PreferEnvironmentPath       = 0x02000000,
    KeepLocalIDListForUNCTarget = 0x04000000,
};

static const std::map<LinkFlags, std::string_view> LinkFlagsNames{ GET_PAIR_FROM_ENUM(LinkFlags::HasTargetIDList),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasLinkInfo),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasName),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasRelativePath),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasWorkingDir),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasArguments),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasIconLocation),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::IsUnicode),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::ForceNoLinkInfo),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasExpString),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::RunInSeparateProcess),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::Unknown0),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasDarwinID),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::RunAsUser),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::HasExpIcon),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::NoPidlAlias),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::Unknown1),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::RunWithShimLayer),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::ForceNoLinkTrack),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::EnableTargetMetadata),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::DisableLinkPathTracking),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::DisableKnownFolderTracking),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::DisableKnownFolderAlias),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::AllowLinkToLink),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::UnaliasOnSave),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::PreferEnvironmentPath),
                                                                   GET_PAIR_FROM_ENUM(LinkFlags::KeepLocalIDListForUNCTarget) };

static const std::map<LinkFlags, std::string_view> LinkFlagsDescriptions{
    { LinkFlags::HasTargetIDList,
      "The shell link is saved with an item ID list (IDList). If this bit is set, a LinkTargetIDList structure MUST follow the "
      "ShellLinkHeader. If this bit is not set, this structure MUST NOT be present." },
    { LinkFlags::HasLinkInfo,
      "The shell link is saved with link information. If this bit is set, a LinkInfo structure MUST be present.If this bit is not "
      "set, "
      "this structure MUST NOT be present." },
    { LinkFlags::HasName,
      "The shell link is saved with a name string. If this bit is set, a NAME_STRING StringData structure MUST be present.If this "
      "bit is "
      "not set, this structure MUST NOT be present" },
    { LinkFlags::HasRelativePath,
      "The shell link is saved with a relative path string. If this bit is set, a RELATIVE_PATH StringData structure MUST be "
      "present.If "
      "this bit is not set, this structure MUST NOT be present." },
    { LinkFlags::HasWorkingDir,
      "The shell link is saved with a working directory string. If this bit is set, a WORKING_DIR StringData structure MUST be "
      "present.If "
      "this bit is not set, this structure MUST NOT be present." },
    { LinkFlags::HasArguments,
      "The shell link is saved with command line arguments. If this bit is set, a COMMAND_LINE_ARGUMENTS StringData structure MUST "
      "be "
      "present.If this bit is not set, this structure MUST NOT be present." },
    { LinkFlags::HasIconLocation,
      "The shell link is saved with an icon location string. If this bit is set, an ICON_LOCATION StringData structure MUST be "
      "present.If "
      "this bit is not set, this structure MUST NOT be present." },
    { LinkFlags::IsUnicode,
      "The shell link contains Unicode encoded strings. This bit SHOULD be set. If this bit is set, the StringData section contains "
      "Unicode - encoded strings; otherwise, it contains strings that are encoded using the system default code page." },
    { LinkFlags::ForceNoLinkInfo, "The LinkInfo structure is ignored." },
    { LinkFlags::HasExpString, "The shell link is saved with an EnvironmentVariableDataBlock." },
    { LinkFlags::RunInSeparateProcess,
      "The target is run in a separate virtual machine when launching a link target that is a 16 - bit application." },
    { LinkFlags::Unknown0, "A bit that is undefined and MUST be ignored." },
    { LinkFlags::HasDarwinID, "The shell link is saved with a DarwinDataBlock." },
    { LinkFlags::RunAsUser, "The application is run as a different user when the target of the shell link is activated." },
    { LinkFlags::HasExpIcon, "The shell link is saved with an IconEnvironmentDataBlock." },
    { LinkFlags::NoPidlAlias,
      "The file system location is represented in the shell namespace when the path to an item is parsed into an IDList." },
    { LinkFlags::Unknown1, "A bit that is undefined and MUST be ignored." },
    { LinkFlags::RunWithShimLayer, "The shell link is saved with a ShimDataBlock." },
    { LinkFlags::ForceNoLinkTrack, "The TrackerDataBlock is ignored." },
    { LinkFlags::EnableTargetMetadata,
      "The shell link attempts to collect target properties and store them in the PropertyStoreDataBlock when the link target is set." },
    { LinkFlags::DisableLinkPathTracking, "The EnvironmentVariableDataBlock is ignored." },
    { LinkFlags::DisableKnownFolderTracking,
      "The SpecialFolderDataBlock) and the KnownFolderDataBlock (section 2.5.6) are ignored when loading the shell link.If this bit is "
      "set, these extra data blocks SHOULD NOT be saved when saving the shell link." },
    { LinkFlags::DisableKnownFolderAlias,
      "If the link has a KnownFolderDataBlock, the unaliased form of the known folder IDList SHOULD be used when translating the target "
      "IDList at the time that the link is loaded." },
    { LinkFlags::AllowLinkToLink,
      "Creating a link that references another link is enabled. Otherwise, specifying a link as the target IDList SHOULD NOT be allowed." },
    { LinkFlags::UnaliasOnSave,
      "When saving a link for which the target IDList is under a known folder, either the unaliased form of that known folder or the "
      "target IDList SHOULD be used." },
    { LinkFlags::PreferEnvironmentPath,
      "The target IDList SHOULD NOT be stored; instead, the path specified in the EnvironmentVariableDataBlock SHOULD be used to refer to "
      "the target." },
    { LinkFlags::KeepLocalIDListForUNCTarget,
      "When the target is a UNC name that refers to a location on a local machine, the local path IDList in the PropertyStoreDataBlock "
      "SHOULD be stored, so it can be used when the link is loaded on the local machine." }
};

static const std::vector<LinkFlags> GetLinkFlags(uint32 flags)
{
    std::vector<LinkFlags> output;

    for (const auto& data : LinkFlagsNames)
    {
        const auto flag = static_cast<LinkFlags>(static_cast<decltype(flags)>(data.first) & flags);
        if (flag == data.first)
        {
            output.emplace_back(flag);
        }
    }

    return output;
}

#pragma pack(push, 4)
struct Header
{
    uint32 headerSize;
    uint8 classIdentifier[16];
    uint32 linkFlags;
    uint32 fileAttributeFlags;
    uint64 creationDate;
    uint64 lastAccessDate;
    uint64 lastModificationDate;
    uint32 filesize;
    int32 iconIndex;
    ShowWindow showCommand;
    HotKey hotKey;
    uint16 unknown0;
    uint32 unknown1;
    uint32 unknown2;
};
#pragma pack(pop)

static_assert(sizeof(Header) == 76);

struct ShellItem
{
    uint16 size;
    uint8 type;
    uint8 data[0];
};

struct ItemID
{
    uint16 ItemIDSize;
    uint8 data[0];
};

struct IDList
{
    // ItemID ItemIDList;
    uint16 TerminalID;
};

struct LinkTargetIDList
{
    uint16 IDListSize;
    // uint8 IDList[0];
};

} // namespace GView::Type::LNK
