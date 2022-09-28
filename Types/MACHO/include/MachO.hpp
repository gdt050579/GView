#pragma once

#include "Utils.hpp"
#include "Swap.hpp"

namespace GView::Type::MachO
{

static constexpr auto INS_CALL_COLOR  = ColorPair{ Color::White, Color::DarkGreen };
static constexpr auto INS_LCALL_COLOR = ColorPair{ Color::Red, Color::DarkGreen };

static constexpr auto INS_JUMP_COLOR  = ColorPair{ Color::White, Color::DarkRed };
static constexpr auto INS_LJUMP_COLOR = ColorPair{ Color::Yellow, Color::DarkRed };

static constexpr auto INS_BREAKPOINT_COLOR = ColorPair{ Color::Magenta, Color::DarkBlue };

static constexpr auto START_FUNCTION_COLOR = ColorPair{ Color::White, Color::Teal };
static constexpr auto END_FUNCTION_COLOR   = ColorPair{ Color::Yellow, Color::Teal };

static constexpr auto EXE_MARKER_COLOR = ColorPair{ Color::Yellow, Color::DarkRed };

namespace Panels
{
    enum class IDs : uint8
    {
        Information   = 0x0,
        LoadCommands  = 0x1,
        Segments      = 0x2,
        Sections      = 0x3,
        DyldInfo      = 0x4,
        Dylib         = 0x5,
        DySymTab      = 0x6,
        GoInformation = 0x7,
        OpCodes       = 0x8,
    };
};

class MachOFile : public TypeInterface,
                  public View::BufferViewer::OffsetTranslateInterface,
                  public View::ContainerViewer::EnumerateInterface,
                  public View::ContainerViewer::OpenItemInterface,
                  public GView::View::BufferViewer::PositionToColorInterface
{
  public:
    struct Colors
    {
        const ColorPair header{ Color::Olive, Color::Transparent };
        const ColorPair loadCommand{ Color::Magenta, Color::Transparent };
        const ColorPair section{ Color::Silver, Color::Transparent };
        const ColorPair linkEdit{ Color::Teal, Color::Transparent };
        const ColorPair arch{ Color::Magenta, Color::Transparent };
        const ColorPair objectName{ Color::DarkRed, Color::Transparent };
        const ColorPair object{ Color::Silver, Color::Transparent };
    } colors;

    struct LoadCommand
    {
        MAC::load_command value;
        uint64_t offset;
    };

    struct Section
    {
        char sectname[16]; /* name of this section */
        char segname[16];  /* segment this section goes in */
        uint64 addr;       /* memory address of this section */
        uint64 size;       /* size in bytes of this section */
        uint32 offset;     /* file offset of this section */
        uint32 align;      /* section alignment (power of 2) */
        uint32 reloff;     /* file offset of relocation entries */
        uint32 nreloc;     /* number of relocation entries */
        uint32 flags;      /* flags (section type and attributes)*/
        uint32 reserved1;  /* reserved (for offset or index) */
        uint32 reserved2;  /* reserved (for count or sizeof) */
        uint32 reserved3;  /* reserved */
    };

    struct Segment
    {
        MAC::LoadCommandType cmd; /* LC_SEGMENT(_64) */
        uint32 cmdsize;           /* includes sizeof section_64 structs */
        char segname[16];         /* segment name */
        uint64 vmaddr;            /* memory address of this segment */
        uint64 vmsize;            /* memory size of this segment */
        uint64 fileoff;           /* file offset of this segment */
        uint64 filesize;          /* amount to map from the file */
        uint32 maxprot;           /* maximum VM protection */
        uint32 initprot;          /* initial VM protection */
        uint32 nsects;            /* number of sections in segment */
        uint32 flags;             /* flags */

        std::vector<Section> sections;
    };

    struct Dylib
    {
        MAC::dylib_command value;
        std::string name;
        uint64_t offset;
    };

    struct MyNList
    {
        uint32_t n_strx;  /* index into the string table */
        uint8_t n_type;   /* type flag, see below */
        uint8_t n_sect;   /* section number or NO_SECT */
        uint16_t n_desc;  /* see <mach-o/stab.h> -> description field */
        uint64_t n_value; /* value of this symbol (or stab offset) */

        std::string symbolNameDemangled;
    };

    struct DySymTab
    {
        MAC::symtab_command sc;
        std::vector<MyNList> objects;
    };

    struct CodeSignature
    {
        MAC::linkedit_data_command ledc;
        MAC::CS_SuperBlob superBlob;
        std::vector<MAC::CS_BlobIndex> blobs;
        MAC::CS_CodeDirectory codeDirectory;
        std::string codeDirectoryIdentifier;
        std::string cdHash;
        std::vector<std::pair<std::string, std::string>> cdSlotsHashes; // per normal slots
        std::vector<MAC::CS_CodeDirectory> alternateDirectories;
        std::vector<std::string> alternateDirectoriesIdentifiers;
        std::vector<std::string> acdHashes;
        std::vector<std::vector<std::pair<std::string, std::string>>> acdSlotsHashes; // per normal slots

        struct
        {
            MAC::CS_RequirementsBlob blob;
            Buffer data;
        } requirements;

        struct
        {
            MAC::CS_GenericBlob blob;
            std::string data;
        } entitlements;

        struct
        {
            uint64 offset;
            uint64 size;

            bool errorHumanReadable = false;
            String humanReadable;

            bool errorPEMs = false;
            String PEMs[DigitalSignature::MAX_SIZE_IN_CONTAINER];
            uint32 PEMsCount = 0;

            bool errorSig = false;
            DigitalSignature::Signature sig;
        } signature;
    };

  public:
    /* Universal/Fat*/
    MAC::fat_header fatHeader;
    std::vector<MAC::Arch> archs;

    /* MachO */
    MAC::mach_header header;
    std::vector<LoadCommand> loadCommands;
    std::vector<Segment> segments;
    std::optional<MAC::dyld_info_command> dyldInfo;
    std::vector<Dylib> dylibs;
    std::optional<DySymTab> dySymTab;
    std::optional<MAC::entry_point_command> main;
    std::optional<MAC::source_version_command> sourceVersion;
    std::optional<MAC::uuid_command> uuid;
    std::vector<MAC::linkedit_data_command> linkEditDatas;
    std::optional<CodeSignature> codeSignature;
    std::optional<MAC::version_min_command> versionMin;
    bool isMacho;
    bool isFat;
    bool shouldSwapEndianess;
    bool is64;

    uint64 panelsMask;
    uint32 currentItemIndex;

    // GO
    Golang::PcLnTab pcLnTab{};

    uint32 showOpcodesMask{ 0 };
    std::vector<std::pair<uint64, uint64>> executableZonesFAs;
    GView::Dissasembly::DissasemblerIntel dissasembler{};

    // these are required here for Fat Containers (can't put them on function level)
    std::map<uint64, GView::View::BufferViewer::BufferColor> cacheBuffer{};
    std::map<uint64, bool> cacheDiscard{};

  public:
    // OffsetTranslateInterface
    uint64 TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex) override;
    uint64 TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex) override;

    // TypeInterface
    std::string_view GetTypeName() override
    {
        return "Mach-O";
    }

    void RunCommand(std::string_view) override;

  public:
    MachOFile(Reference<GView::Utils::DataCache> file);
    virtual ~MachOFile(){};

    bool Update();

    bool HasPanel(Panels::IDs id);

    bool SetHeaderInfo(uint64& offset);
    bool SetHeader(uint64& offset);
    bool SetLoadCommands(uint64& offset);
    bool SetSegmentsAndTheirSections();
    void SetExecutableZones();
    bool SetDyldInfo();
    bool SetIdDylibs();
    bool SetMain(); // LC_MAIN & LC_UNIX_THREAD
    bool SetSymbols();
    bool SetSourceVersion();
    bool SetUUID();
    bool SetLinkEditData();
    bool SetCodeSignature();
    bool SetVersionMin();
    bool ParseGoData();
    bool ParseGoBuild();
    bool ParseGoBuildInfo();
    uint64 VAtoFA(uint64 va);

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

  private:
    bool ComputeHash(const Buffer& buffer, uint8 hashType, std::string& output) const;

    bool GetColorForBuffer(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result) override;
    bool GetColorForBufferIntel(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result);
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<MachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateBasicInfo();
        void UpdateEntryPoint();
        void UpdateSourceVersion();
        void UpdateUUID();
        void UpdateVersionMin();
        void RecomputePanelsPositions();

        void UpdateFatInfo();

      public:
        Information(Reference<Object> _object, Reference<MachOFile> _machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class LoadCommands : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        LoadCommands(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class Segments : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Segments(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class Sections : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Sections(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class DyldInfo : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        void UpdateBasicInfo();
        void RecomputePanelsPositions();

      public:
        DyldInfo(Reference<MachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Dylib : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Dylib(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class SymTab : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int Base;

        std::string_view GetValue(NumericFormatter& n, uint64_t value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        SymTab(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class GoInformation : public TabPage
    {
        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        const std::string_view format            = "%-16s (%s)";
        const std::string_view formatDescription = "%-16s (%s) %s";

        Reference<Object> object;
        Reference<GView::Type::MachO::MachOFile> macho;
        Reference<AppCUI::Controls::ListView> list;

      public:
        GoInformation(Reference<Object> _object, Reference<GView::Type::MachO::MachOFile> _macho);

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
        Reference<GView::Type::MachO::MachOFile> macho;
        Reference<AppCUI::Controls::ListView> list;

      public:
        GoFiles(Reference<Object> _object, Reference<GView::Type::MachO::MachOFile> _macho);

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
        Reference<MachOFile> macho;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        GoFunctions(Reference<MachOFile> macho, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class OpCodes : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> macho;
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
        OpCodes(Reference<Object> object, Reference<GView::Type::MachO::MachOFile> macho);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
} // namespace Panels

namespace Commands
{

    class CodeSignMagic : public AppCUI::Controls::Window
    {
      private:
        Reference<MachOFile> machO;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> general;

        ListViewItem cmsOffset;     // MAC CMS signature/digital signature
        ListViewItem cmsSize;       // MAC CMS signature/digital signature
        ListViewItem humanReadable; // MAC CMS signature/digital signature
        ListViewItem PEMs;          // MAC CMS signature/digital signature

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateLinkeditDataCommand();
        void UpdateSuperBlob();
        void UpdateSlots();
        void UpdateBlobs();
        void UpdateCodeDirectory(
              const MAC::CS_CodeDirectory& code,
              const std::string& identifier,
              const std::string& cdHash,
              const std::vector<std::pair<std::string, std::string>>& slotsHashes);

        void RecomputePanelsPositions();

        void MoreInfo();

      public:
        CodeSignMagic(Reference<MachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
} // namespace Commands
} // namespace GView::Type::MachO
