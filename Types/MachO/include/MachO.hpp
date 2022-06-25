#pragma once

#include "Utils.hpp"
#include "Swap.hpp"

namespace GView::Type::MachO
{
namespace Panels
{
    enum class IDs : uint8_t
    {
        Information  = 0x0,
        LoadCommands = 0x1,
        Segments     = 0x2,
        Sections     = 0x3,
        DyldInfo     = 0x4,
        Dylib        = 0x5,
        DySymTab     = 0x6,
        CodeSign     = 0x7
    };
};

class MachOFile : public TypeInterface,
                  public View::BufferViewer::OffsetTranslateInterface,
                  public View::ContainerViewer::EnumerateInterface,
                  public View::ContainerViewer::OpenItemInterface
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

  public:
    // OffsetTranslateInterface
    uint64 TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex) override;
    uint64 TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex) override;

    // TypeInterface
    std::string_view GetTypeName() override
    {
        return "Mach-O";
    }

  public:
    MachOFile(Reference<GView::Utils::DataCache> file);
    virtual ~MachOFile(){};

    bool Update();

    bool HasPanel(Panels::IDs id);

    bool SetHeaderInfo(uint64& offset);
    bool SetHeader(uint64& offset);
    bool SetLoadCommands(uint64& offset);
    bool SetSegmentsAndTheirSections();
    bool SetDyldInfo();
    bool SetIdDylibs();
    bool SetMain(); // LC_MAIN & LC_UNIX_THREAD
    bool SetSymbols();
    bool SetSourceVersion();
    bool SetUUID();
    bool SetLinkEditData();
    bool SetCodeSignature();
    bool SetVersionMin();

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

  private:
    bool ComputeHash(const Buffer& buffer, uint8 hashType, std::string& output) const;
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

    class CodeSignMagic : public AppCUI::Controls::TabPage
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

        void GoToSelectedOffset();
        void SelectArea();
        void MoreInfo();

      public:
        CodeSignMagic(Reference<MachOFile> machO, Reference<GView::View::WindowInterface> win);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
} // namespace Panels
} // namespace GView::Type::MachO
