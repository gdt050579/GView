#pragma once

#include "Mac.hpp"

namespace GView::Type::MachO::Utils
{
template <typename T>
const T SwapEndian(T u)
{
    union
    {
        T object;
        unsigned char bytes[sizeof(T)];
    } source{ u }, dest{};

    for (auto i = 0; i < sizeof(T); i++)
    {
        dest.bytes[i] = source.bytes[sizeof(T) - i - 1];
    }

    return dest.object;
}

template <typename T>
void SwapEndianInplace(T* u, uint64_t size)
{
    for (auto i = 0; i < size; i++)
    {
        u[i] = u[size - i - 1];
    }
}

template <typename T>
constexpr std::string BinaryToHexString(const T number, const size_t length)
{
    constexpr const char digits[] = "0123456789ABCDEF";

    std::string output;
    output.reserve(length * 3);

    const auto input = reinterpret_cast<const uint8_t*>(&number);
    std::for_each(
          input,
          input + length,
          [&output](uint8_t byte)
          {
              output.push_back(digits[byte >> 4]);
              output.push_back(digits[byte & 0x0F]);
              output.push_back(' ');
          });

    if (output.empty() == false)
    {
        output.resize(output.size() - 1);
    }

    return output;
}
} // namespace GView::Type::MachO::Utils

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

class MachOFile : public TypeInterface, public GView::View::BufferViewer::OffsetTranslateInterface
{
  public:
    struct Colors
    {
        ColorPair header{ Color::Olive, Color::Transparent };
        ColorPair loadCommand{ Color::Magenta, Color::Transparent };
        ColorPair section{ Color::DarkRed, Color::Transparent };
        ColorPair object{ Color::Silver, Color::Transparent };
    } colors;

    struct LoadCommand
    {
        MAC::load_command value;
        uint64_t offset;
    };

    union Segment
    {
        MAC::segment_command x86;
        MAC::segment_command_64 x64;
    };

    union Section
    {
        MAC::section x86;
        MAC::section_64 x64;
    };

    struct DyldInfo
    {
        bool isSet = false;
        MAC::dyld_info_command value;
    };

    struct Dylib
    {
        MAC::dylib_command value;
        std::string name;
        uint64_t offset;
    };

    struct Main
    {
        bool isSet = false;
        MAC::entry_point_command ep;
    };

    struct DySymTab
    {
        MAC::symtab_command sc;
        std::unique_ptr<char[]> symbolTable;
        std::unique_ptr<char[]> stringTable;
        bool isSet = false;
        std::vector<std::string> symbolsDemangled;
    };

    struct SourceVersion
    {
        bool isSet = false;
        MAC::source_version_command svc;
    };

    struct UUID
    {
        bool isSet = false;
        MAC::uuid_command value;
    };

    struct CodeSignature
    {
        bool isSet = false;
        MAC::linkedit_data_command ledc;
        MAC::CS_SuperBlob superBlob;
        std::vector<MAC::CS_BlobIndex> blobs;
        MAC::CS_CodeDirectory codeDirectory;
        std::vector<MAC::CS_CodeDirectory> alternateDirectories;

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
    };

    struct VersionMinCommand
    {
        bool isSet = false;
        MAC::version_min_command vmc;
    };

  public:
    Reference<GView::Utils::FileCache> file;
    MAC::mach_header header;
    std::vector<LoadCommand> loadCommands;
    std::vector<Segment> segments;
    std::vector<Section> sections;
    DyldInfo dyldInfo;
    std::vector<Dylib> dylibs;
    DySymTab dySymTab;
    Main main;
    SourceVersion sourceVersion;
    UUID uuid;
    std::vector<MAC::linkedit_data_command> linkEditDatas;
    CodeSignature codeSignature;
    VersionMinCommand versionMinCommand;
    bool shouldSwapEndianess;
    bool is64;

    uint64_t panelsMask;

  public:
    // OffsetTranslateInterface
    uint64_t TranslateToFileOffset(uint64_t value, uint32 fromTranslationIndex) override;
    uint64_t TranslateFromFileOffset(uint64_t value, uint32 toTranslationIndex) override;

    // TypeInterface
    std::string_view GetTypeName() override
    {
        return "Mach-O";
    }

  public:
    MachOFile(Reference<GView::Utils::FileCache> file);
    virtual ~MachOFile(){};

    bool Update();

    bool HasPanel(Panels::IDs id);

    bool SetArchitectureAndEndianess(uint64_t& offset);
    bool SetHeader(uint64_t& offset);
    bool SetLoadCommands(uint64_t& offset);
    bool SetSegments(uint64_t& offset);
    bool SetSections(uint64_t& offset);
    bool SetDyldInfo(uint64_t& offset);
    bool SetIdDylibs(uint64_t& offset);
    bool SetMain(uint64_t& offset); // LC_MAIN & LC_UNIX_THREAD
    bool SetSymbols(uint64_t& offset);
    bool SetSourceVersion(uint64_t& offset);
    bool SetUUID(uint64_t& offset);
    bool SetLinkEditData(uint64_t& offset);
    bool SetCodeSignature();
    bool SetVersionMin();
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<MachOFile> machO;
        Reference<AppCUI::Controls::ListView> general;

        void UpdateBasicInfo();
        void UpdateEntryPoint();
        void UpdateSourceVersion();
        void UpdateUUID();
        void UpdateVersionMin();
        void RecomputePanelsPositions();

      public:
        Information(Reference<MachOFile> machO);

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
        Reference<AppCUI::Controls::ListView> general;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateLinkeditDataCommand();
        void UpdateSuperBlob();
        void UpdateSlots();
        void UpdateBlobs();
        void UpdateCodeDirectory(const MAC::CS_CodeDirectory& code);

        void RecomputePanelsPositions();

      public:
        CodeSignMagic(Reference<MachOFile> machO);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };
} // namespace Panels
} // namespace GView::Type::MachO
