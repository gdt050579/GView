#pragma once

#include "utils.hpp"

namespace GView::Type::ELF
{
enum class AddressType : uint8
{
    FileOffset = 0,
    VA         = 1
};

constexpr auto ELF_INVALID_ADDRESS = 0xFFFFFFFFFFFFFFFF;

namespace Panels
{
    enum class IDs : uint8
    {
        Information    = 0x0,
        Segments       = 0x1,
        Sections       = 0x2,
        GoInformation  = 0x3,
        StaticSymbols  = 0x4,
        DynamicSymbols = 0x5,
    };
};

class ELFFile : public TypeInterface, public GView::View::BufferViewer::OffsetTranslateInterface
{
  public:
    uint64 panelsMask{ 0 };

    Elf32_Ehdr header32;
    Elf64_Ehdr header64;
    bool is64{ false };

    std::vector<Elf32_Phdr> segments32;
    std::vector<Elf64_Phdr> segments64;

    std::vector<Elf32_Shdr> sections32;
    std::vector<Elf64_Shdr> sections64;

    std::vector<std::string> sectionNames;
    std::vector<uint32> sectionsToSegments;

    std::vector<Elf32_Sym> staticSymbols32;
    std::vector<Elf64_Sym> staticSymbols64;
    std::vector<std::string> staticSymbolsNames;

    std::vector<Elf32_Sym> dynamicSymbols32;
    std::vector<Elf64_Sym> dynamicSymbols64;
    std::vector<std::string> dynamicSymbolsNames;

    // GO
    uint32 nameSize = 0;
    uint32 valSize  = 0;
    uint32 tag      = 0;
    std::string noteName{};
    std::string gnuString;
    Golang::PcLnTab pcLnTab{};

  public:
    ELFFile();
    virtual ~ELFFile()
    {
    }

    bool Update();
    bool HasPanel(Panels::IDs id);
    bool ParseGoData();
    bool ParseSymbols();

    uint64 TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex) override;
    uint64 TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex) override;
    uint64 ConvertAddress(uint64 address, AddressType fromAddressType, AddressType toAddressType);

    uint64 FileOffsetToVA(uint64 fileOffset);
    uint64 VAToFileOffset(uint64 virtualAddress);

    std::string_view GetTypeName() override
    {
        return "ELF";
    }
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        const std::string_view format            = "%-16s (%s)";
        const std::string_view formatDescription = "%-16s (%s) %s";

        Reference<Object> object;
        Reference<GView::Type::ELF::ELFFile> elf;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        void UpdateGeneralInformation();
        void UpdateHeader();
        void UpdateIssues();
        void RecomputePanelsPositions();

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
            auto it         = general->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
            it.SetType(type);

            return it;
        }

      public:
        Information(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> elf);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override;
    };

    class Segments : public AppCUI::Controls::TabPage
    {
        Reference<ELFFile> elf;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Segments(Reference<ELFFile> elf, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class Sections : public AppCUI::Controls::TabPage
    {
        Reference<ELFFile> elf;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Sections(Reference<ELFFile> elf, Reference<GView::View::WindowInterface> win);

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
        Reference<GView::Type::ELF::ELFFile> elf;
        Reference<AppCUI::Controls::ListView> list;

      public:
        GoInformation(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> _elf);

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
        Reference<GView::Type::ELF::ELFFile> elf;
        Reference<AppCUI::Controls::ListView> list;

      public:
        GoFiles(Reference<Object> _object, Reference<GView::Type::ELF::ELFFile> _elf);

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
        Reference<ELFFile> elf;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        GoFunctions(Reference<ELFFile> elf, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class DynamicSymbols : public AppCUI::Controls::TabPage
    {
        Reference<ELFFile> elf;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        DynamicSymbols(Reference<ELFFile> elf, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };

    class StaticSymbols : public AppCUI::Controls::TabPage
    {
        Reference<ELFFile> elf;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        StaticSymbols(Reference<ELFFile> elf, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::ELF
