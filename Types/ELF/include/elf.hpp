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

static constexpr auto INS_CALL_COLOR  = ColorPair{ Color::Yellow, Color::Silver };
static constexpr auto INS_LCALL_COLOR = ColorPair{ Color::White, Color::Silver };

static constexpr auto INS_JUMP_COLOR  = ColorPair{ Color::White, Color::DarkRed };
static constexpr auto INS_LJUMP_COLOR = ColorPair{ Color::Yellow, Color::DarkRed };

static constexpr auto INS_BREAKPOINT_COLOR = ColorPair{ Color::Magenta, Color::DarkBlue };

static constexpr auto START_FUNCTION_COLOR = ColorPair{ Color::Yellow, Color::Olive };
static constexpr auto END_FUNCTION_COLOR   = ColorPair{ Color::Black, Color::Olive };

static constexpr auto EXE_MARKER_COLOR = ColorPair{ Color::Yellow, Color::DarkRed };

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
        OpCodes        = 0x6,
    };
};

class ELFFile : public TypeInterface,
                public GView::View::BufferViewer::OffsetTranslateInterface,
                public GView::View::BufferViewer::PositionToColorInterface
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

    uint32 showOpcodesMask{ 0 };

  public:
    ELFFile();
    virtual ~ELFFile()
    {
    }

    bool Update();
    bool HasPanel(Panels::IDs id);
    bool ParseGoData();
    bool ParseSymbols();

    uint64 memStartOffset;
    uint64 memEndOffset;
    bool GetColorForBuffer(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result) override;
    bool GetColorForBufferForIntel(uint64 offset, BufferView buf, GView::View::BufferViewer::BufferColor& result);

    uint64 TranslateToFileOffset(uint64 value, uint32 fromTranslationIndex) override;
    uint64 TranslateFromFileOffset(uint64 value, uint32 toTranslationIndex) override;
    uint64 ConvertAddress(uint64 address, AddressType fromAddressType, AddressType toAddressType);

    uint64 FileOffsetToVA(uint64 fileOffset);
    uint64 VAToFileOffset(uint64 virtualAddress);

    uint64 GetImageBase() const;
    uint64 GetVirtualSize() const;

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

    class OpCodes : public AppCUI::Controls::TabPage
    {
        Reference<ELFFile> elf;
        Reference<Object> object;

        Reference<AppCUI::Controls::Label> value;
        Reference<AppCUI::Controls::CheckBox> all;
        Reference<AppCUI::Controls::CheckBox> header;
        Reference<AppCUI::Controls::CheckBox> call;
        Reference<AppCUI::Controls::CheckBox> lcall;
        Reference<AppCUI::Controls::CheckBox> jmp;
        Reference<AppCUI::Controls::CheckBox> ljmp;
        Reference<AppCUI::Controls::CheckBox> bp;
        Reference<AppCUI::Controls::CheckBox> fstart;
        Reference<AppCUI::Controls::CheckBox> fend;

        inline bool AllChecked();
        inline bool AllUnChecked();
        inline void SetMaskText();
        inline void SetConfig(bool checked, uint16 position);

      public:
        OpCodes(Reference<Object> object, Reference<GView::Type::ELF::ELFFile> elf);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::ELF
