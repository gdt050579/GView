#pragma once

#include "utils.hpp"

namespace GView::Type::ELF
{
// version of the pclntab (Program Counter Line Table) -: https://go.dev/src/debug/gosym/pclntab.go
enum class PclntabVersion : int32
{
    Unknown = -1,
    _11     = 0,
    _12     = 1,
    _116    = 2,
    _118    = 3,
};

enum class GoMagic : uint32 // https://go.dev/src/debug/gosym/pclntab.go
{
    _12  = 0xfffffffb,
    _116 = 0xfffffffa,
    _118 = 0xfffffff0,
};

static std::string_view GetNameForGoMagic(GoMagic magic)
{
    switch (magic)
    {
    case GView::Type::ELF::GoMagic::_12:
        return "Version 12";
    case GView::Type::ELF::GoMagic::_116:
        return "Version 116";
    case GView::Type::ELF::GoMagic::_118:
        return "Version 118";
    default:
        return "Version Unknown";
    }
}

struct GoFunctionHeader
{
    GoMagic magic;
    uint16 padding;
    uint8 instructionSizeQuantum; // (1 for x86, 4 for ARM)
    uint8 sizeOfUintptr;          // in bytes
};

struct FstEntry32
{
    uint32 pc;
    uint32 functionOffset;
};

struct FstEntry64
{
    uint64 pc;
    uint32 functionOffset;
};

struct GoFunctionHeader2
{
    uint32 magic;          // 0xFFFFFFF0
    uint8 pad1;            // 0
    uint8 pad2;            // 0
    uint8 minLC;           // min instruction size (1 for x86, 4 for ARM)
    uint8 ptrSize;         // size of a ptr in bytes
    int32 nfunc;           // number of functions in the module
    uint32 nfiles;         // number of entries in the file tab
    uint32 textStart;      // base for function entry PC offsets in this module, equal to moduledata.text
    uint32 funcnameOffset; // offset to the funcnametab variable from pcHeader
    uint32 cuOffset;       // offset to the cutab variable from pcHeader
    uint32 filetabOffset;  // offset to the filetab variable from pcHeader
    uint32 pctabOffset;    // offset to the pctab variable from pcHeader
    uint32 pclnOffset;     // offset to the pclntab variable from pcHeader
};

struct Func32
{
    uint32 entry;    // start pc
    int32 name;      // name (offset to C string)
    int32 args;      // size of arguments passed to function
    int32 frame;     // size of function frame, including saved caller PC
    int32 pcsp;      // pcsp table (offset to pcvalue table)
    int32 pcfile;    // pcfile table (offset to pcvalue table)
    int32 pcln;      // pcln table (offset to pcvalue table)
    int32 nfuncdata; // number of entries in funcdata list
    int32 npcdata;   // number of entries in pcdata list
};

struct Func64
{
    uint64 entry;    // start pc
    int32 name;      // name (offset to C string)
    int32 args;      // size of arguments passed to function
    int32 frame;     // size of function frame, including saved caller PC
    int32 pcsp;      // pcsp table (offset to pcvalue table)
    int32 pcfile;    // pcfile table (offset to pcvalue table)
    int32 pcln;      // pcln table (offset to pcvalue table)
    int32 nfuncdata; // number of entries in funcdata list
    int32 npcdata;   // number of entries in pcdata list
};

enum class AddressType : uint8
{
    FileOffset = 0,
    VA         = 1
};

constexpr auto ELF_INVALID_ADDRESS = 0xFFFFFFFFFFFFFFFF;

namespace Panels
{
    enum class IDs : uint8_t
    {
        Information = 0x0,
        Segments    = 0x1,
        Sections    = 0x2,
        GoFunctions = 0x3,
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

    // GO
    uint32 goplcntabSectionIndex = -1;
    Buffer gopclntabBuffer{};
    GoFunctionHeader* goFunctionHeader = nullptr;
    uint64 sizeOfFunctionSymbolTable   = 0;
    std::vector<FstEntry32> entries32;
    std::vector<FstEntry64> entries64;
    std::vector<Func32> functions32;
    std::vector<Func64> functions64;
    std::vector<std::string> functionsNames;

  public:
    ELFFile();
    virtual ~ELFFile()
    {
    }

    bool Update();
    bool HasPanel(Panels::IDs id);
    bool ParseGoData();

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
        void UpdateGoInformation();
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
}; // namespace Panels
} // namespace GView::Type::ELF
