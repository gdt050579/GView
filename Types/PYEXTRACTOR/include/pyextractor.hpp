#pragma once

#include "GView.hpp"

namespace GView::Type::PYEXTRACTOR
{
enum class Magic : uint16 {
    NoCompression      = 0x0178, // - No Compression / low
    DefaultCompression = 0x9C78, // - Default Compression
    BestCompression    = 0xDA78  // - Best Compression
};

constexpr auto PYINSTALLER20_COOKIE_SIZE     = 24U;                             // For pyinstaller 2.0
constexpr auto PYINSTALLER21_COOKIE_SIZE     = PYINSTALLER20_COOKIE_SIZE + 64U; // For pyinstaller 2.1 +
constexpr std::string_view PYINSTALLER_MAGIC = "MEI\014\013\012\013\016";       // Magic number which identifies pyinstaller

enum class PyInstallerVersion : uint8 { Unknown, V20, V21Plus };

constexpr std::string_view GetNameForPyInstallerVersion(PyInstallerVersion v)
{
    switch (v) {
    case GView::Type::PYEXTRACTOR::PyInstallerVersion::Unknown:
        return "Unknown";
    case GView::Type::PYEXTRACTOR::PyInstallerVersion::V20:
        return "v20";
    case GView::Type::PYEXTRACTOR::PyInstallerVersion::V21Plus:
        return "v21+";
    default:
        return "Unknown";
    }
}

struct TOCEntry {
#pragma pack(push, 1)
    uint32 entrySize{ 0 };
    uint32 entryPos{ 0 };
    uint32 cmprsdDataSize{ 0 };
    uint32 uncmprsdDataSize{ 0 };
    uint8 cmprsFlag{ 0 };
    uint8 typeCmprsData{ 0 };
#pragma pack(pop)
    Buffer name;
};

constexpr auto TOC_ENTRY_KNOWN_SIZE = 18;

struct Archive {
    uint64 cookiePosition{ 0 };
    PyInstallerVersion version{ PyInstallerVersion::Unknown };

#pragma pack(push, 1)
    struct {
        char magic[8]{ 0 };
        uint32 lengthofPackage{ 0 };
        uint32 tableOfContentPosition{ 0 };
        uint32 tableOfContentSize{ 0 };
        uint32 pyver{ 0 };
        char pylibname[64]{ 0 };
    } info;
#pragma pack(pop)
};

namespace Panels
{
    enum class IDs : uint8 { Information = 0x0, TOCEntries = 0x1 };
};

class PYEXTRACTORFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    uint64 panelsMask{ 0 };
    Archive archive;
    std::vector<TOCEntry> tocEntries;

    uint32 currentItemIndex{ 0 };

  public:
    PYEXTRACTORFile();
    virtual ~PYEXTRACTORFile() = default;

    bool Update();
    bool HasPanel(Panels::IDs id);

    std::string_view GetTypeName() override
    {
        return "PYEXTRACTOR";
    }
    void RunCommand(std::string_view) override
    {
    }

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;
    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

  private:
    bool SetCookiePosition();
    bool SetInstallerVersion();
    bool SetInfo();
    bool SetTableOfContentEntries();

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

    std::string GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
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
        Reference<GView::Type::PYEXTRACTOR::PYEXTRACTORFile> py;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        void UpdateGeneralInformation();
        void UpdateArchive();
        void UpdateIssues();
        void RecomputePanelsPositions();

        template <typename T>
        ListViewItem AddDecAndHexElement(std::string_view name, std::string_view format, T value, ListViewItem::Type type = ListViewItem::Type::Normal)
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
        Information(Reference<Object> _object, Reference<GView::Type::PYEXTRACTOR::PYEXTRACTORFile> py);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override;
    };

    class TOCEntries : public AppCUI::Controls::TabPage
    {
        Reference<GView::Type::PYEXTRACTOR::PYEXTRACTORFile> py;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int base;

        std::string_view GetValue(NumericFormatter& n, uint32 value);
        void GoToSelectedEntry();
        void SelectCurrentEntry();
        void OpenCurrentEntry();

      public:
        TOCEntries(Reference<GView::Type::PYEXTRACTOR::PYEXTRACTORFile> py, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
} // namespace Panels
} // namespace GView::Type::PYEXTRACTOR
