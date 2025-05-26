#pragma once

#include "GView.hpp"

namespace GView::Type::ZIP
{
class ZIPFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    uint32 currentItemIndex{ 0 };
    GView::Decoding::ZIP::Info info{};
    std::vector<uint32> curentChildIndexes{};
    bool isTopContainer{ true };
    std::string password;

  public:
    ZIPFile();
    virtual ~ZIPFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "ZIP";
    }

    void RunCommand(std::string_view) override
    {
    }

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;

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

    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::ZIP::ZIPFile> zip;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void RecomputePanelsPositions();

        template <typename T>
        void AddDecAndHexElement(std::string_view name, std::string_view format, T value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            const auto v    = nf.ToString(value, dec);
            const auto hexV = nf2.ToString(value, hex);
            general->AddItem({ name, ls.Format(format.data(), v.data(), hexV.data()) });
        }

        template <typename T>
        void AddNameAndHexElement(std::string_view name, std::string_view format, const T& value)
        {
            LocalString<1024> ls;
            LocalString<1024> ls2;

            constexpr auto size = sizeof(value) / sizeof(value[0]);
            ls2.Format("0x");
            for (auto i = 0ULL; i < size; i++)
            {
                ls2.AddFormat("%.2x", value[i]);
            }
            const auto vHex = ls2.GetText();
            general->AddItem({ name, ls.Format(format.data(), std::string{ value, sizeof(value) }.c_str(), vHex) });
        }

      public:
        Information(Reference<Object> _object, Reference<GView::Type::ZIP::ZIPFile> _zip);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Objects : public AppCUI::Controls::TabPage
    {
        Reference<ZIPFile> zip;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Objects(Reference<ZIPFile> zip, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::ZIP
