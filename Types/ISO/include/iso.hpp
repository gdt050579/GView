#pragma once

#include "Common.hpp"
#include "ECMA119.hpp"

namespace GView::Type::ISO
{
class ISOFile : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    struct MyVolumeDescriptorHeader
    {
        ECMA_119_VolumeDescriptorHeader header;
        uint64 offsetInFile;
    };

    std::vector<MyVolumeDescriptorHeader> headers;
    std::vector<ECMA_119_DirectoryRecord> records;

    ECMA_119_PrimaryVolumeDescriptor pvd{};
    ECMA_119_DirectoryRecord root{};
    std::vector<ECMA_119_DirectoryRecord> objects;

    std::map<uint64, ECMA_119_DirectoryRecord> itemsCache;

    uint32 currentItemIndex;

  public:
    ISOFile();
    virtual ~ISOFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "ISO";
    }
    void RunCommand(std::string_view) override
    {
    }

    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
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
};

namespace Panels
{
    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::ISO::ISOFile> iso;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateVolumeHeader(const ECMA_119_VolumeDescriptorHeader& vdh);
        void UpdateBootRecord(const ECMA_119_BootRecord& br);
        void UpdatePrimaryVolumeDescriptor(const ECMA_119_PrimaryVolumeDescriptor& pvd);
        void UpdateSupplementaryVolumeDescriptor(const ECMA_119_SupplementaryVolumeDescriptor& pvd);
        void UpdateVolumeDescriptor(const ECMA_119_VolumeDescriptorData& vdd);
        void UpdateVolumePartitionDescriptor(const ECMA_119_VolumePartitionDescriptor& vpd);
        void UpdateIssues();
        void UpdateVolumeDescriptors();
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

        void AddDateAndHexElement(std::string_view name, std::string_view format, const ECMA_119_dec_datetime& date)
        {
            LocalString<1024> ls;
            LocalString<1024> ls2;
            LocalString<1024> ls3;

            ls.Format(
                  "%.4s-%.2s-%.2s %.2s:%.2s:%.2s:%.2s +%u",
                  date.year,
                  date.months,
                  date.days,
                  date.hours,
                  date.minutes,
                  date.seconds,
                  date.milliseconds,
                  date.timezone);

            const auto dateBuffer = (unsigned char*) &date;
            constexpr auto size   = sizeof(date);
            ls2.Format("0x");
            for (auto i = 0ULL; i < size; i++)
            {
                ls2.AddFormat("%.2x", dateBuffer[i]);
            }
            const auto dateHex = ls2.GetText();
            general->AddItem({ name, ls3.Format(format.data(), ls.GetText(), dateHex) });
        }

      public:
        Information(Reference<Object> _object, Reference<GView::Type::ISO::ISOFile> _iso);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
    };

    class Objects : public AppCUI::Controls::TabPage
    {
        Reference<ISOFile> iso;
        Reference<GView::View::WindowInterface> win;
        Reference<AppCUI::Controls::ListView> list;
        int32 Base;

        std::string_view GetValue(NumericFormatter& n, uint64 value);
        void GoToSelectedSection();
        void SelectCurrentSection();

      public:
        Objects(Reference<ISOFile> iso, Reference<GView::View::WindowInterface> win);

        void Update();
        bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control>, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::ISO
