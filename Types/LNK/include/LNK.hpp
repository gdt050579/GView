#pragma once

#include "Internal.hpp"

namespace GView::Type::LNK
{
class LNKFile : public TypeInterface
{
  public:
    Header header;

    LinkTargetIDList linkTargetIDList;
    Buffer linkTargetIDListBuffer;
    std::vector<ItemID*> itemIDS;

    Buffer locationInformationBuffer;
    LocationInformation locationInformation;
    uint32 unicodeLocalPathOffset = 0;
    std::u16string_view unicodeLocalPath;
    uint32 unicodeCommonPathOffset = 0;
    std::u16string_view unicodeCommonPath;
    VolumeInformation* volumeInformation             = nullptr;
    NetworkShareInformation* networkShareInformation = nullptr;

    uint32 dataStringsOffset = 0;
    Buffer dataStringsBuffer;
    std::map<DataStringTypes, ConstString> dataStrings;

    Buffer extraDataBuffer;
    std::vector<ExtraDataBase*> extraDataBases;
    std::map<PropertyStore*, std::vector<PropertyStore_ShellPropertySheet*>> propertyStores;

    LNKFile();
    virtual ~LNKFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "LNK";
    }
    void RunCommand(std::string_view) override
    {
    }
    virtual bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

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
    static ListViewItem AddGUIDElement(Reference<AppCUI::Controls::ListView> list, std::string_view name, MyGUID& guid)
    {
        CHECK(list.IsValid(), ListViewItem{}, "");

        LocalString<1024> ls;
        auto element = list->AddItem({ name,
                                       ls.Format(
                                             "%-20s {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                                             GetNameFromGUID(guid).data(),
                                             guid.a,
                                             guid.b,
                                             guid.c,
                                             guid.d[0],
                                             guid.d[1],
                                             guid.d[2],
                                             guid.d[3],
                                             guid.d[4],
                                             guid.d[5],
                                             guid.d[6],
                                             guid.d[7]) });
        element.SetType(ListViewItem::Type::Emphasized_1);

        return element;
    }

    class Information : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::LNK::LNKFile> lnk;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

        void AddDateTime(std::string_view name, std::string_view format, uint64 value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            AppCUI::OS::DateTime dt;
            dt.CreateFromFileTime(value);
            const auto valueHex = nf.ToString(value, hex);
            general->AddItem({ name, ls.Format(format.data(), dt.GetStringRepresentation().data(), valueHex.data()) })
                  .SetType(ListViewItem::Type::Emphasized_1);
        }

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

      public:
        Information(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };

    class ShellItems : public AppCUI::Controls::TabPage
    {
      protected:
        Reference<Object> object;
        Reference<GView::Type::LNK::LNKFile> lnk;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        ShellItems(std::string_view name) : TabPage(name){};

        template <typename T>
        ListViewItem AddDecAndHexElement(std::string_view name, std::string_view format, T value)
        {
            LocalString<1024> ls;
            NumericFormatter nf;
            NumericFormatter nf2;

            const auto v    = nf.ToString(value, dec);
            const auto vHex = nf2.ToString(value, hex);
            return general->AddItem({ name, ls.Format(format.data(), v.data(), vHex.data()) });
        }

        void UpdateRootFolderShellItem(RootFolderShellItem& item);
        void UpdateExtensionBlock0xBEEF0017(ExtensionBlock0xBEEF0017& block);
        void UpdateVolumeShellItem(VolumeShellItem& item);
        void UpdateLinkTargetIDList(const std::vector<ItemID*>& itemIDS);
        void UpdateFileEntryShellItem(ItemID* item);
        void UpdateExtensionBlock0xBEEF0003(ExtensionBlock0xBEEF0003& block);
        void UpdateExtensionBlock0xBEEF0004Base(ExtensionBlock0xBEEF0004Base& block);
        void UpdateExtensionBlock0xBEEF0004_V3(ExtensionBlock0xBEEF0004_V3* block);
        void UpdateExtensionBlock0xBEEF0004_V7(ExtensionBlock0xBEEF0004_V7* block);
        void UpdateExtensionBlock0xBEEF0004_V8(ExtensionBlock0xBEEF0004_V8* block);
        void UpdateExtensionBlock0xBEEF0004_V9(ExtensionBlock0xBEEF0004_V9* block);
        void UpdateControlPanelShellItem(ControlPanelShellItem& block);
        void UpdateDelegateShellItem(DelegateShellItem& item);
        void UpdateNetworkLocationShellItem(NetworkLocationShellItem& item);
    };

    class LinkTargetIDList : public ShellItems
    {
        void UpdateGeneralInformation();
        void UpdateIssues();
        void RecomputePanelsPositions();

      public:
        LinkTargetIDList(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };

    class LocationInformation : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::LNK::LNKFile> lnk;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateIssues();
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

      public:
        LocationInformation(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };

    class ExtraData : public ShellItems
    {
        void UpdateGeneralInformation();
        void UpdateExtraDataBase(ExtraDataBase* base);
        void UpdateExtraData_EnvironmentVariablesLocation(ExtraData_EnvironmentVariablesLocation* data);
        void UpdateExtraData_ConsoleProperties(ExtraData_ConsoleProperties* data);
        void UpdateExtraData_DistributedLinkTrackerProperties(ExtraData_DistributedLinkTrackerProperties* data);
        void UpdateExtraData_ConsoleCodepage(ExtraData_ConsoleCodepage* data);
        void UpdateExtraData_SpecialFolderLocation(ExtraData_SpecialFolderLocation* data);
        void UpdateExtraData_DarwinProperties(ExtraData_DarwinProperties* data);
        void UpdateExtraData_IconLocation(ExtraData_IconLocation* data);
        void UpdateExtraData_ShimLayer(ExtraData_ShimLayer* data);
        void UpdateExtraData_MetadataPropertyStore(ExtraData_MetadataPropertyStore* data);
        void UpdateExtraData_KnownFolderLocation(ExtraData_KnownFolderLocation* data);
        void UpdateExtraData_VistaAndAboveIDListDataBlock(ExtraData_VistaAndAboveIDListDataBlock* data);
        void UpdateIssues();
        void RecomputePanelsPositions();

      public:
        ExtraData(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk);

        void Update();
        virtual void OnAfterResize(int newWidth, int newHeight) override
        {
            RecomputePanelsPositions();
        }
        bool OnUpdateCommandBar(Application::CommandBar& commandBar) override;
        bool OnEvent(Reference<Control> ctrl, Event evnt, int controlID) override;
    };
}; // namespace Panels
} // namespace GView::Type::LNK
