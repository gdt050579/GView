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

    LNKFile();
    virtual ~LNKFile()
    {
    }

    bool Update();

    std::string_view GetTypeName() override
    {
        return "LNK";
    }
};

namespace Panels
{
    static void AddGUIDElement(Reference<AppCUI::Controls::ListView> list, std::string_view name, MyGUID& guid)
    {
        CHECKRET(list.IsValid(), "");

        LocalString<1024> ls;
        list->AddItem({ name,
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
                              guid.d[7]) })
              .SetType(ListViewItem::Type::Emphasized_1);
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

    class LinkTargetIDList : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::LNK::LNKFile> lnk;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateRootFolderShellItem(RootFolderShellItem& item);
        void UpdateExtensionBlock0xBEEF0017(ExtensionBlock0xBEEF0017& block);
        void UpdateVolumeShellItem(VolumeShellItem& item);
        void UpdateLinkTargetIDList();
        void UpdateFileEntryShellItem_XPAndLater(ItemID* item);
        void UpdateExtensionBlock0xBEEF0003(ExtensionBlock0xBEEF0003& block);
        void UpdateExtensionBlock0xBEEF0004Base(ExtensionBlock0xBEEF0004Base& block);
        void UpdateExtensionBlock0xBEEF0004_V9(ExtensionBlock0xBEEF0004_V9* block);
        void UpdateControlPanelShellItem(ControlPanelShellItem& block);
        void UpdateDelegateShellItem(DelegateShellItem& item);
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

    class ExtraData : public AppCUI::Controls::TabPage
    {
        Reference<Object> object;
        Reference<GView::Type::LNK::LNKFile> lnk;
        Reference<AppCUI::Controls::ListView> general;
        Reference<AppCUI::Controls::ListView> issues;

        inline static const auto dec = NumericFormat{ NumericFormatFlags::None, 10, 3, ',' };
        inline static const auto hex = NumericFormat{ NumericFormatFlags::HexPrefix, 16 };

        void UpdateGeneralInformation();
        void UpdateExtraDataBase(ExtraDataBase* base);
        void UpdateExtraData_SpecialFolderLocation(ExtraData_SpecialFolderLocation* data);
        void UpdateExtraData_KnownFolderLocation(ExtraData_KnownFolderLocation* data);
        void UpdateExtraData_EnvironmentVariablesLocation(ExtraData_EnvironmentVariablesLocation* data);
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
