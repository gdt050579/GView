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

        void AddGUIDElement(std::string_view name, uint8 value[16])
        {
            LocalString<1024> ls;
            general->AddItem({ name,
                               ls.Format(
                                     "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                                     value[0],
                                     value[1],
                                     value[2],
                                     value[3],
                                     value[4],
                                     value[5],
                                     value[6],
                                     value[7],
                                     value[8],
                                     value[9],
                                     value[10],
                                     value[11],
                                     value[12],
                                     value[13],
                                     value[14],
                                     value[15]) });
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
        void UpdateExtensionBlock0xBEEF0004Base(ExtensionBlock0xBEEF0004Base& block);
        void UpdateExtensionBlock0xBEEF0004BaseV9(ExtensionBlock0xBEEF0004_V9* block);
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

        void AddGUIDElement(std::string_view name, uint8 value[16])
        {
            LocalString<1024> ls;
            general->AddItem({ name,
                               ls.Format(
                                     "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                                     value[0],
                                     value[1],
                                     value[2],
                                     value[3],
                                     value[4],
                                     value[5],
                                     value[6],
                                     value[7],
                                     value[8],
                                     value[9],
                                     value[10],
                                     value[11],
                                     value[12],
                                     value[13],
                                     value[14],
                                     value[15]) });
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
}; // namespace Panels
} // namespace GView::Type::LNK
