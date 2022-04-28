#include "LNK.hpp"

using namespace GView::Type::LNK;
using namespace GView::Type::LNK::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Information::Information(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk) : TabPage("Informa&tion")
{
    lnk     = _lnk;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    Update();
}

void Information::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Info").SetType(ListViewItem::Type::Category);

    general->AddItem({ "File", object->GetName() });

    const auto fileSize    = nf.ToString(lnk->obj->GetData().GetSize(), dec);
    const auto hexfileSize = nf2.ToString(lnk->obj->GetData().GetSize(), hex);
    general->AddItem({ "Size", ls.Format("%-14s (%s)", fileSize.data(), hexfileSize.data()) });

    general->AddItem("Header").SetType(ListViewItem::Type::Category);

    const auto headerSize    = nf.ToString(lnk->header.headerSize, dec);
    const auto headerSizeHex = nf2.ToString(lnk->header.headerSize, hex);
    general->AddItem({ "Header Size", ls.Format("%-14s (%s)", headerSize.data(), headerSizeHex.data()) });

    const auto& guid = lnk->header.classIdentifier;
    general->AddItem({ "Class Identifier",
                       ls.Format(
                             "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                             guid[0],
                             guid[1],
                             guid[2],
                             guid[3],
                             guid[4],
                             guid[5],
                             guid[6],
                             guid[7],
                             guid[8],
                             guid[9],
                             guid[10],
                             guid[11],
                             guid[12],
                             guid[13],
                             guid[14],
                             guid[15]) });

    const auto dataFlags    = nf.ToString(lnk->header.dataFlags, dec);
    const auto dataFlagsHex = nf2.ToString(lnk->header.dataFlags, hex);
    general->AddItem({ "Data Flags", ls.Format("%-14s (%s)", dataFlags.data(), dataFlagsHex.data()) });

    const auto fileAttributeFlags    = nf.ToString(lnk->header.fileAttributeFlags, dec);
    const auto fileAttributeFlagsHex = nf2.ToString(lnk->header.fileAttributeFlags, hex);
    general->AddItem({ "File Attribute Flags", ls.Format("%-14s (%s)", dataFlags.data(), dataFlagsHex.data()) });

    DateTime dt;
    dt.CreateFromFileTime(lnk->header.creationDate);
    const auto creationDateHex = nf2.ToString(lnk->header.creationDate, hex);
    general->AddItem({ "Creation Date", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), creationDateHex.data()) });

    dt.CreateFromFileTime(lnk->header.lastAccessDate);
    const auto lastAccessDateHex = nf2.ToString(lnk->header.lastAccessDate, hex);
    general->AddItem({ "Last Access Date", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), lastAccessDateHex.data()) });

    dt.CreateFromFileTime(lnk->header.lastModificationDate);
    const auto lastModificationDateHex = nf2.ToString(lnk->header.lastModificationDate, hex);
    general->AddItem(
          { "Last Modification Date", ls.Format("%-20s (%s)", dt.GetStringRepresentation().data(), lastModificationDateHex.data()) });

    const auto filesize    = nf.ToString(lnk->header.filesize, dec);
    const auto filesizeHex = nf2.ToString(lnk->header.filesize, hex);
    general->AddItem({ "File size", ls.Format("%-14s (%s)", filesize.data(), filesizeHex.data()) });

    const auto iconIndex    = nf.ToString(lnk->header.iconIndex, dec);
    const auto iconIndexHex = nf2.ToString(lnk->header.iconIndex, hex);
    general->AddItem({ "Icon Index", ls.Format("%-14s (%s)", iconIndex.data(), iconIndexHex.data()) });

    const auto showWindow    = nf.ToString(lnk->header.showWindow, dec);
    const auto showWindowHex = nf2.ToString(lnk->header.showWindow, hex);
    general->AddItem({ "Show Window", ls.Format("%-14s (%s)", showWindow.data(), showWindowHex.data()) });

    const auto hotKey    = nf.ToString(lnk->header.hotKey, dec);
    const auto hotKeyHex = nf2.ToString(lnk->header.hotKey, hex);
    general->AddItem({ "HotKey", ls.Format("%-14s (%s)", hotKey.data(), hotKeyHex.data()) });

    const auto unknown0    = nf.ToString(lnk->header.unknown0, dec);
    const auto unknown0Hex = nf2.ToString(lnk->header.unknown0, hex);
    general->AddItem({ "Unknown0", ls.Format("%-14s (%s)", unknown0.data(), unknown0Hex.data()) });

    const auto unknown1    = nf.ToString(lnk->header.unknown1, dec);
    const auto unknown1Hex = nf2.ToString(lnk->header.unknown1, hex);
    general->AddItem({ "Unknown1", ls.Format("%-14s (%s)", unknown1.data(), unknown1Hex.data()) });

    const auto unknown2    = nf.ToString(lnk->header.unknown2, dec);
    const auto unknown2Hex = nf2.ToString(lnk->header.unknown2, hex);
    general->AddItem({ "Unknown2", ls.Format("%-14s (%s)", unknown2.data(), unknown2Hex.data()) });
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), general->GetItemsCount() + 3);

    // CHECKRET(general.IsValid() & issues.IsValid(), "");
    // issues->SetVisible(issues->GetItemsCount() > 0);
    // if (issues->IsVisible())
    //{
    //    general->Resize(GetWidth(), general->GetItemsCount() + issues->GetItemsCount() + 3);
    //}
}

bool Information::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool Information::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    if (evnt == Event::Command)
    {
        switch (controlID)
        {
        default:
            break;
        }
    }

    return false;
}

void Information::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
