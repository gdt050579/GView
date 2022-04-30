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
    AddDecAndHexElement("Size", "%-20s (%s)", lnk->obj->GetData().GetSize());

    general->AddItem("Header").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Header Size", "%-20s (%s)", lnk->header.headerSize);
    AddGUIDElement("Class Identifier", lnk->header.classIdentifier);
    AddDecAndHexElement("Link Flags", "%-20s (%s)", lnk->header.linkFlags);

    const auto lFlags = LNK::GetLinkFlags(lnk->header.linkFlags);
    for (const auto& flag : lFlags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = LNK::LinkFlagsNames.at(flag).data();
        const auto flagDescription = LNK::LinkFlagsDescriptions.at(flag).data();

        general->AddItem({ "", ls.Format("%-20s %-4s %s", flagName, hfls.GetText(), flagDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDecAndHexElement("File Attribute Flags", "%-20s (%s)", lnk->header.fileAttributeFlags);

    const auto faFlags = LNK::GetFileAttributeFlags(lnk->header.fileAttributeFlags);
    for (const auto& flag : faFlags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = LNK::FileAttributeFlagsNames.at(flag).data();
        const auto flagDescription = LNK::FileAttributeFlagsDescriptions.at(flag).data();

        general->AddItem({ "", ls.Format("%-20s %-4s %s", flagName, hfls.GetText(), flagDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDateTime("Creation Date", "%-20s (%s)", lnk->header.creationDate);
    AddDateTime("Last Access Date", "%-20s (%s)", lnk->header.lastAccessDate);
    AddDateTime("Last Modification Date", "%-20s (%s)", lnk->header.lastModificationDate);
    AddDecAndHexElement("File size", "%-20s (%s)", lnk->header.filesize);
    AddDecAndHexElement("Icon Index", "%-20s (%s)", lnk->header.iconIndex);

    const auto showCommandName        = LNK::ShowWindowNames.at(lnk->header.showCommand).data();
    const auto showCommandDescription = LNK::ShowWindowDescriptions.at(lnk->header.showCommand).data();
    const auto showCommandHex         = nf.ToString((uint32) lnk->header.showCommand, hex);
    general->AddItem({ "Show Command", ls.Format("%-20s (%s) %s", showCommandName, showCommandHex.data(), showCommandDescription) })
          .SetType(ListViewItem::Type::Emphasized_2);

    const auto hotKeyName =
          LNK::GetHotKeyHighFromFlags(lnk->header.hotKey.high) + "|" + std::string{ LNK::HotKeyLowNames.at(lnk->header.hotKey.low) };
    const auto hotKeyHex = nf2.ToString(*(uint32*) &lnk->header.hotKey, hex);
    general->AddItem({ "HotKey", ls.Format("%-20s (%s)", hotKeyName.c_str(), hotKeyHex.data()) });

    AddDecAndHexElement("Unknown0", "%-20s (%s)", lnk->header.unknown0);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", lnk->header.unknown1);
    AddDecAndHexElement("Unknown2", "%-20s (%s)", lnk->header.unknown2);

    general->AddItem("Data Strings").SetType(ListViewItem::Type::Category);

    LocalUnicodeStringBuilder<1024> lusb;
    for (const auto& [type, data] : lnk->dataStrings)
    {
        const auto& typeName = LNK::DataStringTypesNames.at(type);
        lusb.Set(data);
        std::string path;
        lusb.ToString(path);
        general->AddItem({ typeName.data(), ls.Format("%s", path.c_str()) });
    }
}

void Information::UpdateIssues()
{
}

void Information::RecomputePanelsPositions()
{
    CHECKRET(general.IsValid(), "");

    general->Resize(GetWidth(), std::min<>(this->GetHeight(), (int) general->GetItemsCount() + 3));

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
