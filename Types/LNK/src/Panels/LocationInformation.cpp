#include "LNK.hpp"

using namespace GView::Type::LNK;
using namespace GView::Type::LNK::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

Panels::LocationInformation::LocationInformation(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk)
    : TabPage("L&ocationInformation")
{
    lnk     = _lnk;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

    Update();
}

void Panels::LocationInformation::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    LocalString<1024> ls2;
    NumericFormatter nf;
    NumericFormatter nf2;

    general->AddItem("Location Information").SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Size", "%-20s (%s)", lnk->locationInformation.size);
    AddDecAndHexElement("Header Size", "%-20s (%s)", lnk->locationInformation.headerSize);
    AddDecAndHexElement("Flags", "%-20s (%s)", lnk->locationInformation.flags);

    const auto flags = LNK::GetLocationFlags(lnk->locationInformation.flags);
    for (const auto& flag : flags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName        = LNK::LocationFlagsNames.at(flag).data();
        const auto flagDescription = LNK::LocationFlagsDescriptions.at(flag).data();

        general->AddItem({ "", ls.Format("%-20s %-4s %s", flagName, hfls.GetText(), flagDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDecAndHexElement("Volume Information Offset", "%-20s (%s)", lnk->locationInformation.volumeInformationOffset);
    AddDecAndHexElement("Local Path Offset", "%-20s (%s)", lnk->locationInformation.localPathOffset);
    AddDecAndHexElement("Network Share Offset", "%-20s (%s)", lnk->locationInformation.networkShareOffset);
    AddDecAndHexElement("Common Path Offset", "%-20s (%s)", lnk->locationInformation.commonPathOffset);

    auto offset = 0;
    if (lnk->locationInformation.headerSize > 28)
    {
        AddDecAndHexElement("Unicode Local Path Offset", "%-20s (%s)", lnk->unicodeLocalPathOffset);
        general->AddItem({ "Unicode Local Path", ls.Format("%S", lnk->locationInformationBuffer.GetData() + lnk->unicodeLocalPathOffset) });
        offset += sizeof(lnk->unicodeLocalPathOffset);

        if (lnk->locationInformation.headerSize > 32)
        {
            AddDecAndHexElement("Unicode Common Path Offset", "%-20s (%s)", lnk->unicodeCommonPathOffset);
            general->AddItem(
                  { "Unicode Common Path", ls.Format("%S", lnk->locationInformationBuffer.GetData() + lnk->unicodeCommonPathOffset) });
            offset += sizeof(lnk->unicodeCommonPathOffset);
        }
    }

    if (lnk->locationInformation.localPathOffset > 0)
    {
        general->AddItem(
              { "Local Path", ls.Format("%s", lnk->locationInformationBuffer.GetData() + lnk->locationInformation.localPathOffset) });
    }

    general->AddItem(
          { "Common Path", ls.Format("%s", lnk->locationInformationBuffer.GetData() + lnk->locationInformation.commonPathOffset) });

    if (lnk->locationInformation.volumeInformationOffset != 0)
    {
        general->AddItem("Volume Information").SetType(ListViewItem::Type::Category);

        AddDecAndHexElement("Size", "%-20s (%s)", lnk->volumeInformation->size);

        const auto driveTypeName        = LNK::DriveTypeNames.at(lnk->volumeInformation->driveType).data();
        const auto driveTypeDescription = LNK::DriveTypeDescriptions.at(lnk->volumeInformation->driveType).data();
        ls2.Format("(0x%X)", lnk->volumeInformation->driveType);
        general->AddItem({ "Drive Type", ls.Format("%-20s %-4s %s", driveTypeName, ls2.GetText(), driveTypeDescription) })
              .SetType(ListViewItem::Type::Emphasized_2);

        AddDecAndHexElement("Drive Serial Number", "%-20s (%s)", lnk->volumeInformation->driveSerialNumber);
        AddDecAndHexElement("Volume Label Offset", "%-20s (%s)", lnk->volumeInformation->volumeLabelOffset);
        general->AddItem(
              { "Volume Label", ls.Format("%s", ((uint8*) lnk->volumeInformation) + lnk->volumeInformation->volumeLabelOffset) });

        if (lnk->volumeInformation->volumeLabelOffset > 16)
        {
            const auto unicodeVolumeLabelOffset =
                  *(uint32*) ((uint8*) lnk->volumeInformation + sizeof(lnk->volumeInformation->volumeLabelOffset));
            AddDecAndHexElement("Unicode Volume Label Offset", "%-20s (%s)", unicodeVolumeLabelOffset);
            general->AddItem({ "Unicode Volume Label", ls.Format("%s", (uint8*) lnk->volumeInformation + unicodeVolumeLabelOffset) });
        }
    }

    if (lnk->locationInformation.networkShareOffset > 0)
    {
        general->AddItem("Network Share Offset").SetType(ListViewItem::Type::Category);

        AddDecAndHexElement("Size", "%-20s (%s)", lnk->networkShareInformation->size);

        const auto flags = LNK::GetNetworkShareFlags(lnk->networkShareInformation->flags);
        for (const auto& flag : flags)
        {
            LocalString<16> hfls;
            hfls.Format("(0x%X)", flag);

            const auto flagName        = LNK::NetworkShareFlagsNames.at(flag).data();
            const auto flagDescription = LNK::NetworkShareFlagsDescriptions.at(flag).data();

            general->AddItem({ "", ls.Format("%-20s %-4s %s", flagName, hfls.GetText(), flagDescription) })
                  .SetType(ListViewItem::Type::Emphasized_2);
        }

        AddDecAndHexElement("Network Share Name Offset", "%-20s (%s)", lnk->networkShareInformation->networkShareNameOffset);
        AddDecAndHexElement("Device Name Offset", "%-20s (%s)", lnk->networkShareInformation->deviceNameOffset);

        const auto networkProviderTypeName = LNK::NetworkProviderTypesNames.at(lnk->networkShareInformation->networkProviderType).data();
        const auto networkProviderTypeHex  = ls2.Format("(0x%X)", lnk->networkShareInformation->networkProviderType).data();
        general->AddItem({ "Network Provider Type", ls.Format("%-20s %-4s", networkProviderTypeName, networkProviderTypeHex) })
              .SetType(ListViewItem::Type::Emphasized_2);

        if (lnk->networkShareInformation->networkShareNameOffset > 0x20)
        {
            const auto unicodeLocalPathOffset = *(uint32*) ((uint8*) lnk->networkShareInformation + sizeof(LocationInformation));
            AddDecAndHexElement("Unicode Local Path Offset", "%-20s (%s)", unicodeLocalPathOffset);
            general->AddItem({ "Unicode Local Path", ls.Format("%ls", (uint8*) lnk->networkShareInformation + unicodeLocalPathOffset) });

            const auto unicodeCommonPathOffset =
                  *(uint32*) ((uint8*) lnk->networkShareInformation + sizeof(LocationInformation) + sizeof(unicodeLocalPathOffset));
            AddDecAndHexElement("Unicode Common Path Offset", "%-20s (%s)", unicodeCommonPathOffset);
            general->AddItem({ "Unicode Common Path", ls.Format("%ls", (uint8*) lnk->networkShareInformation + unicodeCommonPathOffset) });
        }

        general->AddItem({ "Network Share Name",
                           ls.Format("%s", (uint8*) lnk->networkShareInformation + lnk->networkShareInformation->networkShareNameOffset) });

        if (lnk->networkShareInformation->deviceNameOffset > 0)
        {
            general->AddItem({ "Device Name",
                               ls.Format("%s", (uint8*) lnk->networkShareInformation + lnk->networkShareInformation->deviceNameOffset) });
        }
    }
}

void Panels::LocationInformation::UpdateIssues()
{
}

void Panels::LocationInformation::RecomputePanelsPositions()
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

bool Panels::LocationInformation::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool Panels::LocationInformation::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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

void Panels::LocationInformation::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
