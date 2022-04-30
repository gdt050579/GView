#include "LNK.hpp"

using namespace GView::Type::LNK;
using namespace GView::Type::LNK::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

ExtraData::ExtraData(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk) : TabPage("&ExtraData")
{
    lnk     = _lnk;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10",
          std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 100 } },
          ListViewFlags::None);

    Update();
}

void ExtraData::UpdateGeneralInformation()
{
    LocalString<1024> ls;
    LocalString<1024> ls2;

    for (const auto& extraData : lnk->extraDataBases)
    {
        switch (extraData->signature)
        {
        case ExtraDataSignatures::EnvironmentVariablesLocation:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::ConsoleProperties:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::DistributedLinkTrackerProperties:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::ConsoleCodepage:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::SpecialFolderLocation:
            UpdateExtraData_SpecialFolderLocation((ExtraData_SpecialFolderLocation*) extraData);
            break;
        case ExtraDataSignatures::DarwinProperties:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::IconLocation:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::ShimLayerProperties:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::MetadataPropertyStore:
            UpdateExtraDataBase(extraData);
            break;
        case ExtraDataSignatures::KnownFolderLocation:
            UpdateExtraData_KnownFolderLocation((ExtraData_KnownFolderLocation*) extraData);
            break;
        case ExtraDataSignatures::ShellItemIdentifiersListProperties:
            UpdateExtraDataBase(extraData);
            break;
        default:
            UpdateExtraDataBase(extraData);
            break;
        }
    }
}

void ExtraData::UpdateExtraDataBase(ExtraDataBase* base)
{
    const auto& signatureName = LNK::ExtraDataSignaturesNames.at(base->signature).data();

    general->AddItem(signatureName).SetType(ListViewItem::Type::Category);

    AddDecAndHexElement("Size", "%-20s (%s)", base->size);
    AddDecAndHexElement("Signature", "%-20s (%s)", (uint32) base->signature);
}

void ExtraData::UpdateExtraData_SpecialFolderLocation(ExtraData_SpecialFolderLocation* data)
{
    UpdateExtraDataBase(&data->base);
    AddDecAndHexElement("Identifier", "%-20s (%s)", data->identifier);
    AddDecAndHexElement("First Child Segment Offset", "%-20s (%s)", data->firstChildSegmentOffset);
}

void ExtraData::UpdateExtraData_KnownFolderLocation(ExtraData_KnownFolderLocation* data)
{
    UpdateExtraDataBase(&data->base);
    AddGUIDElement(general, "Identifier", data->identifier); // TODO: map GUIDS
    AddDecAndHexElement("First Child Segment Offset", "%-20s (%s)", data->firstChildSegmentOffset);
}

void ExtraData::UpdateIssues()
{
}

void ExtraData::RecomputePanelsPositions()
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

bool ExtraData::OnUpdateCommandBar(Application::CommandBar& commandBar)
{
    // commandBar.SetCommand(AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10, "placeholder_name", CMD_ID);
    return true;
}

bool ExtraData::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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

void ExtraData::Update()
{
    general->DeleteAllItems();

    UpdateGeneralInformation();
    UpdateIssues();
    RecomputePanelsPositions();
}
