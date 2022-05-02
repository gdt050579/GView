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
            UpdateExtraData_EnvironmentVariablesLocation((ExtraData_EnvironmentVariablesLocation*) extraData);
            break;
        case ExtraDataSignatures::ConsoleProperties:
            UpdateExtraData_ConsoleProperties((ExtraData_ConsoleProperties*) extraData);
            break;
        case ExtraDataSignatures::DistributedLinkTrackerProperties:
            UpdateExtraData_DistributedLinkTrackerProperties((ExtraData_DistributedLinkTrackerProperties*) extraData);
            break;
        case ExtraDataSignatures::ConsoleCodepage:
            UpdateExtraData_ConsoleCodepage((ExtraData_ConsoleCodepage*) extraData);
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
    AddGUIDElement(general, "Identifier", data->identifier);
    AddDecAndHexElement("First Child Segment Offset", "%-20s (%s)", data->firstChildSegmentOffset);
}

void ExtraData::UpdateExtraData_EnvironmentVariablesLocation(ExtraData_EnvironmentVariablesLocation* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);
    general->AddItem({ "Location ASCII", ls.Format("%.*s", data->location, sizeof(data->location) / sizeof(data->location[0])) });
    general->AddItem({ "Location Unicode",
                       ls.Format("%.*S", data->unicodeLocation, sizeof(data->unicodeLocation) / sizeof(data->unicodeLocation[0])) });
}

void ExtraData::UpdateExtraData_ConsoleProperties(ExtraData_ConsoleProperties* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);

    AddDecAndHexElement("Color Flags", "%-20s (%s)", data->colorFlags);
    const auto colorFlags = LNK::GetConsoleColorFlags(data->colorFlags);
    for (const auto& flag : colorFlags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName = LNK::ConsoleColorFlagsNames.at(flag).data();
        general->AddItem({ "", ls.Format("%-20s %-4s", flagName, hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDecAndHexElement("Pop Up Fill Attributes", "%-20s (%s)", data->popUpFillAttributes);
    const auto popUpFillAttributes = LNK::GetConsoleColorFlags(data->popUpFillAttributes);
    for (const auto& flag : popUpFillAttributes)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        const auto flagName = LNK::ConsoleColorFlagsNames.at(flag).data();
        general->AddItem({ "", ls.Format("%-20s %-4s", flagName, hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);
    }

    AddDecAndHexElement("Screen Width Buffer Size", "%-20s (%s)", data->screenWidthBufferSize);
    AddDecAndHexElement("Screen Height Buffer Size", "%-20s (%s)", data->screenHeightBufferSize);
    AddDecAndHexElement("Window Width", "%-20s (%s)", data->windowWidth);
    AddDecAndHexElement("Window Height", "%-20s (%s)", data->windowHeight);
    AddDecAndHexElement("Window Origin X Coordinate", "%-20s (%s)", data->windowOriginXCoordinate);
    AddDecAndHexElement("Window Origin Y Coordinate", "%-20s (%s)", data->windowOriginYCoordinate);
    AddDecAndHexElement("Unknown0", "%-20s (%s)", data->unknown0);
    AddDecAndHexElement("Unknown1", "%-20s (%s)", data->unknown1);
    AddDecAndHexElement("Font Size", "%-20s (%s)", data->fontSize);

    LocalString<128> hfls;
    hfls.Format("(0x%X)", data->fontFamily);
    const auto fontFamily = LNK::ConsoleFontFamilyNames.at(data->fontFamily).data();
    general->AddItem({ "Font Family", ls.Format("%-20s %-4s", fontFamily, hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);

    hfls.Format("(0x%X)", data->fontWeigth);
    general->AddItem({ "Font Weigth", ls.Format("%-20s %-4s", data->fontWeigth < 700 ? "Regular" : "Bold", hfls.GetText()) });
    general->AddItem({ "Face Name", ls.Format("%*.S", sizeof(data->faceName) / sizeof(data->faceName[0]), data->faceName) });
    hfls.Format("(0x%X)", data->cursorSize);
    general->AddItem({ "Font Weigth",
                       ls.Format(
                             "%-20s %-4s",
                             data->cursorSize <= 25   ? "Small"
                             : data->cursorSize <= 50 ? "Normal"
                                                      : "Large",
                             hfls.GetText()) });
    AddDecAndHexElement("Full Screen", "%-20s (%s)", data->fullScreen);
    AddDecAndHexElement("Quick Edit", "%-20s (%s)", data->quickEdit);
    AddDecAndHexElement("Insert Mode", "%-20s (%s)", data->insertMode);
    AddDecAndHexElement("Auto Position", "%-20s (%s)", data->autoPosition);
    AddDecAndHexElement("History Buffer Size", "%-20s (%s)", data->historyBufferSize);
    AddDecAndHexElement("Number Of History Buffers", "%-20s (%s)", data->numberOfHistoryBuffers);
    AddDecAndHexElement("History No Dup", "%-20s (%s)", data->historyNoDup);

    hfls.Clear();
    for (const auto& c : data->colorTable)
    {
        hfls.AddFormat("%02X", c);
    }
    general->AddItem({ "Color Table", ls.Format("%s", fontFamily, hfls.GetText()) });
}

void ExtraData::UpdateExtraData_DistributedLinkTrackerProperties(ExtraData_DistributedLinkTrackerProperties* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);
    AddDecAndHexElement("Size Of Distributed Link Tracker Data", "%-20s (%s)", data->sizeOfDistributedLinkTrackerData);
    AddDecAndHexElement("Version Of Distributed Link Tracker Data", "%-20s (%s)", data->versionOfDistributedLinkTrackerData);
    general->AddItem({ "Machine Identifier String",
                       ls.Format(
                             "%*.s",
                             sizeof(data->machineIdentifierString) / sizeof(data->machineIdentifierString[0]),
                             data->machineIdentifierString) });
    AddGUIDElement(general, "Droid Volume Identifier", data->droidVolumeIdentifier);
    AddGUIDElement(general, "Droid File Identifier", data->droidFileIdentifier);
    AddGUIDElement(general, "Birth Droid Volume Identifier", data->birthDroidVolumeIdentifier);
    AddGUIDElement(general, "Birth Droid File Identifier", data->birthDroidFileIdentifier);
}

void ExtraData::UpdateExtraData_ConsoleCodepage(ExtraData_ConsoleCodepage* data)
{
    UpdateExtraDataBase(&data->base);
    AddDecAndHexElement("Code Page", "%-20s (%s)", data->codePage);
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
