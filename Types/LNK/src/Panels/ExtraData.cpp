#include "LNK.hpp"

using namespace GView::Type::LNK;
using namespace GView::Type::LNK::Panels;
using namespace AppCUI::Controls;
using namespace AppCUI::OS;

ExtraData::ExtraData(Reference<Object> _object, Reference<GView::Type::LNK::LNKFile> _lnk) : ShellItems("&ExtraData")
{
    lnk     = _lnk;
    object  = _object;
    general = CreateChildControl<ListView>(
          "x:0,y:0,w:100%,h:10", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:100" }, ListViewFlags::None);

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
            UpdateExtraData_DarwinProperties((ExtraData_DarwinProperties*) extraData);
            break;
        case ExtraDataSignatures::IconLocation:
            UpdateExtraData_IconLocation((ExtraData_IconLocation*) extraData);
            break;
        case ExtraDataSignatures::ShimLayerProperties:
            UpdateExtraData_ShimLayer((ExtraData_ShimLayer*) extraData);
            break;
        case ExtraDataSignatures::MetadataPropertyStore:
            UpdateExtraData_MetadataPropertyStore((ExtraData_MetadataPropertyStore*) extraData);
            break;
        case ExtraDataSignatures::KnownFolderLocation:
            UpdateExtraData_KnownFolderLocation((ExtraData_KnownFolderLocation*) extraData);
            break;
        case ExtraDataSignatures::VistaAndAboveIDListDataBlock:
            UpdateExtraData_VistaAndAboveIDListDataBlock((ExtraData_VistaAndAboveIDListDataBlock*) extraData);
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

void ExtraData::UpdateExtraData_EnvironmentVariablesLocation(ExtraData_EnvironmentVariablesLocation* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);
    general->AddItem({ "Location ASCII", ls.Format("%.*s", sizeof(data->location) / sizeof(data->location[0]), data->location) });
    general->AddItem({ "Location Unicode",
                       ls.Format("%.*S", sizeof(data->unicodeLocation) / sizeof(data->unicodeLocation[0]), data->unicodeLocation) });
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
    general->AddItem({ "Face Name", ls.Format("%.*S", sizeof(data->faceName) / sizeof(data->faceName[0]), data->faceName) });
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
                             "%.*s",
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

void ExtraData::UpdateExtraData_SpecialFolderLocation(ExtraData_SpecialFolderLocation* data)
{
    UpdateExtraDataBase(&data->base);
    AddDecAndHexElement("Identifier", "%-20s (%s)", data->identifier);
    AddDecAndHexElement("First Child Segment Offset", "%-20s (%s)", data->firstChildSegmentOffset);
}

void ExtraData::UpdateExtraData_DarwinProperties(ExtraData_DarwinProperties* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);

    general->AddItem({ "Darwin Application Identifier",
                       ls.Format(
                             "%.*s",
                             sizeof(data->darwinApplicationIdentifier) / sizeof(data->darwinApplicationIdentifier[0]),
                             data->darwinApplicationIdentifier) });

    general->AddItem({ "Unicode Darwin Application Identifier",
                       ls.Format(
                             "%.*S",
                             sizeof(data->unicodeDarwinApplicationIdentifier) / sizeof(data->unicodeDarwinApplicationIdentifier[0]),
                             data->unicodeDarwinApplicationIdentifier) });
}

void ExtraData::UpdateExtraData_IconLocation(ExtraData_IconLocation* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);

    general->AddItem({ "Location ASCII", ls.Format("%.*s", sizeof(data->location) / sizeof(data->location[0]), data->location) });
    general->AddItem({ "Location Unicode",
                       ls.Format("%.*S", sizeof(data->unicodeLocation) / sizeof(data->unicodeLocation[0]), data->unicodeLocation) });
}

void ExtraData::UpdateExtraData_ShimLayer(ExtraData_ShimLayer* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);
    general->AddItem(
          { "Name", ls.Format("%.*ls", data->base.size - sizeof(ExtraData_ShimLayer), ((uint8*) &data) + sizeof(ExtraData_ShimLayer)) });
}

void ExtraData::UpdateExtraData_MetadataPropertyStore(ExtraData_MetadataPropertyStore* data)
{
    LocalString<1024> ls;

    UpdateExtraDataBase(&data->base);

    for (auto& [key, values] : lnk->propertyStores)
    {
        general->AddItem("PropertyStore").SetType(ListViewItem::Type::Category);
        AddDecAndHexElement("Size", "%-20s (%s)", key->size);

        auto offset = sizeof(PropertyStore_ShellPropertySheet);
        for (const auto& sheet : values)
        {
            general->AddItem("PropertyStore_ShellPropertySheet").SetType(ListViewItem::Type::Category);

            AddDecAndHexElement("Property Version", "%-20s (%s)", sheet->version);
            auto classElement = AddGUIDElement(general, "Format Class Identifier", sheet->formatClassIdentifier);

            while (offset < key->size - sizeof(PropertyStore) - sizeof(uint32) /* terminal */)
            {
                if (sheet->formatClassIdentifier == FMTID_UserDefinedProperties)
                {
                    classElement.SetType(ListViewItem::Type::ErrorInformation);
                    break;
                }
                else
                {
                    general->AddItem("PropertyStore_ShellPropertyNumeric").SetType(ListViewItem::Type::Category);

                    auto snpp = (PropertyStore_ShellPropertyNumeric*) ((uint8*) sheet + offset);
                    AddDecAndHexElement("Size", "%-20s (%s)", snpp->size);
                    auto identifierElement = AddDecAndHexElement("Identifier", "%-20s (%s)", snpp->identifier);
                    AddDecAndHexElement("Unknown0", "%-20s (%s)", snpp->unknown0);

                    general->AddItem("PropertyStore_TypedPropertyValue").SetType(ListViewItem::Type::Category);
                    AddDecAndHexElement("Type", "%-20s (%s)", snpp->value.type);
                    AddDecAndHexElement("Padding", "%-20s (%s)", snpp->value.padding);

                    if (sheet->formatClassIdentifier == FMTID_InternetSite)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == WPD_STORAGE_OBJECT_PROPERTIES_V1)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_SID)
                    {
                        general->AddItem("PropertyValueData_FMTID_SID").SetType(ListViewItem::Type::Category);

                        auto pvdSID = (PropertyValueData_FMTID_SID*) ((uint8*) &snpp->value.padding + sizeof(snpp->value.padding));
                        AddDecAndHexElement("Size", "%-20s (%s)", pvdSID->size);

                        const auto sidSize = pvdSID->size - sizeof(pvdSID);
                        general->AddItem({ "Name", ls.Format("%.*S", sidSize, pvdSID->SID) });
                    }
                    else if (sheet->formatClassIdentifier == UNKNOWN_1)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_Music)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_Image)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_Audio)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_Video)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_MediaFile)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == WPD_FUNCTIONAL_OBJECT_PROPERTIES_V1)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == UNKNOWN_2)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_Doc)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_UserDefinedProperties)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == WPD_OBJECT_PROPERTIES_V1)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_SummaryInformation)
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_ThumbnailCacheId)
                    {
                        general->AddItem("PropertyValueData_FMTID_ThumbnailCacheId").SetType(ListViewItem::Type::Category);

                        auto pvdtci =
                              (PropertyValueData_FMTID_ThumbnailCacheId*) ((uint8*) &snpp->value.padding + sizeof(snpp->value.padding));
                        AddGUIDElement(general, "ID", pvdtci->id);
                    }
                    else if (sheet->formatClassIdentifier == FMTID_InternetShortcut)
                    {
                        general->AddItem("PropertyValueData_FMTID_InternetShortcut").SetType(ListViewItem::Type::Category);

                        if (snpp->identifier == 0x05)
                        {
                            auto pvdis =
                                  (PropertyValueData_FMTID_InternetShortcut*) ((uint8*) &snpp->value.padding + sizeof(snpp->value.padding));
                            AddDecAndHexElement("Unknown", "%-20s (%s)", pvdis->size);
                            const auto URLSize = pvdis->size * sizeof(wchar_t);
                            general->AddItem({ "URL", ls.Format("%.*S", URLSize, pvdis->URL) });
                        }
                        else if (snpp->identifier == 0x1A)
                        {
                            auto buffer = (MyGUID*) ((uint8*) &snpp->value.padding + sizeof(snpp->value.padding));
                            AddGUIDElement(general, "FormatID(?)", *buffer);
                        }
                        else
                        {
                            identifierElement.SetType(ListViewItem::Type::ErrorInformation);
                        }
                    }
                    else
                    {
                        classElement.SetType(ListViewItem::Type::ErrorInformation);
                    }

                    offset += snpp->size;
                }
            }
        }
    }

    general
          ->AddItem(
                { "TODO:", "Map https://github.com/libyal/libfwps/blob/main/documentation/Windows%20Property%20Store%20format.asciidoc" })
          .SetType(ListViewItem::Type::ErrorInformation);
}

void ExtraData::UpdateExtraData_KnownFolderLocation(ExtraData_KnownFolderLocation* data)
{
    UpdateExtraDataBase(&data->base);
    AddGUIDElement(general, "Identifier", data->identifier);
    AddDecAndHexElement("First Child Segment Offset", "%-20s (%s)", data->firstChildSegmentOffset);
}

void ExtraData::UpdateExtraData_VistaAndAboveIDListDataBlock(ExtraData_VistaAndAboveIDListDataBlock* data)
{
    UpdateExtraDataBase(&data->base);

    auto item = (ItemID*) ((uint8*) &data->base + sizeof(data->base));
    std::vector<ItemID*> itemIDS;
    while (item->ItemIDSize != 0)
    {
        itemIDS.emplace_back((ItemID*) (item));
        item = (ItemID*) ((uint8*) item + item->ItemIDSize);
    }

    // TODO: random property store in shell item identifiers??? -> remote.file.aidlist.test & unicodeNetworkPath.lnk.test
    // [ [b3 00 00 00] [ad 00] [bb af 93 3b 9f] [00 04] [00 00 00 00 00] ] -> 41 00 00 00 1 S P S
    // [ [a3 00 00 00] [9d 00] [bb af 93 3b 8f] [00 04] [00 00 00 00 00] ] -> 2d 00 00 00 1 S P S
    // auto ps = (PropertyStore*) ((uint8*) (itemIDS[1]) + 18);
    // auto sps = (PropertyStore_ShellPropertySheet*) ((uint8*) (itemIDS[1]) + 22);
    // UpdateExtraData_MetadataPropertyStore();

    UpdateLinkTargetIDList(itemIDS);
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
