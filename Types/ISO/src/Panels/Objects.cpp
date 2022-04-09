#include "iso.hpp"

namespace GView::Type::ISO::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Objects::Objects(Reference<ISOFile> _iso, Reference<GView::View::WindowInterface> _win) : TabPage("&Objects")
{
    iso  = _iso;
    win  = _win;
    Base = 16;

    list = CreateChildControl<ListView>("d:c", ListViewFlags::None);
    list->AddColumn("LEN-DR", TextAlignament::Right, 10);
    list->AddColumn("Attr Len", TextAlignament::Right, 10);
    list->AddColumn("Extent Location", TextAlignament::Right, 17);
    list->AddColumn("Data Length", TextAlignament::Right, 13);
    list->AddColumn("Date", TextAlignament::Right, 25);
    list->AddColumn("File Flags", TextAlignament::Right, 28);
    list->AddColumn("File Unit Size", TextAlignament::Right, 11);
    list->AddColumn("Interleave Gap Size", TextAlignament::Right, 21);
    list->AddColumn("Volume Sequence Number", TextAlignament::Right, 24);
    list->AddColumn("LEN-FI", TextAlignament::Right, 10);
    list->AddColumn("File Identifier", TextAlignament::Left, 100);

    Update();
}

std::string_view Objects::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Objects::GoToSelectedSection()
{
    auto record       = list->GetItemData<ECMA_119_DirectoryRecord>(list->GetCurrentItem());
    const auto offset = record->locationOfExtent.LSB * ISO::ECMA_119_SECTOR_SIZE;

    win->GetCurrentView()->GoTo(offset);
}

void Panels::Objects::SelectCurrentSection()
{
    auto record       = list->GetItemData<ECMA_119_DirectoryRecord>(list->GetCurrentItem());
    const auto offset = record->locationOfExtent.LSB * ISO::ECMA_119_SECTOR_SIZE;
    const auto size   = record->dataLength.LSB;

    win->GetCurrentView()->Select(offset, size);
}

void Panels::Objects::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    for (auto i = 0ULL; i < iso->records.size(); i++)
    {
        const auto& record = iso->records[i];
        const auto item    = list->AddItem(tmp.Format("%s", GetValue(n, record.lengthOfDirectoryRecord).data()));
        list->SetItemText(item, 1, tmp.Format("%s", GetValue(n, record.extendedAttributeRecordLength).data()));
        list->SetItemText(item, 2, tmp.Format("%s", GetValue(n, record.locationOfExtent.LSB).data()));
        list->SetItemText(item, 3, tmp.Format("%s", GetValue(n, record.dataLength.LSB).data()));

        const auto gmt         = record.recordingDateAndTime[6];
        const uint8 gmtHours   = gmt / 4;
        const uint8 gmtMinutes = std::abs((gmt % 4) * 15);

        list->SetItemText(
              item,
              4,
              tmp.Format(
                    "%.4d-%.2d-%.2d %.2d:%.2d:%.2d %.2d:%.2d",
                    1900 + record.recordingDateAndTime[0],
                    record.recordingDateAndTime[1],
                    record.recordingDateAndTime[2],
                    record.recordingDateAndTime[3],
                    record.recordingDateAndTime[4],
                    record.recordingDateAndTime[5],
                    gmtHours,
                    gmtMinutes));

        list->SetItemText(
              item, 5, tmp.Format("[%s] %s", GetECMA_119_FileFlags(record.fileFlags).c_str(), GetValue(n, record.fileFlags).data()));
        list->SetItemText(item, 6, tmp.Format("%s", GetValue(n, record.fileUnitSize).data()));
        list->SetItemText(item, 7, tmp.Format("%s", GetValue(n, record.interleaveGapSize).data()));
        list->SetItemText(item, 8, tmp.Format("%s", GetValue(n, record.volumeSequenceNumber).data()));
        list->SetItemText(item, 9, tmp.Format("%s", GetValue(n, record.lengthOfFileIdentifier).data()));
        list->SetItemText(item, 10, tmp.Format("%.*s", record.lengthOfFileIdentifier, record.fileIdentifier));

        list->SetItemData<ECMA_119_DirectoryRecord>(item, &iso->records[i]);
    }
}

bool Panels::Objects::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));

    return true;
}

bool Panels::Objects::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
{
    CHECK(TabPage::OnEvent(ctrl, evnt, controlID) == false, true, "");

    if (evnt == Event::ListViewItemClicked)
    {
        GoToSelectedSection();
        return true;
    }

    if (evnt == Event::Command)
    {
        switch (static_cast<ObjectAction>(controlID))
        {
        case ObjectAction::GoTo:
            GoToSelectedSection();
            return true;
        case ObjectAction::ChangeBase:
            Base = 26 - Base;
            Update();
            return true;
        case ObjectAction::Select:
            SelectCurrentSection();
            return true;
        }
    }

    return false;
}

} // namespace GView::Type::ISO::Panels
