#include "zip.hpp"

namespace GView::Type::ZIP::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Objects::Objects(Reference<ZIPFile> _zip, Reference<GView::View::WindowInterface> _win) : TabPage("&Objects")
{
    zip  = _zip;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { "n:Filename,a:l,w:100",
            "n:&Type,a:l,w:20",
            "n:&Compressed Size,a:r,w:20",
            "n:&Uncompressed Size,a:r,w:20",
            "n:&Compression Method,a:r,w:20",
            "n:&Disk Number,a:r,w:20",
            "n:&Disk Offset,a:r,w:20" },
          ListViewFlags::None);

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
    // auto record       = list->GetCurrentItem().GetData<ECMA_119_DirectoryRecord>();
    // const auto offset = record->locationOfExtent.LSB * ISO::ECMA_119_SECTOR_SIZE;
    //
    // win->GetCurrentView()->GoTo(offset);
}

void Panels::Objects::SelectCurrentSection()
{
    // auto record       = list->GetCurrentItem().GetData<ECMA_119_DirectoryRecord>();
    // const auto offset = record->locationOfExtent.LSB * ISO::ECMA_119_SECTOR_SIZE;
    // const auto size   = record->dataLength.LSB;
    //
    // win->GetCurrentView()->Select(offset, size);
}

void Panels::Objects::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    for (auto i = 0U; i < zip->info.GetCount(); i++)
    {
        GView::ZIP::Entry entry{ 0 };
        CHECKBK(zip->info.GetEntry(i, entry), "");

        const auto filename = entry.GetFilename();
        auto item           = list->AddItem(filename);
        item.SetText(1, tmp.Format("%s (%s)", entry.GetTypeName().data(), GetValue(n, (uint32) entry.GetType()).data()));
        item.SetText(2, tmp.Format("%s", GetValue(n, entry.GetCompressedSize()).data()));
        item.SetText(3, tmp.Format("%s", GetValue(n, entry.GetUncompressedSize()).data()));
        item.SetText(4, tmp.Format("%s (%s)", entry.GetCompressionMethodName().data(), GetValue(n, entry.GetCompressionMethod()).data()));
        item.SetText(5, tmp.Format("%s", GetValue(n, entry.GetDiskNumber()).data()));
        item.SetText(6, tmp.Format("%s", GetValue(n, entry.GetDiskOffset()).data()));

        //     item.SetData<ECMA_119_DirectoryRecord>(&iso->records[i]);
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

    if (evnt == Event::ListViewItemPressed)
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

} // namespace GView::Type::ZIP::Panels
