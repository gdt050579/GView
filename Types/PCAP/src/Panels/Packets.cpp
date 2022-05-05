#include "PCAP.hpp"

namespace GView::Type::PCAP::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4
};

Packets::Packets(Reference<PCAPFile> _pcap, Reference<GView::View::WindowInterface> _win) : TabPage("&Packets")
{
    pcap = _pcap;
    win  = _win;
    Base = 16;

    list = Factory::ListView::Create(
          this,
          "d:c",
          { { "Seconds", TextAlignament::Right, 16 },
            { "Microseconds", TextAlignament::Right, 16 },
            { "Octets Saved", TextAlignament::Right, 16 },
            { "Actual Length", TextAlignament::Right, 16 } },
          ListViewFlags::None);

    Update();
}

std::string_view Packets::GetValue(NumericFormatter& n, uint64 value)
{
    if (Base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Panels::Packets::GoToSelectedSection()
{
    auto record       = list->GetCurrentItem().GetData<const std::pair<PacketHeader*, uint32>>();
    const auto offset = record->second;

    win->GetCurrentView()->GoTo(offset);
}

void Panels::Packets::SelectCurrentSection()
{
    auto record       = list->GetCurrentItem().GetData<const std::pair<PacketHeader*, uint32>>();
    const auto offset = record->second;
    const auto size   = record->first->inclLen + sizeof(PacketHeader);

    win->GetCurrentView()->Select(offset, size);
}

void Panels::Packets::Update()
{
    list->DeleteAllItems();

    LocalString<128> tmp;
    NumericFormatter n;

    for (auto i = 0ULL; i < pcap->packetHeaders.size(); i++)
    {
        auto& record                 = pcap->packetHeaders[i];
        const auto& [header, offset] = record;
        auto item                    = list->AddItem({ tmp.Format("%s", GetValue(n, header->tsSec).data()) });
        item.SetText(1, tmp.Format("%s", GetValue(n, header->tsUsec).data()));
        item.SetText(2, tmp.Format("%s", GetValue(n, header->inclLen).data()));
        item.SetText(3, tmp.Format("%s", GetValue(n, header->origLen).data()));

        item.SetData<std::pair<PacketHeader*, uint32>>(&record);
    }
}

bool Panels::Packets::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    commandBar.SetCommand(Key::Enter, "GoTo", static_cast<int32_t>(ObjectAction::GoTo));
    commandBar.SetCommand(Key::F9, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(Key::F2, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));

    return true;
}

bool Panels::Packets::OnEvent(Reference<Control> ctrl, Event evnt, int controlID)
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

} // namespace GView::Type::PCAP::Panels
