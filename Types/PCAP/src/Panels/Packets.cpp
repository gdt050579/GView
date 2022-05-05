#include "PCAP.hpp"

namespace GView::Type::PCAP::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

enum class ObjectAction : int32
{
    GoTo       = 1,
    Select     = 2,
    ChangeBase = 4,
    OpenPacket = 8,
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

void Panels::Packets::OpenPacket()
{
    class Dialog : public Window
    {
        Reference<GView::Object> object;
        Reference<ListView> list;
        int32 base;

        std::string_view GetValue(NumericFormatter& n, uint64 value)
        {
            if (base == 10)
            {
                return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
            }

            return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
        }

      public:
        Dialog(
              Reference<GView::Object> _object,
              std::string_view name,
              std::string_view layout,
              LinkType type,
              const PacketHeader* packet,
              int32 _base,
              bool swap)
            : Window(name, layout, WindowFlags::ProcessReturn | WindowFlags::FixedPosition), base(_base)
        {
            object = _object;

            list = CreateChildControl<ListView>(
                  "x:0,y:0,w:100%,h:28",
                  std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 24 } },
                  ListViewFlags::None);

            LocalString<128> tmp;
            NumericFormatter n;

            list->AddItem("Header").SetType(ListViewItem::Type::Category);
            list->AddItem({ "Seconds", tmp.Format("%s", GetValue(n, packet->tsSec).data()) });
            list->AddItem({ "MicroSeconds", tmp.Format("%s", GetValue(n, packet->tsUsec).data()) });
            auto itemInclLen = list->AddItem({ "Saved Length", tmp.Format("%s", GetValue(n, packet->inclLen).data()) });
            if (packet->inclLen != packet->origLen)
            {
                itemInclLen.SetType(ListViewItem::Type::WarningInformation);
            }
            list->AddItem({ "Original Length", tmp.Format("%s", GetValue(n, packet->origLen).data()) });

            if (type == LinkType::ETHERNET)
            {
                list->AddItem("ETHERNET").SetType(ListViewItem::Type::Category);

                auto peh = (Package_EthernetHeader*) ((uint8*) packet + sizeof(PacketHeader));

                union IP
                {
                    unsigned char arr[6];
                    uint64 value;
                };

                IP etherDHost{ 0 };
                IP etherSHost{ 0 };
                memcpy(&etherDHost, peh->etherDhost, 6);
                memcpy(&etherSHost, peh->etherShost, 6);

                if (swap)
                {
                    etherDHost.value = AppCUI::Endian::BigToNative(etherDHost.value);
                    etherSHost.value = AppCUI::Endian::BigToNative(etherSHost.value);
                }

                list->AddItem({ "Destination Host", tmp.Format("%s", GetValue(n, etherDHost.value).data()) });
                list->AddItem({ "Destination Host",
                                tmp.Format(
                                      "%02X.%02X.%02X.%02X.%02X.%02X",
                                      etherDHost.arr[0],
                                      etherDHost.arr[1],
                                      etherDHost.arr[2],
                                      etherDHost.arr[3],
                                      etherDHost.arr[4],
                                      etherDHost.arr[5]) });
                list->AddItem({ "Source Host", tmp.Format("%s", GetValue(n, etherSHost.value).data()) });
                list->AddItem({ "Source Host",
                                tmp.Format(
                                      "%02X.%02X.%02X.%02X.%02X.%02X",
                                      etherSHost.arr[0],
                                      etherSHost.arr[1],
                                      etherSHost.arr[2],
                                      etherSHost.arr[3],
                                      etherSHost.arr[4],
                                      etherSHost.arr[5]) });

                auto eType = peh->etherType;
                if (swap)
                {
                    eType = AppCUI::Endian::BigToNative(peh->etherType);
                }
                const auto etherType      = PCAP::GetEtherType(swap ? eType : AppCUI::Endian::Swap(eType));
                const auto& etherTypeName = PCAP::EtherTypeNames.at(etherType).data();
                const auto etherTypeHex   = GetValue(n, eType);
                list->AddItem({ "Type", tmp.Format("%-10s (%s)", etherTypeName, etherTypeHex.data()) })
                      .SetType(ListViewItem::Type::Emphasized_1);
            }
            else
            {
                list->AddItem("Unknown").SetType(ListViewItem::Type::Category);
            }

            // this->Resize(this->GetWidth(), list->GetItemsCount() + 10);
            // list->Resize(list->GetWidth(), list->GetItemsCount() + 3);
        }
    };

    auto itemData      = list->GetCurrentItem().GetData<const std::pair<PacketHeader*, uint32>>();
    const auto& packet = itemData->first;

    LocalString<128> ls;
    ls.Format("d:c,w:50,h:30", this->GetHeight());
    Dialog dialog(
          nullptr,
          PCAP::LinkTypeNames.at(pcap->header.network).data(),
          ls.GetText(),
          pcap->header.network,
          packet,
          Base,
          pcap->header.magicNumber == Magic::Swapped);
    dialog.Show();
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
    commandBar.SetCommand(Key::Ctrl | Key::Enter, "Open Packet", static_cast<int32_t>(ObjectAction::OpenPacket));

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
        case ObjectAction::OpenPacket:
            OpenPacket();
            return true;
        }
    }

    return false;
}

} // namespace GView::Type::PCAP::Panels
