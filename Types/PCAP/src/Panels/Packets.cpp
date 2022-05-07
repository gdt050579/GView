#include "PCAP.hpp"

namespace GView::Type::PCAP::Panels
{
using namespace AppCUI::Controls;
using namespace AppCUI::Endian;
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
          { { "#", TextAlignament::Right, 6 },
            { "Timestamp", TextAlignament::Right, 20 },
            { "Seconds", TextAlignament::Right, 16 },
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
                  "x:0,y:0,w:100%,h:48",
                  std::initializer_list<ColumnBuilder>{ { "Field", TextAlignament::Left, 24 }, { "Value", TextAlignament::Left, 24 } },
                  ListViewFlags::None);

            LocalString<128> tmp;
            NumericFormatter n;

            list->AddItem("Header").SetType(ListViewItem::Type::Category);

            auto timestamp = packet->tsSec * (uint64) 1000000 + packet->tsUsec;
            timestamp /= 1000000;
            AppCUI::OS::DateTime dt;
            dt.CreateFromTimestamp(timestamp);

            list->AddItem({ "Timestamp", tmp.Format("%s", dt.GetStringRepresentation().data()) });
            list->AddItem({ "Seconds", tmp.Format("%s", GetValue(n, packet->tsSec).data()) });
            list->AddItem({ "MicroSeconds", tmp.Format("%s", GetValue(n, packet->tsUsec).data()) });
            auto itemInclLen = list->AddItem({ "Saved Length", tmp.Format("%s", GetValue(n, packet->inclLen).data()) });
            if (packet->inclLen != packet->origLen)
            {
                itemInclLen.SetType(ListViewItem::Type::WarningInformation);
            }
            list->AddItem({ "Original Length", tmp.Format("%s", GetValue(n, packet->origLen).data()) });

            list->AddItem(LinkTypeNames.at(type).data()).SetType(ListViewItem::Type::Category);
            if (type == LinkType::ETHERNET)
            {
                auto peh = (Package_EthernetHeader*) ((uint8*) packet + sizeof(PacketHeader));

                MAC etherDHost{ 0 };
                MAC etherSHost{ 0 };
                memcpy(&etherDHost, peh->etherDhost, 6);
                memcpy(&etherSHost, peh->etherShost, 6);

                if (swap)
                {
                    etherDHost.value = AppCUI::Endian::BigToNative(etherDHost.value);
                    etherSHost.value = AppCUI::Endian::BigToNative(etherSHost.value);
                }

                list->AddItem({ "Destination Host", tmp.Format("%s", GetValue(n, etherDHost.value).data()) });
                AddMACElement(list, "Destination Host", etherDHost);
                list->AddItem({ "Source Host", tmp.Format("%s", GetValue(n, etherSHost.value).data()) });
                AddMACElement(list, "Source Host", etherSHost);

                auto eType = peh->etherType;
                if (swap == false)
                {
                    eType = AppCUI::Endian::BigToNative(peh->etherType);
                }
                const auto etherType      = PCAP::GetEtherType(eType);
                const auto& etherTypeName = PCAP::EtherTypeNames.at(etherType).data();
                const auto etherTypeHex   = GetValue(n, eType);
                list->AddItem({ "Type", tmp.Format("%-10s (%s)", etherTypeName, etherTypeHex.data()) })
                      .SetType(ListViewItem::Type::Emphasized_1);

                list->AddItem(etherTypeName).SetType(ListViewItem::Type::Category);
                if (etherType == EtherType::IPv4)
                {
                    auto ipv4 = (IPv4Header*) ((uint8*) peh + sizeof(Package_EthernetHeader));
                    list->AddItem({ "Length", tmp.Format("%s", GetValue(n, BigToNative(ipv4->headerLength)).data()) });
                    list->AddItem({ "Version", tmp.Format("%s", GetValue(n, BigToNative(ipv4->version)).data()) });

                    const auto& dscpName = PCAP::DscpTypeNames.at((DscpType) BigToNative((uint8) ipv4->dscp)).data();
                    const auto dscpHex   = GetValue(n, BigToNative((uint8) ipv4->dscp));
                    list->AddItem({ "DSCP", tmp.Format("%-10s (%s)", dscpName, dscpHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

                    const auto& ecnName = PCAP::EcnTypeNames.at((EcnType) BigToNative((uint8) ipv4->ecn)).data();
                    const auto ecnHex   = GetValue(n, BigToNative((uint8) ipv4->ecn));
                    list->AddItem({ "ECN", tmp.Format("%-10s (%s)", ecnName, dscpHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

                    list->AddItem({ "Total Length", tmp.Format("%s", GetValue(n, BigToNative(ipv4->totalLength)).data()) });
                    list->AddItem({ "Identification", tmp.Format("%s", GetValue(n, BigToNative(ipv4->identification)).data()) });

                    auto fragmentation  = ipv4->fragmentation;
                    fragmentation.value = BigToNative(fragmentation.value);
                    list->AddItem({ "Flags", tmp.Format("%s", GetValue(n, fragmentation.flags).data()) });

                    {
                        FragmentationFlags ff{};
                        ff.flags = fragmentation.flags;
                        if (ff.moreFragments)
                        {
                            list->AddItem({ "", "More Fragments" }).SetType(ListViewItem::Type::Emphasized_2);
                        }
                        if (ff.dontFragment)
                        {
                            list->AddItem({ "", "Don't Fragment" }).SetType(ListViewItem::Type::Emphasized_2);
                        }
                        if (ff.reserved)
                        {
                            list->AddItem({ "", "Reserved" }).SetType(ListViewItem::Type::Emphasized_2);
                        }
                    }

                    list->AddItem({ "Fragment Offset", tmp.Format("%s", GetValue(n, fragmentation.fragmentOffset).data()) });

                    list->AddItem({ "TTL", tmp.Format("%s", GetValue(n, BigToNative(ipv4->ttl)).data()) });

                    const auto& protocolName = PCAP::IPv4_ProtocolNames.at((IPv4_Protocol) BigToNative((uint8) ipv4->protocol)).data();
                    const auto protocolHex   = GetValue(n, BigToNative((uint8) ipv4->protocol));
                    list->AddItem({ "Protocol", tmp.Format("%-10s (%s)", protocolName, protocolHex.data()) })
                          .SetType(ListViewItem::Type::Emphasized_1);

                    list->AddItem({ "CRC", tmp.Format("%s", GetValue(n, BigToNative(ipv4->crc)).data()) });

                    list->AddItem({ "Source Address", tmp.Format("%s", GetValue(n, BigToNative(ipv4->sourceAddress)).data()) });
                    AddIPElement(list, "Source Address", BigToNative(ipv4->sourceAddress));

                    list->AddItem({ "Destination Address", tmp.Format("%s", GetValue(n, BigToNative(ipv4->destinationAddress)).data()) });
                    AddIPElement(list, "Destination Address", BigToNative(ipv4->destinationAddress));

                    list->AddItem(protocolName).SetType(ListViewItem::Type::Category);
                    if ((IPv4_Protocol) BigToNative((uint8) ipv4->protocol) == IPv4_Protocol::TCP)
                    {
                        auto tcp = (TCPHeader*) ((uint8*) ipv4 + sizeof(IPv4Header));

                        list->AddItem({ "Source Port", tmp.Format("%s", GetValue(n, BigToNative(tcp->sPort)).data()) });
                        list->AddItem({ "Destination Port", tmp.Format("%s", GetValue(n, BigToNative(tcp->dPort)).data()) });
                        list->AddItem({ "Sequence Number", tmp.Format("%s", GetValue(n, BigToNative(tcp->seq)).data()) });
                        list->AddItem({ "Acknowledgement Number", tmp.Format("%s", GetValue(n, BigToNative(tcp->ack)).data()) });
                        list->AddItem({ "Data Offset", tmp.Format("%s", GetValue(n, BigToNative(tcp->dataOffset)).data()) });
                        list->AddItem({ "Rsvd", tmp.Format("%s", GetValue(n, BigToNative(tcp->rsvd)).data()) });

                        list->AddItem({ "Flags", tmp.Format("%s", GetValue(n, BigToNative(tcp->flags)).data()) });
                        const auto lFlags = PCAP::GetTCPHeader_Flags(BigToNative(tcp->flags));
                        for (const auto& [flag, name] : lFlags)
                        {
                            LocalString<16> hfls;
                            hfls.Format("(0x%X)", flag);

                            list->AddItem({ "", tmp.Format("%-20s %-4s", name.data(), hfls.GetText()) })
                                  .SetType(ListViewItem::Type::Emphasized_2);
                        }

                        list->AddItem({ "Window", tmp.Format("%s", GetValue(n, BigToNative(tcp->win)).data()) });
                        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, BigToNative(tcp->sum)).data()) });
                        list->AddItem({ "Urgent Pointer", tmp.Format("%s", GetValue(n, BigToNative(tcp->urp)).data()) });

                        constexpr auto minSize = sizeof(Package_EthernetHeader) + sizeof(IPv4Header) + sizeof(TCPHeader);
                        uint32 delta           = packet->inclLen - (uint32) minSize;
                        if (tcp->dataOffset > 5)
                        {
                            if (delta > 0)
                            {
                                auto options   = ((uint8*) tcp + sizeof(TCPHeader));
                                const auto end = options + delta;
                                auto kind      = TCPHeader_OptionsKind::EndOfOptionsList;
                                auto option    = (TCPHeader_Options*) options;
                                do
                                {
                                    option               = (TCPHeader_Options*) options;
                                    kind                 = option->kind;
                                    const auto& kindName = TCPHeader_OptionsKindNames.at(kind).data();
                                    const auto kindHex   = GetValue(n, BigToNative((uint8) kind));
                                    list->AddItem({ "Option: Kind", tmp.Format("%-10s (%s)", kindName, kindHex.data()) })
                                          .SetType(ListViewItem::Type::Emphasized_1);

                                    switch (kind)
                                    {
                                    case TCPHeader_OptionsKind::EndOfOptionsList:
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, 1).data()) });
                                        break;
                                    case TCPHeader_OptionsKind::NoOperation:
                                        options = ((uint8*) options + 1);
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, 1).data()) });
                                        break;
                                    case TCPHeader_OptionsKind::MaximumSegmentSize:
                                        options = ((uint8*) options + option->length);
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, option->length).data()) });
                                        list->AddItem({ "Option: MSS",
                                                        tmp.Format(
                                                              "%s",
                                                              GetValue(n, *(uint32*) ((uint8*) &option->length + sizeof(option->length)))
                                                                    .data()) });
                                        break;
                                    case TCPHeader_OptionsKind::WindowScale:
                                        options = ((uint8*) options + option->length);
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, option->length).data()) });
                                        break;
                                    case TCPHeader_OptionsKind::SelectiveAcknowledgementPermitted:
                                        options = ((uint8*) options + option->length);
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, option->length).data()) });
                                        break;
                                    case TCPHeader_OptionsKind::SACK:
                                        options = ((uint8*) options + option->length);
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, option->length).data()) });
                                        break;
                                    case TCPHeader_OptionsKind::TimestampAndEchoOfPreviousTimestamp:
                                        options = ((uint8*) options + option->length);
                                        list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, option->length).data()) });
                                        break;
                                    default:
                                        break;
                                    }
                                } while (kind != TCPHeader_OptionsKind::EndOfOptionsList && (uint8*) option + option->length < end);

                                const auto optionLen =
                                      kind == TCPHeader_OptionsKind::EndOfOptionsList || kind == TCPHeader_OptionsKind::NoOperation
                                            ? 1
                                            : option->length;
                                const auto deltaReached = (uint8*) option + optionLen - (uint8*) tcp - sizeof(TCPHeader);
                                delta                   = (uint32) (deltaReached % 4 != 0) ? ((deltaReached / 4) + 1) * 4 : deltaReached;
                                delta                   = packet->inclLen - minSize - delta;
                            }
                        }

                        if (delta > 6)
                        {
                            list->AddItem({ "Payload Size", tmp.Format("%s", GetValue(n, delta).data()) })
                                  .SetType(ListViewItem::Type::Emphasized_2);
                        }
                    }
                }
                else
                {
                    list->AddItem("Unknown").SetType(ListViewItem::Type::Category);
                }
            }
            else
            {
                list->AddItem("Unknown").SetType(ListViewItem::Type::Category);
            }
        }
    };

    auto itemData      = list->GetCurrentItem().GetData<const std::pair<PacketHeader*, uint32>>();
    const auto& packet = itemData->first;

    LocalString<128> ls;
    ls.Format("d:c,w:50,h:50", this->GetHeight());
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

        auto timestamp = header->tsSec * (uint64) 1000000 + header->tsUsec;
        timestamp /= 1000000;
        AppCUI::OS::DateTime dt;
        dt.CreateFromTimestamp(timestamp);

        auto item = list->AddItem({ tmp.Format("%s", GetValue(n, i).data()) });
        item.SetText(1, tmp.Format("%s", dt.GetStringRepresentation().data()));
        item.SetText(2, tmp.Format("%s", GetValue(n, header->tsSec).data()));
        item.SetText(3, tmp.Format("%s", GetValue(n, header->tsUsec).data()));
        item.SetText(4, tmp.Format("%s", GetValue(n, header->inclLen).data()));
        item.SetText(5, tmp.Format("%s", GetValue(n, header->origLen).data()));

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
