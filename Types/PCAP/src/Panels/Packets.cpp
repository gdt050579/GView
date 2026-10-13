#include "PCAP.hpp"

#include <numeric>

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
          { "n:#,a:r,w:6",
            "n:Timestamp,a:r,w:20",
            "n:Seconds,a:r,w:16",
            "n:Microseconds,a:r,w:16",
            "n:Octets Saved,a:r,w:16",
            "n:Actual Length,a:r,w:16" },
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

void Packets::PacketDialog::AddTruncated()
{
    list->AddItem("Truncated packet").SetType(ListViewItem::Type::ErrorInformation);
}

std::string_view Packets::PacketDialog::GetValue(NumericFormatter& n, uint64 value)
{
    if (base == 10)
    {
        return n.ToString(value, { NumericFormatFlags::None, 10, 3, ',' });
    }

    return n.ToString(value, { NumericFormatFlags::HexPrefix, 16 });
}

void Packets::PacketDialog::Add_PacketHeader(LinkType type, const PacketHeader* packet)
{
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

    list->AddItem(GetNameOrUnknown(LinkTypeNames, type).data()).SetType(ListViewItem::Type::Category);

    PacketData packetData = {};
    packetData.packet     = packet;
    if (type == LinkType::ETHERNET)
    {
        auto peh = (const Package_EthernetHeader*) ((const uint8*) packet + sizeof(PacketHeader));
        packetData.physicalLayer = { LinkType::ETHERNET, peh };
        Add_Package_EthernetHeader(&packetData, peh, packet->inclLen);
    }
    if (type == LinkType::NULL_)
    {
        auto pnh = (const Package_NullHeader*) ((const uint8*) packet + sizeof(PacketHeader));
        packetData.physicalLayer = { LinkType::NULL_, pnh };
        Add_Package_NullHeader(&packetData, pnh, packet->inclLen);
    }
}

void Packets::PacketDialog::Add_Package_EthernetHeader(PacketData* packetData, const Package_EthernetHeader* peh, uint32 packetInclLen)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (packetInclLen < sizeof(Package_EthernetHeader))
        return AddTruncated();

    auto pehRef = *peh;
    Swap(pehRef);

    MAC etherDHost{};
    MAC etherSHost{};
    memcpy(&etherDHost, pehRef.etherDhost, 6);
    memcpy(&etherSHost, pehRef.etherShost, 6);

    AddMACElement(list, "Destination Host", etherDHost);
    AddMACElement(list, "Source Host", etherSHost);

    const auto etherType      = PCAP::GetEtherType(pehRef.etherType);
    const auto& etherTypeName = GetNameOrUnknown(PCAP::EtherTypeNames, etherType).data();
    const auto etherTypeHex   = GetValue(n, pehRef.etherType);
    list->AddItem({ "Type", tmp.Format("%-10s (%s)", etherTypeName, etherTypeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    list->AddItem(etherTypeName).SetType(ListViewItem::Type::Category);
    if (etherType == EtherType::IPv4)
    {
        auto ipv4 = (const IPv4Header*) ((const uint8*) peh + sizeof(Package_EthernetHeader));
        packetData->linkLayer = { LinkType::IPV4, ipv4 };
        Add_IPv4Header(packetData, ipv4, packetInclLen - sizeof(Package_EthernetHeader));
    }
    else if (etherType == EtherType::IPv6)
    {
        auto ipv6 = (const IPv6Header*) ((const uint8*) peh + sizeof(Package_EthernetHeader));
        packetData->linkLayer = { LinkType::IPV6, ipv6 };
        Add_IPv6Header(packetData, ipv6, packetInclLen - sizeof(Package_EthernetHeader));
    }
}

void Packets::PacketDialog::Add_Package_NullHeader(PacketData* packetData, const Package_NullHeader* pnh, uint32 packetInclLen)
{
    LocalString<32> tmp;
    if (packetInclLen < sizeof(Package_NullHeader))
        return AddTruncated();
    if (pnh->family_ip == NULL_FAMILY_IP)
    {
        list->AddItem({ "Family: IP ", tmp.Format("%u", pnh->family_ip) });
        list->AddItem("IPv4").SetType(ListViewItem::Type::Category);
        auto ipv4 = (const IPv4Header*) ((const uint8*) pnh + sizeof(Package_NullHeader));
        packetData->linkLayer = { LinkType::IPV4, ipv4 };
        Add_IPv4Header(packetData, ipv4, packetInclLen - sizeof(Package_NullHeader));
    }
}

void Packets::PacketDialog::Add_IPv4Header(PacketData* packetData, const IPv4Header* ipv4, uint32 packetInclLen)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (packetInclLen < sizeof(IPv4Header))
        return AddTruncated();

    auto ipv4Ref = *ipv4;
    Swap(ipv4Ref);

    list->AddItem({ "Length", tmp.Format("%s", GetValue(n, ipv4Ref.headerLength).data()) });
    list->AddItem({ "Version", tmp.Format("%s", GetValue(n, ipv4Ref.version).data()) });

    const auto& dscpName = GetNameOrUnknown(PCAP::DscpTypeNames, ipv4Ref.dscp).data();
    const auto dscpHex   = GetValue(n, (uint8) ipv4Ref.dscp);
    list->AddItem({ "DSCP", tmp.Format("%-10s (%s)", dscpName, dscpHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    const auto& ecnName = GetNameOrUnknown(PCAP::EcnTypeNames, ipv4Ref.ecn).data();
    const auto ecnHex   = GetValue(n, (uint8) ipv4Ref.ecn);
    list->AddItem({ "ECN", tmp.Format("%-10s (%s)", ecnName, ecnHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    list->AddItem({ "Total Length", tmp.Format("%s", GetValue(n, ipv4Ref.totalLength).data()) });
    list->AddItem({ "Identification", tmp.Format("%s", GetValue(n, ipv4Ref.identification).data()) });

    const auto fragmentation = ipv4->fragmentation;
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

    list->AddItem({ "TTL", tmp.Format("%s", GetValue(n, ipv4Ref.ttl).data()) });

    const auto& protocolName = GetNameOrUnknown(PCAP::IP_ProtocolNames, ipv4Ref.protocol).data();
    const auto protocolHex   = GetValue(n, (uint8) ipv4Ref.protocol);
    list->AddItem({ "Protocol", tmp.Format("%-10s (%s)", protocolName, protocolHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    list->AddItem({ "CRC", tmp.Format("%s", GetValue(n, ipv4Ref.crc).data()) });
    AddIPv4Element(list, "Source Address", ipv4Ref.sourceAddress);
    AddIPv4Element(list, "Destination Address", ipv4Ref.destinationAddress);

    list->AddItem(protocolName).SetType(ListViewItem::Type::Category);
    if (ipv4Ref.protocol == IP_Protocol::TCP)
    {
        auto tcp = (const TCPHeader*) ((const uint8*) ipv4 + sizeof(IPv4Header));
        packetData->transportLayer = { IP_Protocol::TCP, tcp };
        Add_TCPHeader(packetData, tcp, packetInclLen - sizeof(IPv4Header));
    }
    else if (ipv4Ref.protocol == IP_Protocol::UDP)
    {
        auto udp = (const UDPHeader*) ((const uint8*) ipv4 + sizeof(IPv4Header));
        packetData->transportLayer = { IP_Protocol::UDP, udp };
        Add_UDPHeader(packetData, udp, packetInclLen - sizeof(IPv4Header));
    }
    else if (ipv4Ref.protocol == IP_Protocol::ICMP)
    {
        auto icmpBase = (const ICMPHeader_Base*) ((const uint8*) ipv4 + sizeof(IPv4Header));
        // TODO: fix this later!!
        packetData->transportLayer = { IP_Protocol::ICMP, icmpBase };
        Add_ICMPHeader(packetData, icmpBase, packetInclLen - sizeof(IPv4Header));
    }
}

void Packets::PacketDialog::Add_IPv6Header(PacketData* packetData, const IPv6Header* ipv6, uint32 packetInclLen)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (packetInclLen < sizeof(IPv6Header))
        return AddTruncated();

    auto ipv6Ref = *ipv6;
    Swap(ipv6Ref);

    list->AddItem({ "Flow Label", tmp.Format("%s", GetValue(n, ipv6Ref.first.flowLabel).data()) });

    const auto& ecnName = GetNameOrUnknown(PCAP::EcnTypeNames, (EcnType) ipv6Ref.first.ecn).data();
    const auto ecnHex   = GetValue(n, ipv6Ref.first.ecn);
    list->AddItem({ "ECN", tmp.Format("%-10s (%s)", ecnName, ecnHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    const auto& dscpName = GetNameOrUnknown(PCAP::DscpTypeNames, (DscpType) ipv6Ref.first.dscp).data();
    const auto dscpHex   = GetValue(n, ipv6Ref.first.dscp);
    list->AddItem({ "DSCP", tmp.Format("%-10s (%s)", dscpName, dscpHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    list->AddItem({ "Version", tmp.Format("%s", GetValue(n, ipv6Ref.first.version).data()) });
    list->AddItem({ "Payload Length", tmp.Format("%s", GetValue(n, ipv6Ref.payloadLength).data()) });

    const auto& protocolName = GetNameOrUnknown(PCAP::IP_ProtocolNames, ipv6Ref.nextHeader).data();
    const auto protocolHex   = GetValue(n, (uint8) ipv6Ref.nextHeader);
    list->AddItem({ "Next Header", tmp.Format("%-10s (%s)", protocolName, protocolHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    list->AddItem({ "Hop Limit", tmp.Format("%s", GetValue(n, ipv6Ref.hopLimit).data()) });

    AddIPv6Element(list, "Source Address", ipv6Ref.sourceAddress);
    AddIPv6Element(list, "Destination Address", ipv6Ref.destinationAddress);

    list->AddItem(protocolName).SetType(ListViewItem::Type::Category);
    if (ipv6Ref.nextHeader == IP_Protocol::TCP)
    {
        auto tcp = (const TCPHeader*) ((const uint8*) ipv6 + sizeof(IPv6Header));
        packetData->transportLayer = { IP_Protocol::TCP, tcp };
        Add_TCPHeader(packetData, tcp, packetInclLen - sizeof(IPv6Header));
    }
    else if (ipv6Ref.nextHeader == IP_Protocol::UDP)
    {
        auto udp = (const UDPHeader*) ((const uint8*) ipv6 + sizeof(IPv6Header));
        packetData->transportLayer = { IP_Protocol::UDP, udp };
        Add_UDPHeader(packetData, udp, packetInclLen - sizeof(IPv6Header));
    }
}

void Packets::PacketDialog::Add_UDPHeader(PacketData* packetData, const UDPHeader* udp, uint32 udpSize)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (udpSize < sizeof(UDPHeader))
        return AddTruncated();

    auto udpRef = *udp;
    Swap(udpRef);

    list->AddItem({ "Source Port", tmp.Format("%s", GetValue(n, udpRef.srcPort).data()) });
    list->AddItem({ "Destination Port", tmp.Format("%s", GetValue(n, udpRef.destPort).data()) });
    list->AddItem({ "Datagram Length", tmp.Format("%s", GetValue(n, udpRef.length).data()) });
    list->AddItem({ "Datagram Checksum", tmp.Format("%s", GetValue(n, udpRef.checksum).data()) });
    if (udpRef.length >= sizeof(UDPHeader))
    {
        list->AddItem({ "Payload Size", tmp.Format("%s", GetValue(n, udpRef.length - sizeof(UDPHeader)).data()) });
    }

    if (udpRef.destPort == 53)
    {
        list->AddItem("DNS").SetType(ListViewItem::Type::Category);
        auto dns = (const DNSHeader*) ((const uint8*) udp + sizeof(UDPHeader));
        Add_DNSHeader(packetData, dns, udpSize - sizeof(UDPHeader));
    }
    else
    {
        list->AddItem("Unknown/Payload").SetType(ListViewItem::Type::Category);
    }
}

void Packets::PacketDialog::Add_DNSHeader(PacketData* packetData, const DNSHeader* dns, uint32 dnsSize)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (dnsSize < sizeof(DNSHeader))
        return AddTruncated();

    auto dnsRef = *dns;
    Swap(dnsRef);

    list->AddItem({ "ID", tmp.Format("%s", GetValue(n, dnsRef.id).data()) });
    list->AddItem({ "Flags", tmp.Format("%s", GetValue(n, dnsRef.flags).data()) });

    {
        if (dnsRef.rd)
        {
            list->AddItem({ "", "Recursion Desired" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.rd)
        {
            list->AddItem({ "", "Truncated Message" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.aa)
        {
            list->AddItem({ "", "Authoritive Answer" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        const auto opcodeName = GetNameOrUnknown(DNSHeader_OpcodeNames, dnsRef.opcode);
        list->AddItem({ "", opcodeName.data() }).SetType(ListViewItem::Type::Emphasized_2);
        if (dnsRef.qr)
        {
            list->AddItem({ "", "Query/Response" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.rcode)
        {
            list->AddItem({ "", "Response Code" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.cd)
        {
            list->AddItem({ "", "Checking Disabled" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.ad)
        {
            list->AddItem({ "", "Authenticated Data" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.z)
        {
            list->AddItem({ "", "Reserved" }).SetType(ListViewItem::Type::Emphasized_2);
        }
        if (dnsRef.ra)
        {
            list->AddItem({ "", "Recursion Available" }).SetType(ListViewItem::Type::Emphasized_2);
        }
    }

    list->AddItem({ "Question Entries #", tmp.Format("%s", GetValue(n, dnsRef.qdcount).data()) });
    list->AddItem({ "Answer Entries #", tmp.Format("%s", GetValue(n, dnsRef.ancount).data()) });
    list->AddItem({ "Authority Entries #", tmp.Format("%s", GetValue(n, dnsRef.nscount).data()) });
    list->AddItem({ "Resource Entries #", tmp.Format("%s", GetValue(n, dnsRef.arcount).data()) });

    // every read below stays inside the DNS message carried by this packet
    const auto start     = (const uint8*) dns + sizeof(DNSHeader);
    const auto available = dnsSize - static_cast<uint32>(sizeof(DNSHeader));
    uint32 offset        = 0;
    for (uint16 i = 0; i < dnsRef.qdcount; i++)
    {
        std::vector<std::string_view> names;

        bool nameComplete = false;
        while (offset < available)
        {
            const uint8 length = start[offset];
            if (length == 0)
            {
                offset++;
                nameComplete = true;
                break;
            }
            // labels are at most 63 bytes; larger values are compression pointers (not supported here) or garbage
            if (length > 63 || length > available - offset - 1)
            {
                break;
            }
            names.emplace_back(std::string_view{ (const char*) (start + offset + 1), length });
            offset += sizeof(uint8) + length;
        }

        if (!nameComplete || available - offset < 2 * sizeof(uint16))
        {
            list->AddItem("DNS Question is truncated or malformed").SetType(ListViewItem::Type::ErrorInformation);
            break;
        }

        uint16 qType, qClass;
        memcpy(&qType, start + offset, sizeof(qType));
        memcpy(&qClass, start + offset + sizeof(uint16), sizeof(qClass));
        DNSHeader_Question question{ names, (DNSHeader_Question_QType) qType, (DNSHeader_Question_QClass) qClass };
        Swap(question);
        offset += 2 * sizeof(uint16);

        list->AddItem("DNS Question").SetType(ListViewItem::Type::Category);
        Add_DNSHeader_Question(question);
    }

    if (dnsRef.ancount > 0)
    {
        list->AddItem("Answer Entry not supported (please add).").SetType(ListViewItem::Type::ErrorInformation);
    }

    if (dnsRef.nscount > 0)
    {
        list->AddItem("Authority Entry not supported (please add).").SetType(ListViewItem::Type::ErrorInformation);
    }

    if (dnsRef.arcount > 0)
    {
        list->AddItem("Resource Entry not supported (please add).").SetType(ListViewItem::Type::ErrorInformation);
    }
}

void Packets::PacketDialog::Add_ICMPHeader(PacketData* packetData, const ICMPHeader_Base* icmpBase, uint32 icmpSize)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (icmpSize < sizeof(ICMPHeader_Base))
        return AddTruncated();

    auto icmpBaseRef = *icmpBase;
    Swap(icmpBaseRef);

    const auto& icmpTypeName = GetNameOrUnknown(PCAP::ICMPHeader_TypeNames, icmpBaseRef.type).data();
    const auto icmpTypeHex   = GetValue(n, (uint8) icmpBaseRef.type);
    list->AddItem({ "Type", tmp.Format("%-10s (%s)", icmpTypeName, icmpTypeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

    switch (icmpBaseRef.type)
    {
    case ICMPHeader_Type::EchoReply:
    case ICMPHeader_Type::Echo:
    {
        if (icmpSize < sizeof(ICMPHeader_8))
            return AddTruncated();
        ICMPHeader_8 icmp8;
        memcpy(&icmp8, icmpBase, sizeof(icmp8));
        Swap(icmp8);

        list->AddItem({ "Identifier", tmp.Format("%s", GetValue(n, icmp8.identifier).data()) });
        list->AddItem({ "Sequence Number", tmp.Format("%s", GetValue(n, icmp8.sequenceNumber).data()) });
    }
    break;
    case ICMPHeader_Type::DestinationUnreachable:
    {
        const auto& codeName = GetNameOrUnknown(PCAP::ICMPHeader_Code3Names, (ICMPHeader_Code3) icmpBaseRef.code).data();
        const auto codeHex   = GetValue(n, icmpBaseRef.code);
        list->AddItem({ "Code", tmp.Format("%-10s (%s)", codeName, codeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmpBaseRef.checksum).data()) });
    }
    break;
    case ICMPHeader_Type::Redirect:
    {
        if (icmpSize < sizeof(ICMPHeader_5))
            return AddTruncated();
        ICMPHeader_5 icmp5;
        memcpy(&icmp5, icmpBase, sizeof(icmp5));
        Swap(icmp5);

        const auto& codeName = GetNameOrUnknown(PCAP::ICMPHeader_Code5Names, (ICMPHeader_Code5) icmp5.base.code).data();
        const auto codeHex   = GetValue(n, icmp5.base.code);
        list->AddItem({ "Code", tmp.Format("%-10s (%s)", codeName, codeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmp5.base.checksum).data()) });
        AddIPv4Element(list, "Gateway Internet Address", icmp5.gatewayInternetAddress);
    }
    break;
    case ICMPHeader_Type::RouterAdvertisement:
        break;
    case ICMPHeader_Type::RouterSelection:
        break;
    case ICMPHeader_Type::TimeExceeded:
    {
        const auto& codeName = GetNameOrUnknown(PCAP::ICMPHeader_Code11Names, (ICMPHeader_Code11) icmpBaseRef.code).data();
        const auto codeHex   = GetValue(n, icmpBaseRef.code);
        list->AddItem({ "Code", tmp.Format("%-10s (%s)", codeName, codeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmpBaseRef.checksum).data()) });
    }
    break;
    case ICMPHeader_Type::ParameterProblem:
    {
        if (icmpSize < sizeof(ICMPHeader_12))
            return AddTruncated();
        ICMPHeader_12 icmp12;
        memcpy(&icmp12, icmpBase, sizeof(icmp12));
        Swap(icmp12);

        const auto& codeName = GetNameOrUnknown(PCAP::ICMPHeader_Code12Names, (ICMPHeader_Code12) icmp12.base.code).data();
        const auto codeHex   = GetValue(n, icmp12.base.code);
        list->AddItem({ "Code", tmp.Format("%-10s (%s)", codeName, codeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmp12.base.checksum).data()) });
        AddIPv4Element(list, "Pointer", icmp12.pointer);
    }
    break;
    case ICMPHeader_Type::Timestamp:
    case ICMPHeader_Type::TimestampReply:
    {
        if (icmpSize < sizeof(ICMPHeader_13_14))
            return AddTruncated();
        ICMPHeader_13_14 icmp13_14;
        memcpy(&icmp13_14, icmpBase, sizeof(icmp13_14));
        Swap(icmp13_14);

        list->AddItem({ "Code", tmp.Format("%s", GetValue(n, icmp13_14.base.base.code).data()) });
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmp13_14.base.base.checksum).data()) });
        list->AddItem({ "Identifier", tmp.Format("%s", GetValue(n, icmp13_14.base.identifier).data()) });
        list->AddItem({ "Sequence Number", tmp.Format("%s", GetValue(n, icmp13_14.base.sequenceNumber).data()) });
        list->AddItem({ "Originate Timestamp", tmp.Format("%s", GetValue(n, icmp13_14.originateTimestamp).data()) });
        list->AddItem({ "Receive Timestamp", tmp.Format("%s", GetValue(n, icmp13_14.receiveTimestamp).data()) });
        list->AddItem({ "Transmit Timestamp", tmp.Format("%s", GetValue(n, icmp13_14.transmitTimestamp).data()) });
    }
    break;
    case ICMPHeader_Type::InformationRequest:
    case ICMPHeader_Type::InformationReply:
    {
        if (icmpSize < sizeof(ICMPHeader_8))
            return AddTruncated();
        ICMPHeader_8 icmp15_16;
        memcpy(&icmp15_16, icmpBase, sizeof(icmp15_16));
        Swap(icmp15_16);

        list->AddItem({ "Code", tmp.Format("%s", GetValue(n, icmp15_16.base.code).data()) });
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmp15_16.base.checksum).data()) });
        list->AddItem({ "Identifier", tmp.Format("%s", GetValue(n, icmp15_16.identifier).data()) });
        list->AddItem({ "Sequence Number", tmp.Format("%s", GetValue(n, icmp15_16.sequenceNumber).data()) });
    }
    break;
    case ICMPHeader_Type::AddressMaskRequest:
        break;
    case ICMPHeader_Type::AddressMaskReply:
        break;
    case ICMPHeader_Type::Traceroute:
        break;
    case ICMPHeader_Type::DatagramConversionError:
        break;
    case ICMPHeader_Type::MobileHostRedirect:
        break;
    case ICMPHeader_Type::IPv6WhereAreYou:
        break;
    case ICMPHeader_Type::IPv6IAmHere:
        break;
    case ICMPHeader_Type::MobileRegistrationRequest:
        break;
    case ICMPHeader_Type::MobileRegistrationReply:
        break;
    case ICMPHeader_Type::DomainNameRequest:
        break;
    case ICMPHeader_Type::DomainNameReply:
        break;
    case ICMPHeader_Type::SKIP:
        break;
    case ICMPHeader_Type::SourceQuench:
    default:
        list->AddItem({ "Code", tmp.Format("%s", GetValue(n, icmpBaseRef.code).data()) });
        list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, icmpBaseRef.checksum).data()) });
        break;
    }
    if (icmpSize >= sizeof(ICMPHeader_8))
    {
        list->AddItem({ "Payload Size", tmp.Format("%s", GetValue(n, icmpSize - sizeof(ICMPHeader_8)).data()) });
    }
}

void Packets::PacketDialog::Add_DNSHeader_Question(const DNSHeader_Question& question)
{
    LocalString<128> tmp;
    NumericFormatter n;

    std::string fullname;

    list->AddItem({ "Labels #", tmp.Format("%s", GetValue(n, question.names.size()).data()) }).SetType(ListViewItem::Type::Emphasized_1);
    for (const auto& sv : question.names)
    {
        list->AddItem({ "Label", tmp.Format("(%s) %.*s", GetValue(n, sv.size()).data(), sv.size(), sv.data()) });

        fullname.append(sv).append(".");
    }

    if (question.names.empty() == false)
    {
        fullname.erase(fullname.end() - 1);
    }

    list->AddItem({ "Fullname", tmp.Format("%s", fullname.c_str()) }).SetType(ListViewItem::Type::Emphasized_1);

    const auto& qTypeName = GetNameOrUnknown(DNSHeader_Question_QTypeNames, question.qtype).data();
    const auto& qTypeHex  = GetValue(n, (uint16) question.qtype);
    list->AddItem({ "QType", tmp.Format("%-6s (%s)", qTypeName, qTypeHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);
    const auto& qClassName = GetNameOrUnknown(DNSHeader_Question_QClassNames, question.qclass).data();
    const auto& qClassHex  = GetValue(n, (uint16) question.qclass);
    list->AddItem({ "QClass", tmp.Format("%-6s (%s)", qClassName, qClassHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);
}

void Packets::PacketDialog::Add_TCPHeader(PacketData* packetData, const TCPHeader* tcp, uint32 packetInclLen)
{
    LocalString<128> tmp;
    NumericFormatter n;

    if (packetInclLen < sizeof(TCPHeader))
        return AddTruncated();

    auto tcpRef = *tcp;
    Swap(tcpRef);

    list->AddItem({ "Source Port", tmp.Format("%s", GetValue(n, tcpRef.sPort).data()) });
    list->AddItem({ "Destination Port", tmp.Format("%s", GetValue(n, tcpRef.dPort).data()) });
    list->AddItem({ "Sequence Number", tmp.Format("%s", GetValue(n, tcpRef.seq).data()) });
    list->AddItem({ "Acknowledgement Number", tmp.Format("%s", GetValue(n, tcpRef.ack).data()) });
    list->AddItem({ "Data Offset", tmp.Format("%s", GetValue(n, tcpRef.dataOffset).data()) });
    list->AddItem({ "Rsvd", tmp.Format("%s", GetValue(n, tcpRef.rsvd).data()) });

    list->AddItem({ "Flags", tmp.Format("%s", GetValue(n, tcpRef.flags).data()) });
    const auto lFlags = PCAP::GetTCPHeader_Flags(tcpRef.flags);
    for (const auto& [flag, name] : lFlags)
    {
        LocalString<16> hfls;
        hfls.Format("(0x%X)", flag);

        list->AddItem({ "", tmp.Format("%-20s %-4s", name.data(), hfls.GetText()) }).SetType(ListViewItem::Type::Emphasized_2);
    }

    list->AddItem({ "Window", tmp.Format("%s", GetValue(n, tcpRef.win).data()) });
    list->AddItem({ "Checksum", tmp.Format("%s", GetValue(n, tcpRef.sum).data()) });
    list->AddItem({ "Urgent Pointer", tmp.Format("%s", GetValue(n, tcpRef.urp).data()) });

    const uint32 tcp_header_len = tcp->dataOffset * 4;
    if (tcp_header_len < sizeof(TCPHeader))
        return; // err: TODO improve this later

    // the options may be cut by the capture's snaplen: parse only the bytes that were saved
    const uint32 options_len = std::min(tcp_header_len, packetInclLen) - static_cast<uint32>(sizeof(TCPHeader));
    if (options_len > 0)
    {
        Add_TCPHeader_Options((const uint8*) tcp + sizeof(TCPHeader), options_len);
    }

    // TODO: add payload parsing

	if (packetInclLen >= tcp_header_len)
    {
        list->AddItem({ "Payload Size", tmp.Format("%s", GetValue(n, packetInclLen - tcp_header_len).data()) }).SetType(ListViewItem::Type::Emphasized_2);
    }
}

void Packets::PacketDialog::Add_TCPHeader_Options(const uint8* optionsPtr, uint32 optionsLen)
{
    LocalString<128> tmp;
    NumericFormatter n;

    auto options   = optionsPtr;
    const auto end = options + optionsLen;
    while (options < end)
    {
        const auto kind      = static_cast<TCPHeader_OptionsKind>(*options);
        const char* kindName = "not_mapped";
        const auto foundName = TCPHeader_OptionsKindNames.find(kind);
        if (foundName != TCPHeader_OptionsKindNames.end())
            kindName = foundName->second.data();
        const auto kindHex = GetValue(n, BigToNative((uint8) kind));
        list->AddItem({ "Option: Kind", tmp.Format("%-10s (%s)", kindName, kindHex.data()) }).SetType(ListViewItem::Type::Emphasized_1);

        // single byte options
        if (kind == TCPHeader_OptionsKind::EndOfOptionsList || kind == TCPHeader_OptionsKind::NoOperation)
        {
            list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, 1).data()) });
            if (kind == TCPHeader_OptionsKind::EndOfOptionsList)
                break;
            options++;
            continue;
        }

        // every other option is kind + length + data; a length below 2 would never advance
        const auto left = static_cast<size_t>(end - options);
        const uint8 length = left >= 2 ? options[1] : 0;
        if (length < 2 || length > left)
        {
            list->AddItem("Option: invalid length").SetType(ListViewItem::Type::ErrorInformation);
            break;
        }

        switch (kind)
        {
        case TCPHeader_OptionsKind::MaximumSegmentSize:
            list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, length).data()) });
            if (length >= 4)
            {
                uint16 mss;
                memcpy(&mss, options + 2, sizeof(mss));
                list->AddItem({ "Option: MSS", tmp.Format("%s", GetValue(n, BigToNative(mss)).data()) });
            }
            break;
        case TCPHeader_OptionsKind::WindowScale:
        case TCPHeader_OptionsKind::SelectiveAcknowledgementPermitted:
        case TCPHeader_OptionsKind::SACK:
        case TCPHeader_OptionsKind::TimestampAndEchoOfPreviousTimestamp:
            list->AddItem({ "Option: Length", tmp.Format("%s", GetValue(n, length).data()) });
            break;
        case TCPHeader_OptionsKind::TimestampOption:
            list->AddItem({ "Option: TimeStamp", tmp.Format("%s", GetValue(n, length).data()) });
            break;
        default:
            list->AddItem({ "Option: not_mapped" });
            break;
        }
        options += length;
    }
}

Panels::Packets::PacketDialog::PacketDialog(
      Reference<GView::Object> _object, std::string_view name, std::string_view layout, LinkType type, const PacketHeader* packet, int32 _base)
    : Window(name, layout, WindowFlags::ProcessReturn | WindowFlags::FixedPosition), object(_object), base(_base)
{
    list = CreateChildControl<ListView>("x:0,y:0,w:100%,h:48", std::initializer_list<ConstString>{ "n:Field,w:24", "n:Value,w:40" }, ListViewFlags::None);

    Add_PacketHeader(type, packet);
}

void Panels::Packets::OpenPacket()
{
    auto itemData      = list->GetCurrentItem().GetData<const std::pair<PacketHeader*, uint32>>();
    const auto& packet = itemData->first;

    LocalString<128> ls;
    ls.Format("d:c,w:80,h:50", this->GetHeight());
    PacketDialog dialog(nullptr, GetNameOrUnknown(PCAP::LinkTypeNames, pcap->header.network).data(), ls.GetText(), pcap->header.network, packet, Base);
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
    commandBar.SetCommand(PANEL_KEYS.Select.Key, "Select", static_cast<int32_t>(ObjectAction::Select));
    commandBar.SetCommand(PANEL_KEYS.ChangeBase.Key, Base == 10 ? "Dec" : "Hex", static_cast<int32_t>(ObjectAction::ChangeBase));
    commandBar.SetCommand(PANEL_OPEN_PACKET.Key, "Open Packet", static_cast<int32_t>(ObjectAction::OpenPacket));

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
