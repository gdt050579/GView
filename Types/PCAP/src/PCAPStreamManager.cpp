#include "PCAP.hpp"

using namespace GView::Type::PCAP;

void StreamManager::Add_Package_EthernetHeader(const Package_EthernetHeader* peh, uint32 length, const PacketHeader* packet)
{
    const auto etherType = PCAP::GetEtherType(peh->etherType);
    if (etherType == EtherType::IPv4)
    {
        auto ipv4 = (IPv4Header*) ((uint8*) peh + sizeof(Package_EthernetHeader));
        Add_IPv4Header(ipv4, length - sizeof(Package_EthernetHeader), packet);
    }
    else if (etherType == EtherType::IPv6)
    {
        auto ipv6 = (IPv6Header*) ((uint8*) peh + sizeof(Package_EthernetHeader));
        Add_IPv6Header(ipv6, length - sizeof(Package_EthernetHeader), packet);
    }
}

void StreamManager::Add_Package_NullHeader(const Package_NullHeader* pnh, uint32 length, const PacketHeader* packet)
{
    if (pnh->family_ip == NULL_FAMILY_IP)
    {
        auto ipv4 = (IPv4Header*) ((uint8*) pnh + sizeof(Package_NullHeader));
        Add_IPv4Header(ipv4, length - sizeof(Package_NullHeader), packet);
    }
}

void StreamManager::Add_IPv4Header(const IPv4Header* ipv4, size_t packetInclLen, const PacketHeader* packet)
{
    if (ipv4->protocol == IP_Protocol::TCP)
    {
        auto tcp = (TCPHeader*) ((uint8*) ipv4 + sizeof(IPv4Header));
        Add_TCPHeader(tcp, packetInclLen - sizeof(IPv4Header), ipv4, static_cast<uint32>(EtherType::IPv4), packet);
    }
    // TODO: add support for UDP streams
    /*else if (ipv4->protocol == IP_Protocol::UDP)
    {
        auto udp = (UDPHeader*) ((uint8*) ipv4 + sizeof(IPv4Header), static_cast<uint32>(EtherType::IPv4));
        Add_UDPHeader(udp);
    }*/
}

void StreamManager::Add_IPv6Header(const IPv6Header* ipv6, size_t packetInclLen, const PacketHeader* packet)
{
    if (ipv6->nextHeader == IP_Protocol::TCP)
    {
        auto tcp = (TCPHeader*) ((uint8*) ipv6 + sizeof(IPv4Header));
        Add_TCPHeader(tcp, packetInclLen - sizeof(IPv6Header), ipv6, static_cast<uint32>(EtherType::IPv6), packet);
    }
    // TODO: add support for UDP streams
    /*else if (ipv6->nextHeader == IP_Protocol::UDP)
    {
        auto udp = (UDPHeader*) ((uint8*) ipv6 + sizeof(IPv6Header));
        Add_UDPHeader(udp);
    }*/
}

void StreamManager::Add_TCPHeader(const TCPHeader* tcp, size_t packetInclLen, const void* ipHeader, uint32 ipProto, const PacketHeader* packet)
{
    const auto etherProto = static_cast<EtherType>(ipProto);
    LocalString<64> srcIp, dstIp, srcPort, dstPort;
    NumericFormatter n;
    switch (etherProto)
    {
    case EtherType::IPv4:
    {
        auto* ip = (const IPv4Header*) ipHeader;

        auto ipv4Ref = *ip;
        Swap(ipv4Ref);

        Utils::IPv4ElementToStringNoHex(ipv4Ref.sourceAddress, srcIp);
        Utils::IPv4ElementToStringNoHex(ipv4Ref.destinationAddress, dstIp);
        break;
    }
    case EtherType::IPv6:
    {
        auto* ip = (const IPv6Header*) ipHeader;

        auto ipv6Ref = *ip;
        Swap(ipv6Ref);

        Utils::IPv6ElementToString(ipv6Ref.sourceAddress, srcIp);
        Utils::IPv6ElementToString(ipv6Ref.destinationAddress, dstIp);
        break;
    }
    default:
        // TODO: in the future add an error
        return;
    }

    auto tcpRef = *tcp;
    Swap(tcpRef);

    const uint32 tcp_header_len = tcpRef.dataOffset * 4;
    const uint32 options_len    = tcp_header_len - sizeof(TCPHeader);

    if (tcp_header_len < sizeof(TCPHeader))
        return; // err: TODO improve this later

    StreamPayload payload{};
    if (packetInclLen > tcp_header_len)
    {
        payload.size     = static_cast<uint32>(packetInclLen) - tcp_header_len;
        payload.location = ((uint8*) tcp + sizeof(TCPHeader) + options_len);
    }

    srcPort.Format("%s", n.ToString(tcpRef.sPort, { NumericFormatFlags::None, 10, 3, '.' }).data());
    dstPort.Format("%s", n.ToString(tcpRef.dPort, { NumericFormatFlags::None, 10, 3, '.' }).data());

    LocalString<256> streamName;
    streamName.Format("%s:%s->%s:%s", dstIp.GetText(), dstPort.GetText(), srcIp.GetText(), srcPort.GetText());
    auto revStream = streams.find(streamName.GetText());
    if (revStream != streams.end())
    {
        revStream->second.totalPayload += payload.size;
        revStream->second.packetsOffsets.push_back({ packet, payload });
        return;
    }
    const auto name     = streamName.Format("%s:%s->%s:%s", srcIp.GetText(), srcPort.GetText(), dstIp.GetText(), dstPort.GetText());
    auto& currentStream = streams[name.data()];
    currentStream.totalPayload += payload.size;
    currentStream.packetsOffsets.push_back({ packet, payload });
    currentStream.ipProtocol        = (uint16) ipProto;
    currentStream.transportProtocol = static_cast<uint16>(IP_Protocol::TCP);
}

void StreamManager::AddPacket(const PacketHeader* packet, LinkType network)
{
    if (network == LinkType::ETHERNET)
    {
        auto peh = (Package_EthernetHeader*) ((uint8*) packet + sizeof(PacketHeader));
        Add_Package_EthernetHeader(peh, packet->inclLen, packet);
    }
    if (network == LinkType::NULL_)
    {
        auto pnh = (Package_NullHeader*) ((uint8*) packet + sizeof(PacketHeader));
        Add_Package_NullHeader(pnh, packet->inclLen, packet);
    }
}

void StreamManager::FinishedAdding()
{
    if (streams.empty())
        return;

    finalStreams.reserve(streams.size());

    for (auto& [fst, snd] : streams)
    {
        snd.name = fst;
        finalStreams.push_back(std::move(snd));
    }
    streams.clear();
}
