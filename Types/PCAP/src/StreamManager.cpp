#include "StreamManager.hpp"
#include "Utils.hpp"

using namespace GView::Type::PCAP;

void StreamData::ComputeFinalPayload()
{
    if (totalPayload == 0)
        return;

    uint8* payload = new uint8[totalPayload];

    auto payloadPtr = payload;
    for (const auto& packet : packetsOffsets)
        if (packet.payload.location)
        {
            memcpy(payloadPtr, packet.payload.location, packet.payload.size);
            payloadPtr += packet.payload.size;
        }

    connPayload.size     = (uint32) totalPayload;
    connPayload.location = payload;

    //CallTransportLayerPlugins();
}

void StreamManager::Add_Package_EthernetHeader(PacketData* packetData, const Package_EthernetHeader* peh, uint32 length, const PacketHeader* packet)
{
    auto pehRef = *peh;
    Swap(pehRef);

    const auto etherType = PCAP::GetEtherType(pehRef.etherType);
    if (etherType == EtherType::IPv4)
    {
        auto ipv4 = (IPv4Header*) ((uint8*) peh + sizeof(Package_EthernetHeader));
        packetData->linkLayer = { LinkType::IPV4, ipv4 };
        Add_IPv4Header(packetData, ipv4, length - sizeof(Package_EthernetHeader), packet);
    }
    else if (etherType == EtherType::IPv6)
    {
        auto ipv6 = (IPv6Header*) ((uint8*) peh + sizeof(Package_EthernetHeader));
        packetData->linkLayer = { LinkType::IPV6, ipv6 };
        Add_IPv6Header(packetData, ipv6, length - sizeof(Package_EthernetHeader), packet);
    }
}

void StreamManager::Add_Package_NullHeader(PacketData* packetData, const Package_NullHeader* pnh, uint32 length, const PacketHeader* packet)
{
    if (pnh->family_ip == NULL_FAMILY_IP)
    {
        auto ipv4 = (IPv4Header*) ((uint8*) pnh + sizeof(Package_NullHeader));
        packetData->linkLayer = { LinkType::IPV4, ipv4 };
        Add_IPv4Header(packetData, ipv4, length - sizeof(Package_NullHeader), packet);
    }
}

void StreamManager::Add_IPv4Header(PacketData* packetData, const IPv4Header* ipv4, size_t packetInclLen, const PacketHeader* packet)
{
    if (ipv4->protocol == IP_Protocol::TCP)
    {
        auto tcp = (TCPHeader*) ((uint8*) ipv4 + sizeof(IPv4Header));
        packetData->transportLayer = { IP_Protocol::TCP, tcp };
        Add_TCPHeader(packetData, tcp, packetInclLen - sizeof(IPv4Header), ipv4, static_cast<uint32>(EtherType::IPv4), packet);
    }
    // TODO: add support for UDP streams
    /*else if (ipv4->protocol == IP_Protocol::UDP)
    {
        auto udp = (UDPHeader*) ((uint8*) ipv4 + sizeof(IPv4Header), static_cast<uint32>(EtherType::IPv4));
        Add_UDPHeader(udp);
    }*/
}

void StreamManager::Add_IPv6Header(PacketData* packetData, const IPv6Header* ipv6, size_t packetInclLen, const PacketHeader* packet)
{
    if (ipv6->nextHeader == IP_Protocol::TCP)
    {
        auto tcp = (TCPHeader*) ((uint8*) ipv6 + sizeof(IPv4Header));
        packetData->transportLayer = { IP_Protocol::TCP, tcp };
        Add_TCPHeader(packetData, tcp, packetInclLen - sizeof(IPv6Header), ipv6, static_cast<uint32>(EtherType::IPv6), packet);
    }
    // TODO: add support for UDP streams
    /*else if (ipv6->nextHeader == IP_Protocol::UDP)
    {
        auto udp = (UDPHeader*) ((uint8*) ipv6 + sizeof(IPv6Header));
        Add_UDPHeader(udp);
    }*/
}

void StreamManager::Add_TCPHeader(
      PacketData* packetData, const TCPHeader* tcp, size_t packetInclLen, const void* ipHeader, uint32 ipProto, const PacketHeader* packet)
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

    const bool hasRstFlag = (tcp->flags & RST) > 0;
    const bool hasFinFlag = (tcp->flags & FIN) > 0;
    const bool hasSynFlag = (tcp->flags & SYN) > 0;

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

    StreamData* streamToAddTo = nullptr;

    LocalString<256> streamName;
    streamName.Format("%s:%s -> %s:%s", dstIp.GetText(), dstPort.GetText(), srcIp.GetText(), srcPort.GetText());
    auto revStream = streams.find(streamName.GetText());
    if (revStream != streams.end())
    {
        if (!revStream->second.back().isFinished)
            streamToAddTo = &revStream->second.back();
        else
        {
            revStream->second.emplace_back();
            streamToAddTo                    = &revStream->second.back();
            streamToAddTo->ipProtocol        = (uint16) ipProto;
            streamToAddTo->transportProtocol = static_cast<uint16>(IP_Protocol::TCP);
        }
    }
    else
    {
        const auto name     = streamName.Format("%s:%s -> %s:%s", srcIp.GetText(), srcPort.GetText(), dstIp.GetText(), dstPort.GetText());
        auto& currentStream = streams[name.data()];
        if (currentStream.empty())
        {
            currentStream.emplace_back();
            streamToAddTo                    = &currentStream.back();
            streamToAddTo->ipProtocol        = (uint16) ipProto;
            streamToAddTo->transportProtocol = static_cast<uint16>(IP_Protocol::TCP);
        }
        streamToAddTo = &currentStream.back();
        if (streamToAddTo->isFinished)
        {
            currentStream.emplace_back();
            streamToAddTo                    = &currentStream.back();
            streamToAddTo->ipProtocol        = (uint16) ipProto;
            streamToAddTo->transportProtocol = static_cast<uint16>(IP_Protocol::TCP);
        }
    }

    if (hasRstFlag)
        streamToAddTo->isFinished = true;
    if (hasFinFlag)
        ++streamToAddTo->finFlagsFound;
    if (hasSynFlag && streamToAddTo->finFlagsFound >= 2)
        streamToAddTo->isFinished = true;

    StreamTCPOrder order{};
    order.seqNumber   = tcp->seq;
    order.ackNumber   = tcp->ack;
    order.maxNumber   = std::max(tcp->seq, tcp->ack);
    order.packetIndex = (uint32) streamToAddTo->packetsOffsets.size();

    streamToAddTo->totalPayload += payload.size;
    streamToAddTo->packetsOffsets.push_back({ packet, payload, order, *packetData });
}

void StreamManager::AddToKnownProtocols(const std::string& layerName)
{
    if (layerName.empty())
        return;
    for (const auto& name : protocolsFound)
        if (name == layerName)
            return;
    protocolsFound.push_back(layerName);
}

void StreamManager::AddPacket(const PacketHeader* packet, LinkType network)
{
    PacketData packetData = {};
    packetData.packet     = packet;
    if (network == LinkType::ETHERNET)
    {
        auto peh = (Package_EthernetHeader*) ((uint8*) packet + sizeof(PacketHeader));
        packetData.physicalLayer = { LinkType::ETHERNET, peh };
        Add_Package_EthernetHeader(&packetData, peh, packet->inclLen, packet);
    }
    if (network == LinkType::NULL_)
    {
        auto pnh = (Package_NullHeader*) ((uint8*) packet + sizeof(PacketHeader));
        packetData.physicalLayer = { LinkType::NULL_, pnh };
        Add_Package_NullHeader(&packetData, pnh, packet->inclLen, packet);
    }
}

bool StreamManager::RegisterPayloadParser(unique_ptr<PayloadDataParserInterface> parser)
{
    payloadParsers.push_back(std::move(parser));
    return true;
}

void StreamManager::InitStreamManager(Reference<GView::View::WindowInterface> windowParam)
{
    window = windowParam;
}
