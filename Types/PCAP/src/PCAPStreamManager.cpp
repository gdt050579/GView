#include "PCAP.hpp"

using namespace GView::Type::PCAP;

void StreamData::computeFinalPayload()
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

    tryParsePayload();
}

void StreamManager::Add_Package_EthernetHeader(const Package_EthernetHeader* peh, uint32 length, const PacketHeader* packet)
{
    auto pehRef = *peh;
    Swap(pehRef);

    const auto etherType = PCAP::GetEtherType(pehRef.etherType);
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
            revStream->second.push_back({});
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
            currentStream.push_back({});
            streamToAddTo                    = &currentStream.back();
            streamToAddTo->ipProtocol        = (uint16) ipProto;
            streamToAddTo->transportProtocol = static_cast<uint16>(IP_Protocol::TCP);
        }
        streamToAddTo = &currentStream.back();
        if (streamToAddTo->isFinished)
        {
            revStream->second.push_back({});
            streamToAddTo                    = &revStream->second.back();
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
    streamToAddTo->packetsOffsets.push_back({ packet, payload, order });
}

constexpr uint32 maxWaitUntilEndLine = 300;

constexpr std::string_view httpPattern        = "HTTP/1.";
constexpr std::string_view httpContentPattern = "Content-Length: ";
void StreamData::tryParsePayload()
{
    if (connPayload.size < 3)
        return;
    for (int i = 0; i < 3; i++)
        if (!isalpha(connPayload.location[i]))
            return;

    uint8 buffer[300]     = {};
    uint32 bufferSize     = 0;
    const uint8* startPtr = connPayload.location;
    const uint8* endPtr   = connPayload.location + connPayload.size;
    bool wasEndline       = false;
    uint32 spaces         = 0;

    bool identified = false;

    StreamTcpLayer layer{};

    while (startPtr < endPtr)
    {
        if (*startPtr == 0x0D || *startPtr == 0x0a)
        {
            wasEndline = true;
            ++spaces;
        }
        else if (wasEndline)
        {
            if (spaces >= 4)
            {
                if (identified)
                {
                    if (layer.payload.size)
                    {
                        layer.payload.location = (uint8*) startPtr;
                        // push

                        startPtr += layer.payload.size;
                        bufferSize         = 0;
                        buffer[bufferSize] = '\0';
                        identified         = false;
                        applicationLayers.push_back(layer);
                        layer = {};
                        continue;
                    }
                    applicationLayers.push_back(layer);
                    layer      = {};
                    identified = false;
                }
            }

            buffer[bufferSize] = '\0';

            if (identified)
            {
                if (bufferSize >= httpContentPattern.size() && memcmp(buffer, httpContentPattern.data(), httpContentPattern.size()) == 0)
                {
                    identified      = true;
                    auto payloadLen = Number::ToInt64((char*) buffer + httpContentPattern.size());
                    if (payloadLen.has_value())
                        layer.payload.size = payloadLen.value();
                }
            }

            wasEndline = false;
            spaces     = 0;

            if (!identified)
            {
                if (bufferSize < httpPattern.size())
                    break;
                if (memcmp(buffer, httpPattern.data(), httpPattern.size()) == 0)
                {
                    identified = true;
                    layer.name = (uint8*) strdup((char*) buffer);
                }
                else if (memcmp(buffer + bufferSize - httpPattern.size() - 1, httpPattern.data(), httpPattern.size()) == 0)
                {
                    identified = true;
                    layer.name = (uint8*) strdup((char*) buffer);
                }
            }
            bufferSize         = 0;
            buffer[bufferSize] = '\0';

            if (bufferSize >= maxWaitUntilEndLine - 1)
                break;
            buffer[bufferSize++] = *startPtr;
        }
        else
        {
            if (bufferSize >= maxWaitUntilEndLine - 1)
                return;
            buffer[bufferSize++] = *startPtr;
        }

        startPtr++;
    }

	if (startPtr >= endPtr)
        appLayerName = "HTTP";
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

    for (auto& [streamName, connections] : streams)
    {
        for (auto& conn : connections)
        {
            conn.name = streamName;
            // conn.sortPackets();
            conn.computeFinalPayload();
            finalStreams.push_back(conn);
        }
    }

    streams.clear();
}
