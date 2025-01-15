#pragma once

#include "API.hpp"

namespace GView::Type::PCAP
{
class StreamManager
{
    std::unordered_map<std::string, std::deque<StreamData>> streams;
    std::vector<StreamData> finalStreams;
    std::vector<std::string> protocolsFound;
    std::vector<unique_ptr<PayloadDataParserInterface>> payloadParsers;
    Reference<GView::View::WindowInterface> window;

    // TODO: maybe sync functions with those used in Panels?
    void Add_Package_EthernetHeader(PacketData* packetData, const Package_EthernetHeader* peh, uint32 length, const PacketHeader* packet);
    void Add_Package_NullHeader(PacketData* packetData, const Package_NullHeader* pnh, uint32 length, const PacketHeader* packet);

    void Add_IPv4Header(PacketData* packetData, const IPv4Header* ipv4, size_t packetInclLen, const PacketHeader* packet);
    void Add_IPv6Header(PacketData* packetData, const IPv6Header* ipv6, size_t packetInclLen, const PacketHeader* packet);

    void Add_TCPHeader(PacketData* packetData, const TCPHeader* tcp, size_t packetInclLen, const void* ipHeader, uint32 ipProto, const PacketHeader* packet);

    void AddToKnownProtocols(const std::string& layerName);

  public:
    StreamManager() = default;

    void AddPacket(const PacketHeader* packet, LinkType network);
    void FinishedAdding();
    bool RegisterPayloadParser(unique_ptr<PayloadDataParserInterface> parser);

    void InitStreamManager(Reference<GView::View::WindowInterface> windowParam);
    Reference<GView::View::WindowInterface> GetWindow() const
    {
        return window;
    }

    bool empty() const noexcept
    {
        return finalStreams.empty();
    }

    decltype(finalStreams.size()) size() const noexcept
    {
        return finalStreams.size();
    }

    decltype(finalStreams)::iterator begin() noexcept
    {
        return finalStreams.begin();
    }
    decltype(finalStreams)::iterator end() noexcept
    {
        return finalStreams.end();
    }

    const StreamData* operator[](uint32 index) const
    {
        if (index < finalStreams.size())
            return &finalStreams.at(index);
        return nullptr;
    }

    std::string GetProtocolsFound() const
    {
        if (protocolsFound.empty())
            return "none recognized";
        // TODO: improve performance with faster string addition
        std::string res;
        for (const auto& proto : protocolsFound)
            res += proto + " ";

        return res;
    }
};

} // namespace GView::Type::PCAP