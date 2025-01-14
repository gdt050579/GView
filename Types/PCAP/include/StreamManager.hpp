#pragma once

#include "Internal.hpp"

namespace GView::Type::PCAP
{
    struct PayloadDataParserInterface;
    struct ConnectionCallbackInterface
    {
        /**
         * \brief Fill the application layer field "AppLayer" from the StreamView for the current connection
         * \param appLayerName the name of the application layer
         * \return true if set successfully, false otherwise
         */
        virtual bool AddConnectionAppLayerName(std::string appLayerName) = 0;
        /**
         * \brief Fill the summary field "Summary" from the StreamView for the current connection
         * \param summary the data to be filled with
         * \return true if set successfully, false otherwise
         */
        virtual bool AddConnectionSummary(std::string summary) = 0;

        /**
         * \brief Add a panel for the current connection
         * \param panel 
         * \param isVertical 
         */
        virtual void AddPanel(Pointer<TabPage> panel, bool isVertical) = 0;

        virtual ~ConnectionCallbackInterface() = default;
    };

    struct PayloadInformation
    {
        StreamPayload* payload;
        std::vector<StreamPacketData>* packets;
    };

    struct PayloadDataParserInterface
    {
        /**
         * \brief Protocol name for the application layer
         * \return string: the actual name of the protocol
         */
        virtual std::string GetProtocolName() const = 0;

        /**
         * \brief Try to parse the connection
         * \param payloadInformation contains the full payload and a vector of packets
         * \param callbackInterface interface for sending data back to the to appear in StreamManager
         * \return nullptr if the parser is not able to parse the payload, otherwise a pointer to the parser
         */
        virtual PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface *callbackInterface) = 0;

        virtual ~PayloadDataParserInterface() = default;
    };

class StreamManager
{
    std::unordered_map<std::string, std::deque<StreamData>> streams;
    std::vector<StreamData> finalStreams;
    std::vector<std::string> protocolsFound;
    std::vector<unique_ptr<PayloadDataParserInterface>> payloadParsers;

    // TODO: maybe sync functions with those used in Panels?
    void Add_Package_EthernetHeader(PacketData* packetData, const Package_EthernetHeader* peh, uint32 length, const PacketHeader* packet);
    void Add_Package_NullHeader(PacketData* packetData, const Package_NullHeader* pnh, uint32 length, const PacketHeader* packet);

    void Add_IPv4Header(PacketData* packetData, const IPv4Header* ipv4, size_t packetInclLen, const PacketHeader* packet);
    void Add_IPv6Header(PacketData* packetData, const IPv6Header* ipv6, size_t packetInclLen, const PacketHeader* packet);

    void Add_TCPHeader(PacketData* packetData, const TCPHeader* tcp, size_t packetInclLen, const void* ipHeader, uint32 ipProto, const PacketHeader* packet);

    void AddToKnownProtocols(const std::string& layerName);

  public:
    void AddPacket(const PacketHeader* header, LinkType network);
    void FinishedAdding();
    bool RegisterPayloadParser(unique_ptr<PayloadDataParserInterface> parser);

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