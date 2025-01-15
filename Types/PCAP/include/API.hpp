#pragma once

#include "Internal.hpp"

namespace GView::Type::PCAP
{
struct PayloadDataParserInterface;
struct ConnectionCallbackInterface {
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
     * \return true if added successfully, false otherwise
     */
    virtual bool AddPanel(Pointer<TabPage> panel, bool isVertical) = 0;

    /**
     * \brief When parsing the payloads set the application layers. Each layer contains relevant information for the payload parser.
     * The parser can set its payloadData pointer memory. This is also used when extending the connection from the StreamView when showing multiple items. Each layer is interactive from the StreamView window.
     * \return the list where the payload parser can set up relevant information about layers
     */
    virtual std::deque<StreamTcpLayer>& GetApplicationLayers() = 0;

    virtual ~ConnectionCallbackInterface() = default;
};

struct PayloadInformation {
    StreamPayload* payload;
    std::vector<StreamPacketData>* packets;
};

struct PayloadDataParserInterface {
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
    virtual PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) = 0;

    virtual ~PayloadDataParserInterface() = default;
};
} // namespace GView::Type::PCAP