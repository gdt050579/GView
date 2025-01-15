#include "API.hpp"
#include "StreamManager.hpp"

using namespace GView::Type::PCAP;

struct ConnectionCallbackInterfaceImpl : public ConnectionCallbackInterface {
    StreamData* streamData;
    StreamManager* streamManager;

    virtual bool AddConnectionAppLayerName(std::string appLayerName) override
    {
        streamData->appLayerName = appLayerName;
        return true;
    }
    virtual bool AddConnectionSummary(std::string summary) override
    {
        streamData->AddDataToSummary(summary);
        return true;
    }
    virtual bool AddPanel(Pointer<TabPage> panel, bool isVertical) override
    {
        return streamManager->GetWindow()->AddPanel(std::move(panel), isVertical);
    }

    std::deque<StreamTcpLayer>& GetApplicationLayers() override
    {
        return streamData->applicationLayers;
    }
};

void StreamManager::FinishedAdding()
{
    if (streams.empty())
        return;

    finalStreams.reserve(streams.size());

    for (auto& [streamName, connections] : streams) {
        for (auto& conn : connections) {
            conn.name = streamName;
            // conn.SortPackets();
            conn.ComputeFinalPayload();

            ConnectionCallbackInterfaceImpl callbackInterface = {};
            callbackInterface.streamData                      = &conn;

            if (conn.connPayload.size) {
                PayloadInformation payloadInfo{ &conn.connPayload, &conn.packetsOffsets };
                for (auto& parser : payloadParsers) {
                    auto result = parser->ParsePayload(payloadInfo, &callbackInterface);
                    if (result) {
                        conn.payloadParserFound = result;
                        break;
                    }
                }
            }

            if (!conn.appLayerName.empty())
                AddToKnownProtocols(conn.appLayerName);
            finalStreams.emplace_back(std::move(conn));
        }
    }

    streams.clear();
}