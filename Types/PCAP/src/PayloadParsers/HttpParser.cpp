#include "HttpParser.hpp"

using namespace GView::Type::PCAP;

constexpr uint32 maxWaitUntilEndLine = 300;

constexpr std::string_view httpPattern        = "HTTP/1.";
constexpr std::string_view httpContentPattern = "Content-Length: ";

void GetFileExtracted(StreamTcpLayer& output)
{
    const auto sv         = std::string_view((char*) output.name.get());
    const auto firstSpace = sv.find_first_of(' ');
    if (firstSpace == std::string::npos)
        return;
    const auto lastSpace = sv.find_last_of(' ');
    if (lastSpace == std::string::npos)
        return;
    const auto extractedLocation = sv.substr(firstSpace + 1, lastSpace - firstSpace - 1);
    const auto slashLoc          = extractedLocation.find_last_of('/');
    if (slashLoc == std::string::npos) {
        output.extractionName = extractedLocation;
        return;
    }
    output.extractionName = extractedLocation.substr(slashLoc + 1);
}

PayloadDataParserInterface* HTTP::HTTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    const auto connPayload = payloadInformation.payload;
    if (payloadInformation.payload->size < 3)
        return nullptr;
    for (int i = 0; i < 3; i++)
        if (!isalpha(connPayload->location[i]))
            return nullptr;

    auto& applicationLayers = callbackInterface->GetApplicationLayers();

    uint8 buffer[300]     = {};
    uint32 bufferSize     = 0;
    const uint8* startPtr = connPayload->location;
    const uint8* endPtr   = connPayload->location + connPayload->size;
    bool wasEndline       = false;
    uint32 spaces         = 0;

    bool identified = false;

    StreamTcpLayer layer = {};

    while (startPtr < endPtr) {
        if (*startPtr == 0x0D || *startPtr == 0x0a) {
            wasEndline = true;
            ++spaces;
        } else if (wasEndline) {
            if (spaces >= 4) {
                if (identified) {
                    if (layer.payload.size) {
                        layer.payload.location = (uint8*) startPtr;
                        // push

                        startPtr += layer.payload.size;
                        bufferSize         = 0;
                        buffer[bufferSize] = '\0';
                        identified         = false;
                        if (!applicationLayers.empty() && !applicationLayers.back().extractionName.empty())
                            layer.extractionName = applicationLayers.back().extractionName;
                        applicationLayers.emplace_back(std::move(layer));
                        layer.Clear();
                        continue;
                    }
                    applicationLayers.emplace_back(std::move(layer));
                    layer.Clear();
                    identified = false;
                }
            }

            buffer[bufferSize] = '\0';

            if (identified) {
                if (bufferSize >= httpContentPattern.size() && memcmp(buffer, httpContentPattern.data(), httpContentPattern.size()) == 0) {
                    identified      = true;
                    auto payloadLen = Number::ToInt64((char*) buffer + httpContentPattern.size());
                    if (payloadLen.has_value())
                        layer.payload.size = (uint32) payloadLen.value();
                }
            }

            wasEndline = false;
            spaces     = 0;

            if (!identified) {
                if (bufferSize < httpPattern.size())
                    break;
                if (memcmp(buffer, httpPattern.data(), httpPattern.size()) == 0) {
                    identified         = true;
                    const auto nameLen = strlen((char*) buffer);
                    layer.name         = std::make_unique<uint8[]>(nameLen + 1);
                    memcpy(layer.name.get(), buffer, nameLen + 1);
                } else if (memcmp(buffer + bufferSize - httpPattern.size() - 1, httpPattern.data(), httpPattern.size()) == 0) {
                    identified         = true;
                    const auto nameLen = strlen((char*) buffer);
                    layer.name         = std::make_unique<uint8[]>(nameLen + 1);
                    memcpy(layer.name.get(), buffer, nameLen + 1);
                    std::string_view sv = { (char*) buffer, bufferSize - httpPattern.size() - 2 };
                    GetFileExtracted(layer);
                    callbackInterface->AddConnectionSummary(std::string(sv.data(), sv.length()));
                }
            }
            bufferSize         = 0;
            buffer[bufferSize] = '\0';

            if (bufferSize >= maxWaitUntilEndLine - 1)
                break;
            buffer[bufferSize++] = *startPtr;
        } else {
            if (bufferSize >= maxWaitUntilEndLine - 1)
                return nullptr;
            buffer[bufferSize++] = *startPtr;
        }

        startPtr++;
    }

    if (startPtr >= endPtr) {
        callbackInterface->AddConnectionAppLayerName("HTTP");
    }

    return this;
}
