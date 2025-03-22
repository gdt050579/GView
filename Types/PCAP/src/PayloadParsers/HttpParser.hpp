#pragma once

#include "API.hpp"

namespace GView::Type::PCAP::HTTP
{

struct HTTPParser : public PayloadDataParserInterface {
    std::string GetProtocolName() const override
    {
        return "HTTP";
    }

    PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) override;
};
} // namespace GView::Type::PCAP::HTTP