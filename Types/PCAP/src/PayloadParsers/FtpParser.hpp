#pragma once

#include "API.hpp"

namespace GView::Type::PCAP::FTP
{

struct FTPParser : public PayloadDataParserInterface {
    std::string GetProtocolName() const override
    {
        return "FTP";
    }

    PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) override;
};
} // namespace GView::Type::PCAP::HTTP