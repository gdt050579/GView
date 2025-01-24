#include "FtpParser.hpp"
#include <PCAP.hpp>

using namespace GView::Type::PCAP;
constexpr uint32 maxWaitUntilEndLine = 300;
constexpr std::string_view ftpWelcomePattern = "220 ";
constexpr std::string_view ftpCommandPattern = "USER ";

PayloadDataParserInterface* FTP::FTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    const auto connPayload = payloadInformation.payload;
    if (connPayload->size < 10 || memcmp(connPayload->location, ftpWelcomePattern.data(), ftpWelcomePattern.size()) != 0)
        return nullptr;

    auto& applicationLayers      = callbackInterface->GetApplicationLayers();
    StreamTcpLayer summaryLayer  = {};
    StreamTcpLayer detailedLayer = {};

    std::ostringstream detailedInfo;
    detailedInfo << "FTP Packet Analysis:\n";
    uint32 packetCount = 0, layerCount = 0;
    std::map<std::string, std::string> ftpKeyValueMap;

    for (auto& packet : *payloadInformation.packets) {
        packetCount++;
        detailedInfo << "\nIndex Packet: " << packetCount << "\n";
        detailedInfo << "Packet Info:\n";
        detailedInfo << "  Timestamp: " << packet.header->tsSec << "." << packet.header->tsUsec << "\n";
        detailedInfo << "  Captured Length: " << packet.header->inclLen << " bytes\n";
        detailedInfo << "  Original Length: " << packet.header->origLen << " bytes\n";

        if (packet.packetData.linkLayer.has_value()) {
            auto ipv4 = (IPv4Header*) packet.packetData.linkLayer->header;
            detailedInfo << "Ethernet Header:\n";
            detailedInfo << "  IPv4 Source: " << ipv4->sourceAddress << "\n";
            detailedInfo << "  IPv4 Destination: " << ipv4->destinationAddress << "\n";
        }

        if (packet.packetData.transportLayer.has_value() && packet.packetData.transportLayer->transportLayer == IP_Protocol::TCP) {
            auto tcp = (TCPHeader*) packet.packetData.transportLayer->transportLayerHeader;
            detailedInfo << "TCP Header:\n";
            detailedInfo << "  Source Port: " << tcp->sPort << "\n";
            detailedInfo << "  Destination Port: " << tcp->dPort << "\n";
        }

        if (packet.payload.size > 0) {
            detailedInfo << "FTP Data Packet:\n";
            detailedInfo << "  Payload Size: " << packet.payload.size << " bytes\n";
        }
        if (packet.payload.size > 0) {
            std::string ftpMessage(reinterpret_cast<const char*>(packet.payload.location), packet.payload.size);
            detailedInfo << "FTP Payload: " << ftpMessage << "\n";


			// Parse the FTP message into key-value pairs (assuming '=' is the delimiter)
			std::istringstream ftpStream(ftpMessage);
			std::string line;
			while (std::getline(ftpStream, line)) {
				size_t delimiterPos = line.find(' ');
				if (delimiterPos != std::string::npos) {
					std::string key = line.substr(0, delimiterPos);
					std::string value = line.substr(delimiterPos + 1);
					ftpKeyValueMap[key] = value;
				}
			}
	    }
    }


    detailedInfo << "\nSummary:\n";
    detailedInfo << "  Total Packets: " << packetCount << "\n";
    detailedInfo << "  Layers Processed: " << layerCount << "\n";

	std::ostringstream tableInfo;

	if (!ftpKeyValueMap.empty())
	{
		tableInfo << "-----------------------------------------\n\n";

		tableInfo << "Parsed FTP Key-Value Map (Table Format):\n";

		for (const auto& [key, value] : ftpKeyValueMap)
		{
			tableInfo  << std::setw(20) << std::left << key
					  << std::setw(15) << std::left << value << "\n";
		}

		tableInfo << "-----------------------------------------\n\n";
	}

	std::string originalInfo = detailedInfo.str();
	detailedInfo.str(""); 
	detailedInfo.clear(); 

	detailedInfo << tableInfo.str(); 
	detailedInfo << originalInfo;    

    std::string dataStr = detailedInfo.str();

    // Assign values to summary layer
    const char* summaryText = "FTP Connection Established";
    summaryLayer.name       = std::make_unique<uint8[]>(strlen(summaryText) + 1);
    memcpy(summaryLayer.name.get(), summaryText, strlen(summaryText) + 1);
    applicationLayers.emplace_back(std::move(summaryLayer));

   
    // Assign values to detailed layer
    const char* detailedText = "Detailed FTP Information";
    detailedLayer.name       = std::make_unique<uint8[]>(strlen(detailedText) + 1);
    memcpy(detailedLayer.name.get(), detailedText, strlen(detailedText) + 1);
    detailedLayer.payload.size     = dataStr.size() + 1;
    detailedLayer.payload.location = new uint8[detailedLayer.payload.size];
    memcpy(detailedLayer.payload.location, dataStr.c_str(), detailedLayer.payload.size);
    applicationLayers.emplace_back(std::move(detailedLayer));

    std::ostringstream conciseSummary;
    conciseSummary << "FTP Packet Analysis: " << packetCount << " packets captured.";
    callbackInterface->AddConnectionSummary(conciseSummary.str());
    callbackInterface->AddConnectionAppLayerName("FTP");
    return this;
}
