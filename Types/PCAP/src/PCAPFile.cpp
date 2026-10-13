#include "PCAP.hpp"

#include <algorithm>

using namespace GView::Type::PCAP;

PCAPFile::PCAPFile()
{
}

bool PCAPFile::Update()
{
    auto offset = 0ULL;
    CHECK(obj->GetData().Copy<Header>(offset, header), false, "");
    offset += sizeof(Header);
    const bool swapped = header.magicNumber == Magic::Swapped;
    if (swapped)
    {
        Swap(header);
    }

    // the whole capture is kept in memory and packet offsets are stored as uint32
    const auto fileSize = obj->GetData().GetSize();
    CHECK(fileSize >= offset && fileSize <= 0xFFFFFFFFULL, false, "");
    if (fileSize == offset)
    {
        return true; // a valid capture without packets
    }
    data = obj->GetData().CopyToBuffer(offset, static_cast<uint32>(fileSize - offset));
    CHECK(data.IsValid(), false, "");

    // Every consumer reads inclLen bytes after a packet header, so a packet is kept only if its header and its saved data
    // fit in the buffer. A truncated last packet ends the list.
    const uint64 dataSize = data.GetLength();
    uint64 position       = 0;
    while (dataSize - position >= sizeof(PacketHeader))
    {
        auto packet = reinterpret_cast<PacketHeader*>(data.GetData() + position);
        if (swapped)
        {
            packet->tsSec   = AppCUI::Endian::BigToNative(packet->tsSec);
            packet->tsUsec  = AppCUI::Endian::BigToNative(packet->tsUsec);
            packet->inclLen = AppCUI::Endian::BigToNative(packet->inclLen);
            packet->origLen = AppCUI::Endian::BigToNative(packet->origLen);
        }
        if (packet->inclLen > dataSize - position - sizeof(PacketHeader))
        {
            break;
        }
        packetHeaders.emplace_back(packet, static_cast<uint32>(offset + position));
        position += sizeof(PacketHeader) + packet->inclLen;
    }

    return true;
}

constexpr uint64 ITEM_INVALID_VALUE = static_cast<uint64>(-1);

bool PCAPFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    if (streamManager.empty())
        return false;

    currentItemIndex = 0;
    currentChildIndexes.clear();

    uint32 totalItems = (uint32) streamManager.size();

    if (!path.empty()) {
        uint32 value = 0;
        auto data    = path.data();
        auto dataEnd = data + path.size();
        while (data < dataEnd) {
            value = value * 10 + (int) *data - '0';
            data++;
        }
        const auto& stream = streamManager[value];
        totalItems         = (uint32) stream->applicationLayers.size();
        parent.SetData(value);
    }

    for (uint32 i = 0; i < totalItems; i++)
        currentChildIndexes.push_back(i);

    return currentItemIndex != this->currentChildIndexes.size();
}

bool PCAPFile::PopulateItem(TreeViewItem item)
{
    uint32 streamIndex;
    const uint64 itemData = item.GetParent().GetData(ITEM_INVALID_VALUE);
    bool isTree           = false;
    if (itemData != ITEM_INVALID_VALUE) {
        streamIndex = (uint32) itemData;
    } else {
        streamIndex = currentItemIndex;
        isTree      = true;
    }

    const auto stream = streamManager[streamIndex];
    if (!stream)
        return false;

    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::None, 10 };

    LocalString<128> tmp;
    NumericFormatter n;

    if (isTree) {
        const bool isExpandable = !stream->applicationLayers.empty();
        item.SetExpandable(isExpandable);
        item.SetData(currentItemIndex);

        item.SetText(tmp.Format("%s", n.ToString(streamIndex, NUMERIC_FORMAT).data()));
        item.SetText(1, stream->name);
        item.SetText(2, stream->GetIpProtocolName());
        item.SetText(3, stream->GetTransportProtocolName());
        item.SetText(4, tmp.Format("%s", n.ToString(stream->totalPayload, NUMERIC_FORMAT).data()));
        item.SetText(5, stream->appLayerName.data());
        item.SetText(6, stream->summary.data());

        if (isExpandable)
            item.SetType(TreeViewItem::Type::Highlighted);
    } else {
        item.SetExpandable(false);
        item.SetData(currentItemIndex);

        item.SetText(tmp.Format("%s", n.ToString(currentItemIndex, NUMERIC_FORMAT).data()));
        item.SetText(1, tmp.Format("%s", stream->applicationLayers[currentItemIndex].name.get()));

        item.SetText(4, tmp.Format("%s", n.ToString(stream->applicationLayers[currentItemIndex].payload.size, NUMERIC_FORMAT).data()));
        if (stream->applicationLayers[currentItemIndex].payload.size > 0)
            item.SetType(TreeViewItem::Type::Highlighted);
    }

    currentItemIndex++;
    return currentItemIndex != this->currentChildIndexes.size();
}

void PCAPFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    if (path.empty())
        return;

    // TODO: improve
    std::string streamText, applicationText;
    std::string* toAppend = &streamText;
    for (const auto c : path) {
        if (c >= '0' && c <= '9')
            toAppend->push_back((char) c);
        else
            toAppend = &applicationText;
    }

    const auto streamIdVar = Number::ToUInt32(streamText);
    if (!streamIdVar.has_value())
        return;

    const auto appLayerVar = Number::ToUInt32(applicationText);
    if (!appLayerVar.has_value())
        return;

    OpenStreamPayload(streamIdVar.value(), appLayerVar.value());
}

bool PCAPFile::OpenStreamPayload(uint32 streamId, uint32 layerIndex)
{
    const auto& stream = streamManager[streamId];
    if (!stream)
        return false;

    if (layerIndex >= stream->applicationLayers.size())
        return false;

    const auto& layer = stream->applicationLayers[layerIndex];
    if (layer.payload.size == 0)
        return false;

    uint8* payload = new uint8[layer.payload.size];
    memcpy(payload, layer.payload.location, layer.payload.size);

    std::string extractionName;
    if (!layer.extractionName.empty())
        extractionName = std::string(layer.extractionName.data(), layer.extractionName.size());
    else
        extractionName = (const char*) layer.name.get();

    const Buffer buffer = { payload, layer.payload.size };

    auto parent = AppCUI::Application::GetCurrentWindow();
    LocalString<128> creation_method;
    creation_method.SetFormat("Stream %u, layer %u", streamId, layerIndex);
    GView::App::OpenBuffer(buffer, extractionName, extractionName, GView::App::OpenMethod::BestMatch, "", parent, creation_method.GetText());
    return true;
}

std::vector<std::pair<std::string, std::string>> PCAPFile::GetPropertiesForContainerView()
{
    std::vector<std::pair<std::string, std::string>> result{};
    result.reserve(4);

    LocalString<32> tmp;
    tmp.SetFormat("%hu.%hu", header.versionMajor, header.versionMinor);

    NumericFormatter n;
    result.emplace_back("PCAP Version", tmp.GetText());
    result.emplace_back("Total packets", n.ToString((uint32) packetHeaders.size(), NumericFormatFlags::None).data());
    result.emplace_back("Total streams", n.ToString((uint32) streamManager.size(), NumericFormatFlags::None).data());
    result.emplace_back("Protocols", streamManager.GetProtocolsFound().data());

    return result;
}

GView::Utils::JsonBuilderInterface* PCAPFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    builder->AddUInt("TotalPackets", packetHeaders.size());
    builder->AddUInt("TotalStreams", streamManager.size());
    return builder;
}

GView::HDF::ActionStatus PCAPFile::Execute(const GView::HDF::GroundActionView& action, const GView::HDF::ActionInput*, GView::HDF::DisclosureSink& out)
{
    using GView::HDF::ActionStatus;
    if (action.action == actions.CheckConnections) {
        // every connection that transfers an executable or a script becomes a subject extracted from the capture
        const auto self         = out.Self();
        const auto executables  = streamManager.GetConnectionsWithExecutables();
        const auto scripts      = streamManager.GetConnectionsWithJSScripts();
        std::vector<uint16> all = executables;
        all.insert(all.end(), scripts.begin(), scripts.end());
        std::sort(all.begin(), all.end());
        all.erase(std::unique(all.begin(), all.end()), all.end());
        if (all.size() > MAX_CONNECTION_SUBJECTS)
            all.resize(MAX_CONNECTION_SUBJECTS);
        for (const auto id : all) {
            LocalString<64> name;
            name.SetFormat("Connection %u", static_cast<uint32>(id));
            const auto connection = out.CreateSubject(name.ToStringView(), self);
            if (!connection.IsValid())
                continue;
            connectionOfSubject[connection.id] = id;
            if (std::binary_search(executables.begin(), executables.end(), id))
                out.Assert(predicates.HasConnectionWithExecutable, { connection, streamManager.GetExecutableNameFromConnection(id) });
            if (std::binary_search(scripts.begin(), scripts.end(), id))
                out.Assert(predicates.HasConnectionWithScript, { connection, streamManager.GetScriptNameFromConnection(id) });
        }
        return ActionStatus::Success;
    }
    if (action.action == actions.ExtractConnectionData) {
        const auto connection = action.SubjectArg(0);
        const auto it         = connectionOfSubject.find(connection.id);
        if (it == connectionOfSubject.end())
            return ActionStatus::Failed;
        const auto* stream = streamManager[it->second];
        if (!stream || stream->applicationLayers.size() < 2 || stream->applicationLayers[1].payload.size == 0)
            return ActionStatus::Failed; // nothing transferred over this connection
        const auto& layer = stream->applicationLayers[1];
        std::string name  = !layer.extractionName.empty() ? std::string(layer.extractionName.data(), layer.extractionName.size())
                                                          : std::string((const char*) layer.name.get());
        // the payload is a new subject; the window opened for it attaches to it (its PopulateWindow discloses into Gamma_beta)
        if (!out.CreateSubject(name, connection).IsValid())
            return ActionStatus::Failed;
        return OpenStreamPayload(it->second, 1) ? ActionStatus::Success : ActionStatus::Failed;
    }
    return ActionStatus::Failed;
}
