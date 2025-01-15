#include "PCAP.hpp"

using namespace GView::Type::PCAP;

PCAPFile::PCAPFile()
{
}

bool PCAPFile::Update()
{
    auto offset = 0;
    CHECK(obj->GetData().Copy<Header>(offset, header), false, "");
    offset += sizeof(Header);
    if (header.magicNumber == Magic::Swapped)
    {
        Swap(header);
    }

    // TODO: check for future, is this really ok? test with big pcap files
    data = obj->GetData().CopyToBuffer(offset, (uint32) obj->GetData().GetSize() - offset);
    CHECK(data.IsValid(), false, "");

    const auto delta = offset;
    do
    {
        const auto& [header, _] = packetHeaders.emplace_back((PacketHeader*) (data.GetData() + offset - delta), offset);
        offset += (sizeof(PacketHeader) + header->origLen);
    } while (offset < obj->GetData().GetSize());

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

    if (!path.empty())
    {
        uint32 value = 0;
        auto data    = path.data();
        auto dataEnd = data + path.size();
        while (data < dataEnd)
        {
            value = value * 10 + (int) *data - '0';
            data++;
        }
        const auto& stream = streamManager[value];
        totalItems         = (uint32)stream->applicationLayers.size();
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
    if (itemData != ITEM_INVALID_VALUE)
    {
        streamIndex = (uint32)itemData;
    }
    else
    {
        streamIndex = currentItemIndex;
        isTree      = true;
    }

    const auto stream = streamManager[streamIndex];
    if (!stream)
        return false;

    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::None, 10 };

    LocalString<128> tmp;
    NumericFormatter n;

    if (isTree)
    {
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
    }
    else
    {
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
    for (const auto c : path)
    {
        if (c >= '0' && c <= '9')
            toAppend->push_back((char)c);
        else
            toAppend = &applicationText;
    }

    const auto streamIdVar = Number::ToUInt32(streamText);
    if (!streamIdVar.has_value())
        return;

    const auto appLayerVar = Number::ToUInt32(applicationText);
    if (!appLayerVar.has_value())
        return;

    const auto& stream = streamManager[streamIdVar.value()];
    if (!stream)
        return;

    if (appLayerVar.value() >= stream->applicationLayers.size())
        return;

    const auto& layer = stream->applicationLayers[appLayerVar.value()];
    if (layer.payload.size == 0)
        return;

    uint8* payload = new uint8[layer.payload.size];
    memcpy(payload, layer.payload.location, layer.payload.size);

    std::string extractionName;
    if (!layer.extractionName.empty())
        extractionName = std::string(layer.extractionName.data(), layer.extractionName.size());
    else
        extractionName = (const char*) layer.name.get();

    const Buffer buffer = { payload, layer.payload.size };

    GView::App::OpenBuffer(buffer, extractionName, extractionName, GView::App::OpenMethod::BestMatch);
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
