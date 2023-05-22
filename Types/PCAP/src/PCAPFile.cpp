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
        const std::string_view sv = std::string_view{ (char*) path.data(), path.size() };
        const auto indexVal       = Number::ToInt32(sv);
        if (indexVal.has_value())
        {
            const auto& stream = streamManager[indexVal.value()];
            totalItems         = stream->applicationLayers.size();
            parent.SetData(indexVal.value());
        }
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
        streamIndex = itemData;
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
        item.SetExpandable(!stream->applicationLayers.empty());
        item.SetData(currentItemIndex);

        item.SetText(tmp.Format("%s", n.ToString(streamIndex, NUMERIC_FORMAT).data()));
        item.SetText(1, stream->name);
        item.SetText(2, stream->GetIpProtocolName());
        item.SetText(3, stream->GetTransportProtocolName());
        item.SetText(4, tmp.Format("%s", n.ToString(stream->totalPayload, NUMERIC_FORMAT).data()));
    }
    else
    {
        item.SetExpandable(false);
        item.SetData(currentItemIndex);

        item.SetText(tmp.Format("%s", n.ToString(currentItemIndex, NUMERIC_FORMAT).data()));
        item.SetText(1, tmp.Format("%s", stream->applicationLayers[currentItemIndex].name));
    }

    currentItemIndex++;
    return currentItemIndex != this->currentChildIndexes.size();
}

void PCAPFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    const auto stream = streamManager[static_cast<uint32>(item.GetData(-1))];
    if (!stream)
        return;

    uint8* payload = new uint8[stream->connPayload.size];
    memcpy(payload, stream->connPayload.location, stream->connPayload.size);

    const Buffer buffer = { payload, stream->connPayload.size };
    GView::App::OpenBuffer(buffer, "name", "name", GView::App::OpenMethod::BestMatch);
}
