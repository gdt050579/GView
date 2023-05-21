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

bool PCAPFile::BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent)
{
    if (streamManager.empty())
        return false;

    currentItemIndex = 0;
    currentChildIndexes.clear();

    if (path.empty())
    {
        for (uint32 i = 0; i < streamManager.size(); i++)
            currentChildIndexes.push_back(i);

        return currentItemIndex != this->currentChildIndexes.size();
    }

    return false;
}

bool PCAPFile::PopulateItem(TreeViewItem item)
{
    const auto realIndex = currentChildIndexes.at(currentItemIndex);

    const auto stream = streamManager[realIndex];
    if (!stream)
        return false;

    const static NumericFormat NUMERIC_FORMAT{ NumericFormatFlags::None, 10 };

    LocalString<128> tmp;
    NumericFormatter n;

    item.SetExpandable(false);
    item.SetData(realIndex);

    item.SetText(tmp.Format("%s", n.ToString(realIndex, NUMERIC_FORMAT).data()));
    item.SetText(1, stream->name);
    item.SetText(2, stream->GetIpProtocolName());
    item.SetText(3, stream->GetTransportProtocolName());
    item.SetText(4, tmp.Format("%s", n.ToString(stream->totalPayload, NUMERIC_FORMAT).data()));

    currentItemIndex++;
    return currentItemIndex != this->currentChildIndexes.size();
}

void PCAPFile::OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item)
{
    const auto stream = streamManager[static_cast<uint32>(item.GetData(-1))];
    if (!stream)
        return;

    uint8* payload = new uint8[stream->totalPayload];

    auto payloadPtr = payload;
    for (const auto& packet : stream->packetsOffsets)
        if (packet.payload.location)
        {
            memcpy(payloadPtr, packet.payload.location, packet.payload.size);
            payloadPtr += packet.payload.size;
        }

    const Buffer buffer = { payload, stream->totalPayload };
    GView::App::OpenBuffer(buffer, "name", "name", GView::App::OpenMethod::BestMatch);
}
