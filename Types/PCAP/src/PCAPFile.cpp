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

    return true;
}
