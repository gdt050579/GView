#include "JT.hpp"

using namespace GView::Type::JT;

JTFile::JTFile()
{
}

bool JTFile::Update()
{
    auto offset = 0;
    CHECK(obj->GetData().Copy<FileHeader>(offset, fh), false, "");
    offset = fh.tocOffset;

    CHECK(obj->GetData().Copy<decltype(TOCSegment::entryCount)>(offset, tc.entryCount), false, "");

    tc.entries.resize(tc.entryCount);
    offset += sizeof(TOCSegment::entryCount);
    for (uint32 i = 0U; i < tc.entryCount; i++)
    {
        auto& entry = tc.entries.at(i);
        CHECK(obj->GetData().Copy<TOCEntry>(offset, entry), false, "");
        offset += sizeof(TOCEntry);
    }

    return true;
}

GView::Utils::JsonBuilderInterface* JTFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    builder->AddUInt("TOCOffset", fh.tocOffset);
    builder->AddUInt("TOCEntryCount", tc.entryCount);
    return builder;
}
