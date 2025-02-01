#include <nlohmann/json.hpp>
#include "JT.hpp"

using namespace GView::Type::JT;
using nlohmann::json;

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

std::string JTFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    json context;
    context["Name"] = obj->GetName();
    context["ContentSize"] = obj->GetData().GetSize();
    context["TOCOffset"] = fh.tocOffset;
    context["TOCEntryCount"] = tc.entryCount;
    return context.dump();
}
