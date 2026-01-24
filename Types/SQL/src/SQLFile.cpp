#include "sql.hpp"

namespace GView::Type::SQL
{
	SQLFile::SQLFile()
	{
	}

	bool SQLFile::Update() {
        return true;
	}

	GView::Utils::JsonBuilderInterface* SQLFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
    {
        auto builder = GView::Utils::JsonBuilderInterface::Create();
        builder->AddU16String("Name", obj->GetName());
        builder->AddUInt("ContentSize", obj->GetData().GetSize());
        return builder;
    }
}