#include "jclass.hpp"

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Controls;
using namespace AppCUI::Application;
using namespace GView::Type;
using namespace GView::View;

namespace GView::Type::JClass
{

string_view ClassViewer::GetTypeName()
{
    return "class";
}

void ClassViewer::RunCommand(std::string_view)
{
}

GView::Utils::JsonBuilderInterface* ClassViewer::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    auto builder = GView::Utils::JsonBuilderInterface::Create();
    builder->AddU16String("Name", obj->GetName());
    builder->AddUInt("ContentSize", obj->GetData().GetSize());
    return builder;
}
} // namespace GView::Type::JClass
