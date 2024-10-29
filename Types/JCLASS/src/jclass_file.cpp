#include "jclass.hpp"
#include <nlohmann/json.hpp>

using namespace AppCUI;
using namespace AppCUI::OS;
using namespace AppCUI::Controls;
using namespace AppCUI::Application;
using namespace GView::Type;
using namespace GView::View;
using nlohmann::json;

namespace GView::Type::JClass
{

string_view ClassViewer::GetTypeName()
{
    return "class";
}

void ClassViewer::RunCommand(std::string_view)
{
}

std::string ClassViewer::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    json context;
    context["Name"]        = obj->GetName();
    context["ContentSize"] = obj->GetData().GetSize();
    return context.dump();
}
} // namespace GView::Type::JClass
