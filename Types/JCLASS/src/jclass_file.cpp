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

} // namespace GView::Type::JClass
