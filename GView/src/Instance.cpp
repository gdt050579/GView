#include <GViewApp.hpp>

using namespace GView::App;
using namespace AppCUI::Application;

bool Instance::Init()
{
    InitializationData initData;
    initData.Flags = InitializationFlags::Menu | InitializationFlags::CommandBar;
    CHECK(AppCUI::Application::Init(initData), false, "Fail to initialize AppCUI framework !");


    return true;
}
void Instance::Run()
{
    AppCUI::Application::Run();
}