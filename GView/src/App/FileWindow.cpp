#include "GViewApp.hpp"

using namespace GView::App;

constexpr int HORIZONTA_PANEL_ID = 100000;

FileWindow::FileWindow(std::unique_ptr<GView::Object> obj): 
    Window("", "d:c", WindowFlags::Sizeable),
    builder(std::move(obj))
{
     
}
bool FileWindow::Create(const GView::Type::Plugin& plugin)
{
    // builder action
    CHECK(plugin.Create(builder, *builder.fileObject), false, "Building the view failed !");
    // all good - lets create objects
    // 1. create window
    horizontal = this->CreateChildControl<Splitter>("d:c", false);
    vertical = horizontal->CreateChildControl<Splitter>("d:c", true);
    // 2. views
    view = vertical->CreateChildControl<Tab>("d:c", TabFlags::HideTabs, 16);
    verticalPanels = vertical->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    horizontalPanels = horizontal->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    // 3. add vertical panels
    for (auto &ctrl : builder.verticalPanels)
    {
        this->verticalPanels->AddControl(std::move(ctrl));
    }
    // 4. add horizontal panels
    auto cb = this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft);
    //cb.AddSingleChoiceItem("<*>", 100, true);
    int id = HORIZONTA_PANEL_ID;
    for (auto& ctrl : builder.horizontalPanels)
    {
        cb.AddSingleChoiceItem((AppCUI::Utils::CharacterView)ctrl->GetText(), id++, false);
        this->horizontalPanels->AddControl(std::move(ctrl));        
    }
    // 5. add builders
    for (auto& viewBuilder : builder.views)
    {
        this->view->AddControl(viewBuilder->Build(*builder.fileObject));
    }
    return true;
}