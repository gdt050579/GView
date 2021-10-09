#include "GViewApp.hpp"

using namespace GView::App;

constexpr int HORIZONTA_PANEL_ID = 100000;

bool FileWindow::Create(const GView::Type::Plugin& plugin, std::unique_ptr<GView::Object> fileObj)
{
    // take ownership
    this->fileObject = std::move(fileObj);
    // builder action
    CHECK(plugin.Create(builder, *this->fileObject.get()), false, "Building the view failed !");
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
    return true;
}