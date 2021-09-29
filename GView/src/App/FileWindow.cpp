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
    Window::Create("<name>", "d:c", WindowFlags::Sizeable);
    this->horizontal.Create(this, "d:c", false);
    this->vertical.Create(&this->horizontal, "d:c", true);
    // 2. views
    this->view.Create(&vertical, "d:c");
    this->verticalPanels.Create(&vertical, "d:c", TabFlags::ListView | TabFlags::TransparentBackground);
    this->horizontalPanels.Create(&horizontal, "d:c", TabFlags::HideTabs | TabFlags::TransparentBackground);
    // 3. add vertical panels
    for (auto &ctrl : builder.verticalPanels)
    {
        this->verticalPanels.AddControl(ctrl.get());
    }
    // 4. add horizontal panels
    auto cb = this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft);
    //cb.AddSingleChoiceItem("<*>", 100, true);
    int id = HORIZONTA_PANEL_ID;
    for (auto& ctrl : builder.horizontalPanels)
    {
        this->horizontalPanels.AddControl(ctrl.get());
        cb.AddSingleChoiceItem((AppCUI::Utils::CharacterView)ctrl->GetText(), id++, false);
    }
    return true;
}