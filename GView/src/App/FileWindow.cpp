#include "GViewApp.hpp"

using namespace GView::App;

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
    this->verticalPanels.Create(&vertical, "d:c", TabFlags::ListView);
    this->horizontalPanels.Create(&horizontal, "d:c");
    // 3. add panes
    for (auto &ctrl : builder.verticalPanels)
    {
        this->verticalPanels.AddControl(ctrl.get());
    }
    
    return true;
}