#include "GViewApp.hpp"

using namespace GView::App;

bool FileWindow::Create(const GView::Type::Plugin& plugin, std::unique_ptr<GView::Object> fileObj)
{
    // take ownership
    this->fileObject = std::move(fileObj);
    // create window
    Window::Create("<name>", "d:c", WindowFlags::Sizeable);
    this->horizontal.Create(this, "d:c", false);
    this->vertical.Create(&this->horizontal, "d:c", true);
    
    
    return true;
}