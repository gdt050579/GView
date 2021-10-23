#include "GViewApp.hpp"

using namespace GView::App;

constexpr int HORIZONTA_PANEL_ID = 100000;

FileWindow::FileWindow(const AppCUI::Utils::ConstString& name) : Window(name, "d:c", WindowFlags::Sizeable)
{
    // create splitters
    horizontal = this->CreateChildControl<Splitter>("d:c", false);
    vertical   = horizontal->CreateChildControl<Splitter>("d:c", true);
    
    // create tabs
    view             = vertical->CreateChildControl<Tab>("d:c", TabFlags::HideTabs, 16);
    verticalPanels   = vertical->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
    horizontalPanels = horizontal->CreateChildControl<Tab>("d:c", TabFlags::ListView | TabFlags::TransparentBackground, 16);
}
bool FileWindow::Create(const GView::Type::Plugin& plugin)
{
    //// builder action
    //CHECK(plugin.Create(builder, *builder.fileObject), false, "Building the view failed !");
    //// all good - lets create objects
    //
    //// 3. add vertical panels
    //for (auto &ctrl : builder.verticalPanels)
    //{
    //    this->verticalPanels->AddControl(std::move(ctrl));
    //}
    ////this->verticalPanels->GetChild(0)->SetFocus();
    //// 4. add horizontal panels
    //auto cb = this->GetControlBar(WindowControlsBarLayout::BottomBarFromLeft);
    ////cb.AddSingleChoiceItem("<*>", 100, true);
    //int id = HORIZONTA_PANEL_ID;
    //for (auto& ctrl : builder.horizontalPanels)
    //{
    //    cb.AddSingleChoiceItem((AppCUI::Utils::CharacterView)ctrl->GetText(), id++, false);
    //    this->horizontalPanels->AddControl(std::move(ctrl));        
    //}
    //// 5. add builders
    //for (auto& viewBuilder : builder.views)
    //{
    //    this->view->AddControl(viewBuilder->Build(*builder.fileObject));
    //}
    return true;
}
Reference<GView::Object> FileWindow::GetObject()
{
    return Reference<GView::Object>(&this->obj);
}
bool FileWindow::AddPanel(Pointer<TabPage> page, bool vertical)
{
    return false;
}
Reference<GView::View::BufferView> FileWindow::CreateBufferView(const std::string_view& name)
{
    return nullptr;
}