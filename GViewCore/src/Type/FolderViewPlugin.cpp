#include "Internal.hpp"

using namespace GView;

namespace GView::Type::FolderViewPlugin
{
class DefaultInformationPanel : public TabPage
{
  public:
    DefaultInformationPanel(Reference<Object> obj) : TabPage("&Information")
    {
        auto lv = this->CreateChildControl<ListView>("d:c", ListViewFlags::None);
        lv->AddColumn("Field", TextAlignament::Left, 10);
        lv->AddColumn("Value", TextAlignament::Left, 100);
    }
};
class FolderType : public TypeInterface
{
  public:
    std::filesystem::path root;

    string_view GetTypeName() override
    {
        return "Folder";
    }
};
TypeInterface* CreateInstance(const std::filesystem::path& path)
{
    auto* ft = new FolderType();
    ft->root = path;
    return ft;
}
bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    // at least one view and one information panel
    // 1. info panel
    win->AddPanel(Pointer<TabPage>(new DefaultInformationPanel(win->GetObject())), true);

    // 2. views   
    View::ContainerViewer::Settings settings;
    win->CreateViewer("Container", settings);
    return true;
}
} // namespace GView::Type::FolderViewPlugin