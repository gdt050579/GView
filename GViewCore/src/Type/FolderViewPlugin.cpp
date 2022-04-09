#include "Internal.hpp"

using namespace GView;

namespace GView::Type::FolderViewPlugin
{

constexpr string_view folderIcon = "................" // 1
                                   "...WWW.........." // 2
                                   "..WYYYW........." // 3
                                   ".WYYYYYWWWWWWW.." // 4
                                   ".WooooooooooooW." // 5
                                   ".Wo..........oW." // 6
                                   ".Wo..........oW." // 7
                                   ".Wo..........oW." // 8
                                   ".Wo..........oW." // 9
                                   ".WooooooooooooW." // 10
                                   "..WWWWWWWWWWWW.." // 11
                                   "................" // 12
                                   "................" // 13
                                   "................" // 14
                                   "................" // 15
                                   "................";// 16
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
    settings.SetIcon(folderIcon);
    settings.AddColumn("&Name", TextAlignament::Left, 24);
    settings.AddColumn("&Type", TextAlignament::Left, 16);
    settings.AddColumn("&Size", TextAlignament::Right, 12);
    settings.AddColumn("&Created", TextAlignament::Center, 12);
    win->CreateViewer("Container", settings);
    return true;
}
} // namespace GView::Type::FolderViewPlugin