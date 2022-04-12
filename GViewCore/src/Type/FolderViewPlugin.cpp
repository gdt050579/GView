#include "Internal.hpp"
#include <filesystem>

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
        Factory::ListView::Create(
              this, "d:c", { { "Field", TextAlignament::Left, 10 }, { "Value", TextAlignament::Left, 100 } }, ListViewFlags::None);
    }
};
class FolderType : public TypeInterface, public View::ContainerViewer::EnumerateInterface
{
  public:
    std::filesystem::path root;
    std::filesystem::directory_iterator dirIT;

    string_view GetTypeName() override
    {
        return "Folder";
    }
    void BuildPath(TreeViewItem item, std::filesystem::path &path)
    {
        if (item.IsValid())
        {
            BuildPath(item.GetParent(), path);
            auto text = item.GetText();
            
            //path /= item.GetText();
        }
        else
        {
            path = root;
        }
    }
    virtual bool Start(TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
};
bool FolderType::Start(TreeViewItem parent)
{
    std::filesystem::path path;
    BuildPath(parent, path);
    dirIT = std::filesystem::directory_iterator(path);
    return dirIT->exists();
}
bool FolderType::PopulateItem(TreeViewItem item)
{
    item.SetText(dirIT->path().filename().u8string());
    if (dirIT->is_directory())
    {
        item.SetType(TreeViewItem::Type::Highlighted);
        item.SetExpandable(true);
    }
    else
    {
        item.SetType(TreeViewItem::Type::Normal);
        item.SetExpandable(false);
    }
    dirIT++;
    
    return dirIT != std::filesystem::directory_iterator();
}
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
    settings.SetColumns({ { "&Name", TextAlignament::Left, 24 },
                          { "&Type", TextAlignament::Left, 16 },
                          { "&Size", TextAlignament::Right, 12 },
                          { "&Created", TextAlignament::Center, 12 } });
    settings.SetEnumarateCallback((FolderType*) win->GetObject()->type);
    win->CreateViewer("FolderView", settings);
    return true;
}
} // namespace GView::Type::FolderViewPlugin