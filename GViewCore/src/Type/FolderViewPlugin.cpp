#include "Internal.hpp"
#include <filesystem>

using namespace GView;

namespace GView::Type::FolderViewPlugin
{

constexpr string_view folderIcon = "................"  // 1
                                   "...WWW.........."  // 2
                                   "..WYYYW........."  // 3
                                   ".WYYYYYWWWWWWW.."  // 4
                                   ".Wy0y0y0y0y0yoW."  // 5
                                   ".W0y0y0y0y0y0yW."  // 6
                                   ".Wy0y0y0y0y0y0W."  // 7
                                   ".W0y0y0y0y0y0yW."  // 8
                                   ".Wy0y0y0y0y0y0W."  // 9
                                   ".WyyyyyyyyyyyyW."  // 10
                                   "..WWWWWWWWWWWW.."  // 11
                                   "................"  // 12
                                   "................"  // 13
                                   "................"  // 14
                                   "................"  // 15
                                   "................"; // 16
class DefaultInformationPanel : public TabPage
{
  public:
    DefaultInformationPanel(Reference<Object> obj) : TabPage("&Information")
    {
        Factory::ListView::Create(
              this, "d:c", { { "Field", TextAlignament::Left, 10 }, { "Value", TextAlignament::Left, 100 } }, ListViewFlags::None);
    }
};
class FolderType : public TypeInterface, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
{
  public:
    std::filesystem::path root;
    std::filesystem::path temp;
    std::filesystem::directory_iterator dirIT;

    string_view GetTypeName() override
    {
        return "Folder";
    }

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;
};
bool FolderType::BeginIteration(std::u16string_view relativePath, AppCUI::Controls::TreeViewItem parent)
{
    try
    {
        std::filesystem::path path = root;
        path /= relativePath;
        dirIT = std::filesystem::directory_iterator(path);
        if (dirIT == std::filesystem::directory_iterator())
            return false; // empty directory
        return dirIT->exists();
    }
    catch (...)
    {
        return false;
    }
}
bool FolderType::PopulateItem(TreeViewItem item)
{
    bool nameWasSet = false;
    try
    {
        item.SetText(dirIT->path().filename().u8string());
        nameWasSet = true;
        if (dirIT->is_directory())
        {
            item.SetType(TreeViewItem::Type::Category);
            item.SetExpandable(true);
            item.SetText(1, "<FOLDER>");
            item.SetPriority(1);
        }
        else
        {
            item.SetType(TreeViewItem::Type::Normal);
            item.SetExpandable(false);
            NumericFormat fmt(NumericFormatFlags::None, 10, 3, ',');
            NumericFormatter nf;
            item.SetText(1, nf.ToString((uint64) dirIT->file_size(), fmt));
            item.SetPriority(0);
        }
    }
    catch (...)
    {
        item.SetExpandable(false);
        item.SetType(TreeViewItem::Type::ErrorInformation);
        item.SetText(1, "<ERROR>");
        if (!nameWasSet)
            item.SetText("Fail to read name");
    }
    dirIT++;

    return dirIT != std::filesystem::directory_iterator();
}
void FolderType::OnOpenItem(std::u16string_view relativePath, AppCUI::Controls::TreeViewItem item)
{
    std::filesystem::path path = root;
    path /= relativePath;
    GView::App::OpenFile(path);
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
    settings.SetColumns(
          { { "&Name", TextAlignament::Left, 50 }, { "&Size", TextAlignament::Right, 16 }, { "&Created", TextAlignament::Center, 12 } });
    settings.SetEnumerateCallback(win->GetObject()->GetContentType<FolderType>().ToObjectRef<View::ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<FolderType>().ToObjectRef<View::ContainerViewer::OpenItemInterface>());
    win->CreateViewer("FolderView", settings);
    return true;
}
} // namespace GView::Type::FolderViewPlugin
