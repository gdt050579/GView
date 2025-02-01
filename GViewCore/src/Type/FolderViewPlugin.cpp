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
    DefaultInformationPanel(Reference<Object>) : TabPage("&Information")
    {
        Factory::ListView::Create(this, "d:c", { "n:Field,a:l,w:10", "n:Value,a:l,w:100" }, ListViewFlags::None);
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
    void RunCommand(std::string_view) override
    {
    }
    bool UpdateKeys(KeyboardControlsInterface* interface) override
    {
        return true;
    }

    virtual bool BeginIteration(std::u16string_view path, AppCUI::Controls::TreeViewItem parent) override;
    virtual bool PopulateItem(TreeViewItem item) override;
    virtual void OnOpenItem(std::u16string_view path, AppCUI::Controls::TreeViewItem item) override;
    virtual std::string GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
};
bool FolderType::BeginIteration(std::u16string_view relativePath, AppCUI::Controls::TreeViewItem)
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
    catch (std::filesystem::filesystem_error const& ex)
    {
        RETURNERROR(false, ex.what());
    }
}
bool FolderType::PopulateItem(TreeViewItem item)
{
    AppCUI::OS::DateTime dt;
    bool nameWasSet = false;
    try
    {
        item.SetText(dirIT->path().filename().u8string());
        dt.CreateFrom(*dirIT);
        item.SetText(2, dt.GetStringRepresentation());
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
void FolderType::OnOpenItem(std::u16string_view relativePath, AppCUI::Controls::TreeViewItem)
{
    std::filesystem::path path = root;
    path /= relativePath;
    GView::App::OpenFile(path,GView::App::OpenMethod::BestMatch);
}

std::string FolderType::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    NOT_IMPLEMENTED("FOLDER PLUGIN");
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
    auto ft = win->GetObject()->GetContentType<FolderType>();
    // 2. views
    View::ContainerViewer::Settings settings;
    settings.SetIcon(folderIcon);
    settings.SetColumns({ "n:&Name,a:l,w:50", "n:&Size,a:r,w:16", "n:&Created,a:c,w:21" });
    settings.AddProperty("Path", ft->root.u16string());
    settings.SetEnumerateCallback(win->GetObject()->GetContentType<FolderType>().ToObjectRef<View::ContainerViewer::EnumerateInterface>());
    settings.SetOpenItemCallback(win->GetObject()->GetContentType<FolderType>().ToObjectRef<View::ContainerViewer::OpenItemInterface>());
    settings.SetName("Folder View");
    win->CreateViewer(settings);
    return true;
}
} // namespace GView::Type::FolderViewPlugin
