#include "ContainerViewer.hpp"

using namespace GView::View::ContainerViewer;
using namespace AppCUI::Input;

Config Instance::config;

constexpr int32 CMD_ID_ZOOMIN     = 0xBF00;
constexpr int32 CMD_ID_ZOOMOUT    = 0xBF01;
constexpr int32 CMD_ID_NEXT_IMAGE = 0xBF02;
constexpr int32 CMD_ID_PREV_IMAGE = 0xBF03;

Instance::Instance(Reference<GView::Object> _obj, Settings* _settings) : settings(nullptr), ViewControl("Container View")
{
    this->obj                     = _obj;
    this->tempCountRecursiveItems = 0;

    // settings
    if ((_settings) && (_settings->data))
    {
        // move settings data pointer
        this->settings.reset((SettingsData*) _settings->data);
        _settings->data = nullptr;
    }
    else
    {
        // default setup
        this->settings.reset(new SettingsData());
    }

    if (config.Loaded == false)
        config.Initialize();

    if (this->settings->name.Len() > 0)
    {
        this->name.Set(this->settings->name);
    }

    this->currentPath.Resize(256);
    this->currentPath.Clear();

    // create some object
    imgView = Factory::ImageView::Create(this, "x:0,y:0,w:16,h:8", ViewerFlags::HideScrollBar);
    if ((this->settings->icon.GetWidth() == 16) && (this->settings->icon.GetHeight() == 16))
        imgView->SetImage(this->settings->icon, ImageRenderingMethod::PixelTo16ColorsSmallBlock, ImageScaleMethod::NoScale);
    this->propList = Factory::ListView::Create(this, "l:17,t:0,r:0,h:8", { "n:Field,w:20", "n:Value,w:200" }, ListViewFlags::HideColumns);

    this->items = Factory::TreeView::Create(this, "l:0,t:8,r:0,b:0", {}, TreeViewFlags::DynamicallyPopulateNodeChildren | TreeViewFlags::Searchable);
    this->items->Handlers()->OnItemToggle         = this;
    this->items->Handlers()->OnItemPressed        = this;
    this->items->Handlers()->OnCurrentItemChanged = this;
    for (uint32 idx = 0; idx < settings->columnsCount; idx++)
    {
        const auto& col = settings->columns[idx];
        std::string layout; // TODO: GRX - unicode layout parsing seems to be having an issue
        col.layout.ToString(layout);
        this->items->AddColumn(layout);
    }
    for (uint32 idx = 0; idx < settings->propertiesCount; idx++)
    {
        auto item = this->propList->AddItem(settings->properties[idx].key);
        item.SetText(1, settings->properties[idx].value);
        item.SetType(settings->properties[idx].itemType);
        settings->properties[idx].key.Destroy();
        settings->properties[idx].value.Destroy();
    }
    if (settings->enumInterface)
    {
        const std::u16string sep{ char16_t(std::filesystem::path::preferred_separator) };
        this->root = this->items->AddItem(sep, true);
        this->root.Unfold();
    }
    this->items->Sort(0, SortDirection::Ascendent);
    this->items->SetFocus();
    UpdatePathForItem(this->items->GetCurrentItem());
}
void Instance::BuildPath(TreeViewItem item)
{
    if (item == this->root)
        return;
    if (item.IsValid())
    {
        BuildPath(item.GetParent());
        if (this->currentPath.Len() > 0)
        {
            this->currentPath.AddChar(this->settings->pathSeparator);
        }
        this->currentPath.Add(item.GetText(0));
    }
}
void Instance::UpdatePathForItem(TreeViewItem item)
{
    this->currentPath.Clear();
    BuildPath(item);
}
bool Instance::PopulateItem(TreeViewItem item)
{
    UpdatePathForItem(item);

    LocalString<128> temp;
    if (this->settings->enumInterface->BeginIteration(this->currentPath, item))
    {
        while (this->settings->enumInterface->PopulateItem(item.AddChild("")))
        {
            tempCountRecursiveItems++;
            if (AppCUI::Graphics::ProgressStatus::Update(tempCountRecursiveItems, temp.Format("Items: %u", tempCountRecursiveItems)))
                return false;
        }
    }
    return true;
}
bool Instance::OnTreeViewItemToggle(Reference<TreeView>, TreeViewItem& item, bool recursiveCall)
{
    if (!recursiveCall)
    {
        AppCUI::Graphics::ProgressStatus::Init("Reading folder");
        tempCountRecursiveItems = 0;
    }
    if (!item.IsFolded())
    {
        return PopulateItem(item);
    }
    return true;
}
void Instance::OnTreeViewItemPressed(Reference<TreeView>, TreeViewItem& item)
{
    if ((item.GetChildrenCount() == 0) && (this->settings->openItemInterface))
    {
        UpdatePathForItem(item);

        // TODO: investigate this:
        /*

            std::u16string newPath(this->obj->GetPath());
            newPath.append(u".").append(this->currentPath);
            this->settings->openItemInterface->OnOpenItem(newPath, item);
        */

        this->settings->openItemInterface->OnOpenItem(this->currentPath, item);
    }
}
void Instance::OnTreeViewCurrentItemChanged(Reference<TreeView>, TreeViewItem& item)
{
    UpdatePathForItem(item);
}
bool Instance::OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar)
{
    return false;
}
bool Instance::OnKeyEvent(AppCUI::Input::Key keyCode, char16 characterCode)
{
    return ViewControl::OnKeyEvent(keyCode, characterCode);
}
bool Instance::OnEvent(Reference<Control>, Event eventType, int ID)
{
    return false;
}
bool Instance::GoTo(uint64 offset)
{
    return false;
}
bool Instance::Select(uint64 offset, uint64 size)
{
    return false; // no selection is possible in this mode
}
bool Instance::ShowGoToDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowFindDialog()
{
    NOT_IMPLEMENTED(false);
}
bool Instance::ShowCopyDialog()
{
    NOT_IMPLEMENTED(false);
}
//======================================================================[Cursor information]==================

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& r, uint32 width, uint32 height)
{
    this->WriteCusorInfoLine(r, 0, 0, "Path: ", this->currentPath);
}

//======================================================================[PROPERTY]============================
enum class PropertyID : uint32
{
    // display
    None
};
#define BT(t) static_cast<uint32>(t)

bool Instance::GetPropertyValue(uint32 id, PropertyValue& value)
{
    switch (static_cast<PropertyID>(id))
    {
    default:
        break;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 id, const PropertyValue& value, String& error)
{
    CHECK(error.SetFormat("Unknown internat ID: %u", id), false, "");
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return false;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {};
}
#undef BT
