#include "Unpacker.hpp"

#include <unordered_map>
#include <vector>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;

constexpr int BTN_ID_OK     = 1;
constexpr int BTN_ID_CANCEL = 2;

namespace GView::GenericPlugins::Unpackers
{
using namespace AppCUI::Graphics;
using namespace GView::View;


Plugin::Plugin() : Window("Unpackers", "d:c,w:140,h:40", WindowFlags::FixedPosition)
{
    sync = Factory::CheckBox::Create(this, "&Unpackers", "x:2%,y:1,w:30");
    sync->SetChecked(false);

    list = Factory::ListView::Create(
          this,
          "x:2%,y:3,w:96%,h:80%",
          { "n:Window,w:45%", "n:View Name,w:15%", "n:View (Buffer) Count,w:20%", "n:Unpacker,w:20%" },
          ListViewFlags::AllowMultipleItemsSelection);
    list->SetFocus();

    auto ok                         = Factory::Button::Create(this, "&Ok", "x:25%,y:100%,a:b,w:12", BTN_ID_OK);
    ok->Handlers()->OnButtonPressed = this;
    ok->SetFocus();
    Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL)->Handlers()->OnButtonPressed = this;

    Update();
}

void Plugin::OnButtonPressed(Reference<Button> button)
{
    switch (button->GetControlID()) {
    case BTN_ID_CANCEL:
        this->Exit(Dialogs::Result::Cancel);
        break;
    case BTN_ID_OK:
        // select this unpacker and apply it
        this->Exit(Dialogs::Result::Ok);
        break;
    default:
        break;
    }
}

void Plugin::Update()
{
    if (list.IsValid() == false) {
        return;
    }
    list->DeleteAllItems();

    auto item = list->AddItem({ "Ceva", "ViewName", "CevaFormat", "Base64" });

    // auto desktop         = AppCUI::Application::GetDesktop();
    // const auto windowsNo = desktop->GetChildrenCount();
    // for (uint32 i = 0; i < windowsNo; i++)
    //{
    //     auto window    = desktop->GetChild(i);
    //     auto interface = window.ToObjectRef<GView::View::WindowInterface>();

    //    auto currentView           = interface->GetCurrentView();
    //    const auto currentViewName = currentView->GetName();

    //    auto object           = interface->GetObject();
    //    const auto typeName   = object->GetContentType()->GetTypeName();
    //    const auto objectName = object->GetName();

    //    uint32 bufferViewCount       = 0;
    //    const uint32 totalViewsCount = interface->GetViewsCount();
    //    for (uint32 j = 0; j < totalViewsCount; j++)
    //    {
    //        auto view           = interface->GetViewByIndex(j);
    //        const auto viewName = view->GetName();
    //        if (viewName == VIEW_NAME)
    //        {
    //            bufferViewCount++;
    //        }
    //    }

    //    LocalString<64> tmp;
    //    LocalString<64> tmp2;
    //    auto item = list->AddItem({ tmp.Format("#%u %.*ls", i, objectName.size(), objectName.data()),
    //                                currentViewName,
    //                                tmp2.Format("%u/%u", bufferViewCount, totalViewsCount),
    //                                typeName });

    //    if (currentViewName == VIEW_NAME)
    //    {
    //        item.SetType(ListViewItem::Type::SubItemColored);
    //        item.SetColor(1, { Color::Pink, Color::Transparent });
    //    }

    //    if (bufferViewCount > 0)
    //    {
    //        item.SetType(ListViewItem::Type::SubItemColored);
    //        item.SetColor(2, { Color::Pink, Color::Transparent });
    //    }
    //}
}

// you're passing the callbacks - this needs to be statically allocated
// but you should lazy initialize it - so make it a pointer
static std::unique_ptr<GView::GenericPlugins::Unpackers::Plugin> plugin{ nullptr };

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
{
    if (command == "Unpackers") {
        if (plugin == nullptr) {
            plugin.reset(new GView::GenericPlugins::Unpackers::Plugin());
        }
        plugin->Show();
        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["command.Unpacker"] = Input::Key::Alt | Input::Key::F10;
}
}
} // namespace GView::GenericPlugins::Unpackers