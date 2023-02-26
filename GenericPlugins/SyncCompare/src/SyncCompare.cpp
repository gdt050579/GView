#include "SyncCompare.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;
using namespace GView::View;

constexpr int BTN_ID_OK     = 1;
constexpr int BTN_ID_CANCEL = 2;

constexpr std::string_view VIEW_NAME{ "Buffer View" };

class SyncCompareExample : public Window, public Handlers::OnButtonPressedInterface
{
  public:
    SyncCompareExample() : Window("SyncCompare", "d:c,w:70,h:20", WindowFlags::Sizeable | WindowFlags::Maximized)
    {
        auto list = Factory::ListView::Create(
              this, "x:5,y:1,w:85%,h:80%", { "n:Window,w:30%", "n:View Name,w:30%", "n:Type Name,w:50%" }, ListViewFlags::AllowMultipleItemsSelection);
        list->SetFocus();

        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window    = desktop->GetChild(i);
            auto interface = window.ToObjectRef<GView::View::WindowInterface>();

            auto currentView    = interface->GetCurrentView();
            const auto viewName = currentView->GetName();

            auto object         = interface->GetObject();
            const auto typeName = object->GetContentType()->GetTypeName();

            LocalString<64> tmp;
            auto item = list->AddItem({ tmp.Format("#%i", i), viewName, typeName });

            if (viewName == VIEW_NAME)
            {
                item.SetType(ListViewItem::Type::SubItemColored);
                item.SetColor(1, { Color::Pink, Color::Transparent });
            }
        }

        auto ok                         = Factory::Button::Create(this, "&Ok", "x:25%,y:100%,a:b,w:12", BTN_ID_OK);
        ok->Handlers()->OnButtonPressed = this;
        ok->SetFocus();
        Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL)->Handlers()->OnButtonPressed = this;
    }

    void OnButtonPressed(Reference<Button> button) override
    {
        switch (button->GetControlID())
        {
        case BTN_ID_CANCEL:
            ArrangeFilteredWindows("");
            this->Exit();
            break;
        case BTN_ID_OK:
            ArrangeFilteredWindows(VIEW_NAME);
            this->Exit();
            break;
        default:
            break;
        }
    }

    void ArrangeFilteredWindows(const std::string_view& filterName)
    {
        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();

        std::vector<Reference<Control>> filteredWindows{};
        filteredWindows.reserve(windowsNo);

        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window    = desktop->GetChild(i);
            auto interface = window.ToObjectRef<GView::View::WindowInterface>();

            auto currentView    = interface->GetCurrentView();
            const auto viewName = currentView->GetName();

            if (filterName == "") // re-enable
            {
                window->SetEnabled(true);
                filteredWindows.emplace_back(window);
            }
            else if (filterName == viewName) // filter
            {
                filteredWindows.emplace_back(window);
            }
            else // disable
            {
                window->MoveTo(0, 0);
                window->Resize(0, 0);
                window->SetEnabled(false);
            }
        }

        CHECKRET(filteredWindows.size() > 0, "");

        const auto screenSize = desktop->GetClientSize();
        int32 tempSz          = (int32) sqrt(filteredWindows.size());
        tempSz                = std::max<>(tempSz, 1);
        int32 gridX           = tempSz;
        int32 gridY           = tempSz;
        if ((gridY * gridX) < (int32) filteredWindows.size())
            gridX++; // more boxes on horizontal space
        if ((gridY * gridX) < (int32) filteredWindows.size())
            gridY++; // more boxes on vertical space
        int32 gridWidth  = screenSize.Width / gridX;
        int32 gridHeight = screenSize.Height / gridY;
        int32 gridRow    = 0;
        int32 gridColumn = 0;
        int32 x          = 0;
        int32 y          = 0;
        tempSz           = x;

        for (auto i = 0U; i < filteredWindows.size(); i++)
        {
            auto& window = filteredWindows.at(i);

            window->MoveTo(x, y);
            auto gridWinWidth  = gridWidth;
            auto gridWinHeight = gridHeight;
            if (((gridColumn + 1) == gridX) || (i == filteredWindows.size() - 1)) // last column
                gridWinWidth = std::max<>(1, ((int32) screenSize.Width) - x);
            if ((gridRow + 1) == gridY) // last row
                gridWinHeight = std::max<>(1, ((int) screenSize.Height) - y);

            window->Resize(gridWinWidth, gridWinHeight);
            x += window->GetWidth();
            gridColumn++;

            if (gridColumn >= gridX)
            {
                gridColumn = 0;
                x          = tempSz; // restore original "X" value
                y += window->GetHeight();
                gridRow++;
            }
        }
    }
};

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
    {
        if (command == "SyncCompare")
        {
            SyncCompareExample dlg;
            dlg.Show();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.SyncCompare"] = Input::Key::Ctrl | Input::Key::Space;
    }
}
