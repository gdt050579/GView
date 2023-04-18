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

class SyncCompareExample : public Window, public Handlers::OnButtonPressedInterface, public View::ViewControl::BufferColorInterface
{
    Reference<ListView> list;

  public:
    SyncCompareExample() : Window("SyncCompare", "d:c,w:140,h:20", WindowFlags::FixedPosition)
    {
        list = Factory::ListView::Create(
              this,
              "x:5%,y:1,w:90%,h:80%",
              { "n:Window,w:45%", "n:View Name,w:15%", "n:View (Buffer) Count,w:20%", "n:Type Name,w:20%" },
              ListViewFlags::AllowMultipleItemsSelection);
        list->SetFocus();

        auto ok                         = Factory::Button::Create(this, "&Ok", "x:25%,y:100%,a:b,w:12", BTN_ID_OK);
        ok->Handlers()->OnButtonPressed = this;
        ok->SetFocus();
        Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL)->Handlers()->OnButtonPressed = this;

        Update();
    }

    void OnButtonPressed(Reference<Button> button) override
    {
        switch (button->GetControlID())
        {
        case BTN_ID_CANCEL:
            ArrangeFilteredWindows("");
            this->Exit(Dialogs::Result::Cancel);
            break;
        case BTN_ID_OK:
            SetAllWindowsWithGivenViewName(VIEW_NAME);
            ArrangeFilteredWindows(VIEW_NAME);
            this->Exit(Dialogs::Result::Ok);
            break;
        default:
            break;
        }
    }

    void Update()
    {
        if (list.IsValid() == false)
        {
            return;
        }
        list->DeleteAllItems();

        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window    = desktop->GetChild(i);
            auto interface = window.ToObjectRef<GView::View::WindowInterface>();

            auto currentView           = interface->GetCurrentView();
            const auto currentViewName = currentView->GetName();

            auto object           = interface->GetObject();
            const auto typeName   = object->GetContentType()->GetTypeName();
            const auto objectName = object->GetName();

            uint32 bufferViewCount       = 0;
            const uint32 totalViewsCount = interface->GetViewsCount();
            for (uint32 j = 0; j < totalViewsCount; j++)
            {
                auto view           = interface->GetViewByIndex(j);
                const auto viewName = view->GetName();
                if (viewName == VIEW_NAME)
                {
                    bufferViewCount++;
                }
            }

            LocalString<64> tmp;
            LocalString<64> tmp2;
            auto item = list->AddItem({ tmp.Format("#%u %.*ls", i, objectName.size(), objectName.data()),
                                        currentViewName,
                                        tmp2.Format("%u/%u", bufferViewCount, totalViewsCount),
                                        typeName });

            if (currentViewName == VIEW_NAME)
            {
                item.SetType(ListViewItem::Type::SubItemColored);
                item.SetColor(1, { Color::Pink, Color::Transparent });
            }

            if (bufferViewCount > 0)
            {
                item.SetType(ListViewItem::Type::SubItemColored);
                item.SetColor(2, { Color::Pink, Color::Transparent });
            }
        }
    }

    void SetAllWindowsWithGivenViewName(const std::string_view& viewName)
    {
        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window    = desktop->GetChild(i);
            auto interface = window.ToObjectRef<GView::View::WindowInterface>();

            const uint32 totalViewsCount = interface->GetViewsCount();
            for (uint32 j = 0; j < totalViewsCount; j++)
            {
                auto view           = interface->GetViewByIndex(j);
                const auto viewName = view->GetName();
                if (viewName == VIEW_NAME)
                {
                    CHECKBK(interface->SetViewByIndex(j), "");
                    break;
                }
            }
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

        int32 gridX = std::max<>(static_cast<int32>(std::sqrt(filteredWindows.size())), 1);
        int32 gridY = gridX;
        if (gridY * gridX < static_cast<int32>(filteredWindows.size()))
        {
            gridX++; // more boxes on horizontal space
        }
        if (gridY * gridX < static_cast<int32>(filteredWindows.size()))
        {
            gridY++; // more boxes on vertical space
        }

        const int32 gridWidth  = screenSize.Width / gridX;
        const int32 gridHeight = screenSize.Height / gridY;

        int32 gridRow    = 0;
        int32 gridColumn = 0;
        int32 x          = 0;
        int32 y          = 0;

        for (auto i = 0U; i < filteredWindows.size(); i++)
        {
            auto& window = filteredWindows.at(i);
            window->MoveTo(x, y);

            auto windowWidth = gridWidth;
            if (gridColumn + 1 == gridX || i == filteredWindows.size() - 1) // last column
            {
                windowWidth = std::max<>(1, static_cast<int32>(screenSize.Width) - x);
            }

            auto windowHeight = gridHeight;
            if (gridRow + 1 == gridY) // last row
            {
                windowHeight = std::max<>(1, static_cast<int32>(screenSize.Height) - y);
            }

            window->Resize(windowWidth, windowHeight);
            x += window->GetWidth();
            gridColumn++;

            if (gridColumn >= gridX)
            {
                gridColumn = 0;
                x          = 0;
                y += window->GetHeight();
                gridRow++;
            }
        }
    }

    bool GetColorForByteAt(uint64 offset, char ch, AppCUI::Graphics::ColorPair& cp) override
    {
        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();

        std::unordered_map<char, uint32> bytes;

        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window       = desktop->GetChild(i);
            auto interface    = window.ToObjectRef<GView::View::WindowInterface>();
            auto& data        = interface->GetObject()->GetData();
            const auto buffer = data.Get(offset, 1, true);
            if (buffer.IsValid())
            {
                ++bytes[buffer.GetData()[0]];
            }
        }

        if (bytes.size() == 1)
        {
            cp = ColorPair{ Color::Black, Color::Green };
            return true;
        }

        if (bytes.size() < windowsNo)
        {
            if (bytes.at(ch) >= 2)
            {
                cp = AppCUI::Graphics::ColorPair{ Color::Black, Color::Yellow };
                return true;
            }
        }

        return false;
    }

    void SetUpCallbackForViews(bool remove)
    {
        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto window                  = desktop->GetChild(i);
            auto interface               = window.ToObjectRef<GView::View::WindowInterface>();
            const uint32 totalViewsCount = interface->GetViewsCount();
            for (uint32 j = 0; j < totalViewsCount; j++)
            {
                auto view           = interface->GetViewByIndex(j);
                const auto viewName = view->GetName();
                if (viewName == VIEW_NAME) // doesn't actually matter but there's no point calling non buffer views
                {
                    view->SetBufferColorProcessorCallback(remove ? nullptr : this);
                    view->OnEvent(
                          nullptr, AppCUI::Controls::Event::Command, remove ? View::VIEW_COMMAND_DEACTIVATE_COMPARE : View::VIEW_COMMAND_ACTIVATE_COMPARE);
                }
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
            static SyncCompareExample dlg; // you're passing the callback - this needs to be statically allocated
            dlg.SetUpCallbackForViews(dlg.Show() != Dialogs::Result::Ok);
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.SyncCompare"] = Input::Key::Ctrl | Input::Key::Space;
    }
}
