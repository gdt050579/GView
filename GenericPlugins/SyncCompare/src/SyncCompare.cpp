#include "SyncCompare.hpp"

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

constexpr std::string_view VIEW_NAME{ "Buffer View" };

constexpr ColorPair MATCH_PARTIAL{ Color::Black, Color::Yellow };
constexpr ColorPair MATCH_COMPLETE{ Color::Black, Color::Green };

namespace GView::GenericPlugins::SyncCompare
{
using namespace AppCUI::Graphics;
using namespace GView::View;

Plugin::Plugin() : Window("SyncCompare", "d:c,w:140,h:40", WindowFlags::FixedPosition)
{
    sync = Factory::CheckBox::Create(this, "&Sync windows", "x:2%,y:1,w:30");
    sync->SetChecked(false);

    list = Factory::ListView::Create(
          this,
          "x:2%,y:3,w:96%,h:80%",
          { "n:Window,w:45%", "n:View Name,w:15%", "n:View (Buffer) Count,w:20%", "n:Type Name,w:20%" },
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
    switch (button->GetControlID())
    {
    case BTN_ID_CANCEL:
        ArrangeFilteredWindows("");
        this->Exit(Dialogs::Result::Cancel);
        break;
    case BTN_ID_OK:
        SetAllWindowsWithGivenViewName(VIEW_NAME);
        ArrangeFilteredWindows(VIEW_NAME);
        SetUpCallbackForViews(false);
        this->Exit(Dialogs::Result::Ok);
        break;
    default:
        break;
    }
}

void Plugin::Update()
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

void Plugin::SetAllWindowsWithGivenViewName(const std::string_view& viewName)
{
    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    CHECKRET(windowsNo > 1, "");

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

void Plugin::ArrangeFilteredWindows(const std::string_view& filterName)
{
    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    CHECKRET(windowsNo > 1, "");

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

bool Plugin::GetColorForByteAt(uint64 offset, const ViewData& vd, ColorPair& cp)
{
    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    CHECK(windowsNo > 1, false, "");

    std::unordered_map<unsigned char, uint32> bytes;

    CHECK(vd.viewStartOffset <= offset, false, "");
    const auto deltaOffset = offset - vd.viewStartOffset;

    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window    = desktop->GetChild(i);
        auto interface = window.ToObjectRef<GView::View::WindowInterface>();
        auto& data     = interface->GetObject()->GetData();

        ViewData viewData{}; // we assume that current view is what we want (buffer view)
        CHECK(interface->GetCurrentView()->GetViewData(viewData, GView::Utils::INVALID_OFFSET), false, "");

        uint64 thisOffset = viewData.viewStartOffset + deltaOffset;
        const auto buffer = data.Get(thisOffset, 1, true);
        if (buffer.IsValid())
        {
            ++bytes[buffer.GetData()[0]];
        }
    }

    if (bytes.size() == 1 && bytes.at(vd.byte) == windowsNo)
    {
        cp = MATCH_COMPLETE;
        return true;
    }

    if (bytes.size() < windowsNo)
    {
        if (bytes.at(vd.byte) >= 2)
        {
            cp = MATCH_PARTIAL;
            return true;
        }
    }

    return false;
}

bool Plugin::GenerateActionOnMove(Reference<Control> sender, int64 deltaStartView, const ViewData& vd)
{
    CHECK(deltaStartView != 0, false, "");

    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    CHECK(windowsNo > 1, false, "");

    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window    = desktop->GetChild(i);
        auto interface = window.ToObjectRef<GView::View::WindowInterface>();
        auto view      = interface->GetCurrentView();
        if (view.ToObjectRef<Control>() != sender)
        {
            view->AdvanceStartView(deltaStartView);
        }
    }

    return true;
}

void Plugin::SetUpCallbackForViews(bool remove)
{
    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    CHECKRET(windowsNo > 1, "");

    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window    = desktop->GetChild(i);
        auto interface = window.ToObjectRef<GView::View::WindowInterface>();
        auto view      = interface->GetCurrentView();
        view->SetBufferColorProcessorCallback(remove ? nullptr : this);
        view->OnEvent(nullptr, AppCUI::Controls::Event::Command, remove ? View::VIEW_COMMAND_DEACTIVATE_COMPARE : View::VIEW_COMMAND_ACTIVATE_COMPARE);

        if (sync->IsChecked())
        {
            view->SetOnStartViewMoveCallback(remove ? nullptr : this);
            view->OnEvent(nullptr, AppCUI::Controls::Event::Command, remove ? View::VIEW_COMMAND_DEACTIVATE_SYNC : View::VIEW_COMMAND_ACTIVATE_SYNC);
        }
    }
}

bool Plugin::ToggleSync()
{
    sync->SetChecked(!sync->IsChecked());

    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window    = desktop->GetChild(i);
        auto interface = window.ToObjectRef<GView::View::WindowInterface>();
        auto view      = interface->GetCurrentView();

        view->SetOnStartViewMoveCallback(sync->IsChecked() ? this : nullptr);
        view->OnEvent(nullptr, AppCUI::Controls::Event::Command, sync->IsChecked() ? View::VIEW_COMMAND_ACTIVATE_SYNC : View::VIEW_COMMAND_DEACTIVATE_SYNC);
    }

    return true;
}

bool Plugin::FindNextDifference()
{
    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();

    std::vector<Reference<ViewControl>> views;
    views.reserve(windowsNo);

    std::vector<DataCache*> caches;
    caches.reserve(windowsNo);

    std::vector<ViewData> viewsData;
    viewsData.reserve(windowsNo);

    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto window         = desktop->GetChild(i);
        auto interface      = window.ToObjectRef<GView::View::WindowInterface>();
        auto view           = interface->GetCurrentView();
        const auto viewName = view->GetName();
        if (viewName == VIEW_NAME)
        {
            views.push_back(view);
            caches.push_back(&interface->GetObject()->GetData());

            auto& vd = viewsData.emplace_back();
            view->GetViewData(vd, GView::Utils::INVALID_OFFSET);
            vd.viewStartOffset += 1;
        }
    }

    uint64 bufferSize{ GView::Utils::INVALID_OFFSET };
    for (const auto& data : viewsData)
    {
        if (data.viewSize > 0)
        {
            bufferSize = std::min<uint64>(bufferSize, data.viewSize);
        }
    }
    CHECK(bufferSize != GView::Utils::INVALID_OFFSET, false, "");

    bool differenceNotFound{ true };
    do
    {
        std::vector<BufferView> buffers;
        buffers.reserve(windowsNo);

        for (uint32 i = 0; i < windowsNo; i++)
        {
            auto& view             = views.at(i);
            auto& data             = viewsData.at(i);
            auto& cache            = caches.at(i);
            buffers.emplace_back() = cache->Get(data.viewStartOffset, static_cast<uint32>(bufferSize), false);
        }

        uint32 i = 0;
        std::vector<char> bytes;
        bytes.reserve(windowsNo);
        for (; i < bufferSize; i++)
        {
            for (const auto& buffer : buffers)
            {
                if (buffer.GetLength() <= i)
                {
                    differenceNotFound = false;
                    break;
                }

                bytes.push_back(buffer.GetData()[i]);
            }

            if (bytes.empty() || std::equal(bytes.begin() + 1, bytes.end(), bytes.begin()) == false)
            {
                differenceNotFound = false;
                break;
            }

            bytes.clear();
        }

        for (auto& data : viewsData)
        {
            data.viewStartOffset += i;
        }

    } while (differenceNotFound);

    for (uint32 i = 0; i < windowsNo; i++)
    {
        auto& view = views.at(i);

        view->OnEvent(nullptr, AppCUI::Controls::Event::Command, View::VIEW_COMMAND_DEACTIVATE_SYNC);

        view->GoTo(viewsData.at(i).viewStartOffset); // moves the cursor
        view->GoTo(viewsData.at(i).viewStartOffset); // moves the start view

        view->OnEvent(nullptr, AppCUI::Controls::Event::Command, sync->IsChecked() ? View::VIEW_COMMAND_ACTIVATE_SYNC : View::VIEW_COMMAND_DEACTIVATE_SYNC);
    }

    return true;
}
} // namespace GView::GenericPlugins::SyncCompare

// you're passing the callbacks - this needs to be statically allocated
// but you should lazy initialize it - so make it a pointer
static std::unique_ptr<GView::GenericPlugins::SyncCompare::Plugin> plugin{ nullptr };

extern "C"
{
    PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> currentObject)
    {
        if (command == "SyncCompare")
        {
            if (plugin == nullptr)
            {
                plugin.reset(new GView::GenericPlugins::SyncCompare::Plugin());
            }
            plugin->Show();
            return true;
        }
        if (command == "ToggleSync")
        {
            if (plugin == nullptr)
            {
                plugin.reset(new GView::GenericPlugins::SyncCompare::Plugin());
            }
            plugin->ToggleSync();
            return true;
        }
        if (command == "FindNextDifference")
        {
            if (plugin == nullptr)
            {
                plugin.reset(new GView::GenericPlugins::SyncCompare::Plugin());
            }
            plugin->FindNextDifference();
            return true;
        }
        return false;
    }

    PLUGIN_EXPORT void UpdateSettings(IniSection sect)
    {
        sect["command.SyncCompare"]        = Input::Key::Ctrl | Input::Key::Shift | Input::Key::Space;
        sect["command.ToggleSync"]         = Input::Key::Shift | Input::Key::Space;
        sect["command.FindNextDifference"] = Input::Key::Shift | Input::Key::F11;
    }
}
