#include "Unpacker.hpp"

#include <unordered_map>
#include <vector>

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView;

constexpr int BTN_ID_DECODE = 1;
constexpr int BTN_ID_CANCEL = 2;

constexpr uint64 ITEM_INVALID = 0xFFFFFFFF;
constexpr uint64 ITEM_BASE64  = 1;
constexpr uint64 ITEM_ZLIB    = 2;

namespace GView::GenericPlugins::Unpacker
{
using namespace AppCUI::Graphics;
using namespace GView::View;

Plugin::Plugin(Reference<GView::Object> object, Reference<Window> parent) : Window("Unpacker", "d:c,w:60,h:80%", WindowFlags::FixedPosition)
{
    this->object = object;
    this->parent = parent;

    for (auto i = 0U; i < this->object->GetContentType()->GetSelectionZonesCount(); i++) {
        this->selectedZones.emplace_back(this->object->GetContentType()->GetSelectionZone(i));
    }

    description = Factory::Label::Create(this, "", "x:55%,y:1,w:45%,h:30%");

    list = Factory::ListView::Create(this, "x:1,y:0,w:50%,h:90%", { "n:Type,w:100%" }, ListViewFlags::AllowMultipleItemsSelection);

    list->AddItem({ "Base64" }).SetData(ITEM_BASE64);
    list->AddItem({ "ZLib" }).SetData(ITEM_ZLIB);

    list->SetCurrentItem(list->GetItem(0));
    list->RaiseEvent(Event::ListViewCurrentItemChanged);
    list->SetFocus();

    auto decode                         = Factory::Button::Create(this, "&Decode", "x:25%,y:100%,a:b,w:12", BTN_ID_DECODE);
    decode->Handlers()->OnButtonPressed = this;

    Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL)->Handlers()->OnButtonPressed = this;
}

void Plugin::OnButtonPressed(Reference<Button> button)
{
    Buffer b;
    BufferView bv;
    uint64 start = 0;
    uint64 end   = this->object->GetData().GetSize();

    switch (button->GetControlID()) {
    case BTN_ID_CANCEL:
        this->Exit(Dialogs::Result::Cancel);
        break;
    case BTN_ID_DECODE: {
        auto id = list->GetCurrentItem().GetData(ITEM_INVALID);
        switch (id) {
        case ITEM_BASE64: {
            SetAreaToDecode(b, bv, start, end);
            DecodeBase64(bv, start, end);
        } break;
        case ITEM_ZLIB:
            SetAreaToDecode(b, bv, start, end);
            DecodeZLib(bv, start, end);
            break;
        case ITEM_INVALID:
        default:
            break;
        }
    }
        this->Exit(Dialogs::Result::Ok);
        break;
    default:
        break;
    }
}

bool Plugin::OnEvent(Reference<Control> control, Event eventType, int32 ID)
{
    if (Window::OnEvent(control, eventType, ID)) {
        return true;
    }

    switch (eventType) {
    case AppCUI::Controls::Event::ListViewCurrentItemChanged: {
        CHECK(description.IsValid(), false ,"");
        CHECK(list.IsValid(), false ,"");

        auto item = this->list->GetCurrentItem();
        auto id   = item.GetData(ITEM_INVALID);
        CHECK(id != ITEM_INVALID, false, "");

        switch (id) {
        case ITEM_BASE64:
            description->SetText("Base64 encoded payloads");
            break;
        case ITEM_ZLIB:
            description->SetText("Zlib encoded payloads");
            break;
        default:
            break;
        }

        return true;
    } break;
    default:
        break;
    }

    return false;
}

bool Plugin::SetAreaToDecode(Buffer& b, BufferView& bv, uint64& start, uint64& end)
{
    if (this->selectedZones.empty()) {
        bv = this->object->GetData().GetEntireFile();
        if (!bv.IsValid()) {
            b  = this->object->GetData().CopyEntireFile();
            bv = b;
        }
    } else {
        start = selectedZones[0].start;
        end   = selectedZones[selectedZones.size() - 1].end;
        for (auto& sz : selectedZones) {
            const auto size = sz.end - sz.start + 1;
            b.Add(this->object->GetData().Get(sz.start, size, true));
        }
        bv = b;
    }

    CHECK(b.IsValid(), false, "Invalid buffer!");
    CHECK(bv.IsValid(), false, "Invalid buffer view!");

    return true;
}

bool Plugin::DecodeBase64(BufferView input, uint64 start, uint64 end)
{
    bool warning;
    String message;
    Buffer output;
    if (GView::Unpack::Base64::Decode(input, output, warning, message)) {
        if (warning) {
            AppCUI::Dialogs::MessageBox::ShowError("Warning!", message);
        }

        LocalString<128> name;
        name.Format("Buffer_base64_%llx_%llx", start, end);

        LocalUnicodeStringBuilder<2048> fullPath;
        fullPath.Add(this->object->GetPath());
        fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
        fullPath.Add(name);

        GView::App::OpenBuffer(output, name, fullPath, GView::App::OpenMethod::BestMatch, "", this->parent);
        return true;
    }

    AppCUI::Dialogs::MessageBox::ShowError("Error!", "Failed to decode base64!");

    return false;
}

bool Plugin::DecodeZLib(BufferView input, uint64 start, uint64 end)
{
    struct Data {
        Buffer buffer;
        String name;
        String path;
    };

    std::vector<Data> outputs;
    String message;
    uint64 sizeConsumed = 0;

    do {
        Buffer output;
        if (GView::ZLIB::DecompressStream(input, output, message, sizeConsumed)) {
            LocalString<128> name;
            name.Format("Buffer_zlib_%llx_%llx", start, start + sizeConsumed);

            start += sizeConsumed;

            LocalUnicodeStringBuilder<2048> fullPath;
            fullPath.Add(this->object->GetPath());
            fullPath.AddChar((char16_t) std::filesystem::path::preferred_separator);
            fullPath.Add(name);

            std::string path;
            fullPath.ToString(path);

            Data data{ output, name, String{ path } };
            outputs.emplace_back(data);
        } else {
            LocalString<256> title;
            title.Format("Error for area %llx -> %llx!", start, end);
            AppCUI::Dialogs::MessageBox::ShowError(title, message);
            break;
        }

        input = { input.GetData() + sizeConsumed, input.GetLength() - sizeConsumed };
    } while (sizeConsumed < input.GetLength() && sizeConsumed > 0);

    for (const auto& output : outputs) {
        GView::App::OpenBuffer(output.buffer, output.name, output.path, GView::App::OpenMethod::BestMatch, "", this->parent);
    }

    return !outputs.empty();
}

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Unpacker") {
        // we should validate that this is called from Buffer View only for now
        // TODO: maybe centralize views' names
        Reference<Window> parent;

        auto desktop         = AppCUI::Application::GetDesktop();
        const auto windowsNo = desktop->GetChildrenCount();
        for (uint32 i = 0; i < windowsNo; i++) {
            auto window = desktop->GetChild(i);
            if (window->HasFocus()) {
                auto interface             = window.ToObjectRef<GView::View::WindowInterface>();
                auto currentView           = interface->GetCurrentView();
                const auto currentViewName = currentView->GetName();
                if (currentViewName != "Buffer View") {
                    AppCUI::Dialogs::MessageBox::ShowError("Error!", "Unpacker plugin can only be called from buffer views!");
                    return true; // the command did not fail -> it does not apply
                }
                parent = window.ToObjectRef<Window>();
                break;
            }
        }

        if (!parent.IsValid()) {
            AppCUI::Dialogs::MessageBox::ShowError("Error!", "Parent window for Unpacker not found!");
            return false;
        }

        GView::GenericPlugins::Unpacker::Plugin plugin(object, parent);
        plugin.Show();

        return true;
    }
    return false;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Command.Unpacker"] = Input::Key::Alt | Input::Key::F10;
}
}
} // namespace GView::GenericPlugins::Unpacker
