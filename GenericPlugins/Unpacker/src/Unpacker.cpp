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

Plugin::Plugin(Reference<GView::Object> object) : Window("Unpacker", "d:c,w:80,h:80%", WindowFlags::FixedPosition)
{
    this->object = object;

    for (auto i = 0U; i < this->object->GetContentType()->GetSelectionZonesCount(); i++) {
        this->selectedZones.emplace_back(this->object->GetContentType()->GetSelectionZone(i));
    }

    list = Factory::ListView::Create(this, "x:1,y:0,w:60%,h:80%", { "n:Type,w:20%", "n:Description,w:80%" }, ListViewFlags::AllowMultipleItemsSelection);
    list->SetFocus();

    list->AddItem({ "Base64", "Decode base64 encoded payloads" }).SetData(ITEM_BASE64);
    list->AddItem({ "ZLib", "Decode zlib encoded payloads" }).SetData(ITEM_ZLIB);

    auto decode                         = Factory::Button::Create(this, "&Decode", "x:25%,y:100%,a:b,w:12", BTN_ID_DECODE);
    decode->Handlers()->OnButtonPressed = this;
    decode->SetFocus();

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

        GView::App::OpenBuffer(output, name, fullPath, GView::App::OpenMethod::BestMatch, "", this);
        return true;
    }

    AppCUI::Dialogs::MessageBox::ShowError("Error!", input);
    return false;
}

bool Plugin::DecodeZLib(BufferView input, uint64 start, uint64 end)
{
    // TODO:
    return true;
}

extern "C" {
PLUGIN_EXPORT bool Run(const string_view command, Reference<GView::Object> object)
{
    if (command == "Unpacker") {
        // we should validate that this is called from BufferView only for now

        // auto desktop         = AppCUI::Application::GetDesktop();
        // const auto windowsNo = desktop->GetChildrenCount();
        // for (uint32 i = 0; i < windowsNo; i++)
        // {
        //     auto window    = desktop->GetChild(i);
        //     auto interface = window.ToObjectRef<GView::View::WindowInterface>();

        //    auto currentView           = interface->GetCurrentView();
        //    const auto currentViewName = currentView->GetName();
        // }

        GView::GenericPlugins::Unpacker::Plugin plugin(object);
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
