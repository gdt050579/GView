#include "Unpackers.hpp"

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

constexpr char BASE64_ENCODE_TABLE[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                                         'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
                                         's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };

constexpr char BASE64_DECODE_TABLE[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                         -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
                                         54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                                         10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
                                         29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

Plugin::Plugin() : Window("Unpacker", "d:c,w:140,h:40", WindowFlags::FixedPosition)
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

    auto item = list->AddItem({ "Cosmin", "ViewName", "CevaFormat", "Base64" });

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

void Plugin::Base64Encode(BufferView view, Buffer& output)
{
    uint32 sequence      = 0;
    uint32 sequenceIndex = 0;

    // TODO: same as before, pass something that doesn't need extra preprocessing
    for (uint32 i = 0; i < view.GetLength(); i += 2) {
        char decoded = view[i];

        sequence |= decoded << ((3 - sequenceIndex) * 8);
        sequenceIndex++;

        if (sequenceIndex % 3 == 0) {
            // get 4 encoded components out of this one
            // 0x3f -> 0b00111111

            char buffer[] = {
                BASE64_ENCODE_TABLE[(sequence >> 26) & 0x3f],
                BASE64_ENCODE_TABLE[(sequence >> 20) & 0x3f],
                BASE64_ENCODE_TABLE[(sequence >> 14) & 0x3f],
                BASE64_ENCODE_TABLE[(sequence >> 8) & 0x3f],
            };

            output.Add(string_view(buffer, 4));

            sequence      = 0;
            sequenceIndex = 0;
        }
    }

    output.AddMultipleTimes(string_view("=", 1), (3 - sequenceIndex) % 3);
}

bool Plugin::Base64Decode(BufferView view, Buffer& output)
{
    uint32 sequence      = 0;
    uint32 sequenceIndex = 0;
    char lastEncoded     = 0;

    // TODO: pass something else as a parameter, not needing extra pasing in the function
    for (uint32 i = 0; i < view.GetLength(); i += 2) // skip the second byte in the character
    {
        char encoded = view[i];
        CHECK(encoded < sizeof(BASE64_DECODE_TABLE) / sizeof(*BASE64_DECODE_TABLE), false, "");

        if (encoded == '\r' || encoded == '\n') {
            continue;
        }

        if (lastEncoded == '=' && sequenceIndex == 0) {
            AppCUI::Dialogs::MessageBox::ShowError("Warning!", "Ignoring extra bytes after the end of buffer");
            break;
        }

        uint32 decoded;

        if (encoded == '=') {
            // padding
            decoded = 0;
        } else {
            decoded = BASE64_DECODE_TABLE[encoded];
            CHECK(decoded != -1, false, "");
        }

        sequence |= decoded << (2 + (4 - sequenceIndex) * 6);
        sequenceIndex++;

        if (sequenceIndex % 4 == 0) {
            char* buffer = (char*) &sequence;
            output.Add(string_view(buffer + 3, 1));
            output.Add(string_view(buffer + 2, 1));
            output.Add(string_view(buffer + 1, 1));

            sequence      = 0;
            sequenceIndex = 0;
        }

        lastEncoded = encoded;
    }

    return true;
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