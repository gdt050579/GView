#include "Internal.hpp"

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

class XORKeyWindow : public Window
{
    Reference<TextField> textField;
    std::string key;

    bool Validate()
    {
        if (!textField->GetText().Len()) {
            Dialogs::MessageBox::ShowError("Error", "Please enter a key!");
            return false;
        }

        key = textField->GetText();
        return true;
    }

  public:
    XORKeyWindow(const char* title) : Window(title, "d:c,w:60,h:10", WindowFlags::Sizeable)
    {
        Factory::Label::Create(this, "&Key", "x:1,y:1,w:14");
        textField = Factory::TextField::Create(this, "key", "x:16,y:1,w:40");

        Factory::Button::Create(this, "&Ok", "l:16,b:0,w:13", BTN_ID_OK);
        Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);
    }

    virtual bool OnEvent(Reference<Control>, Event eventType, int ID) override
    {
        switch (eventType) {
        case Event::ButtonClicked: {
            switch (ID) {
            case BTN_ID_CANCEL:
                Exit(Dialogs::Result::Cancel);
                return true;
            case BTN_ID_OK:
                if (Validate())
                    Exit(Dialogs::Result::Ok);
                return true;
            default:
                break;
            }
            break;
        }
        case Event::WindowAccept:
            Validate();
            return true;
        case Event::WindowClose:
            Exit(Dialogs::Result::Cancel);
            return true;
        default:
            return false;
        }

        return false;
    }

    inline std::string GetKey() const
    {
        return key;
    }
};

namespace GView::Decoding::XOREncoding
{

void ApplyXOR(BufferView view, const std::string& key, Buffer& output)
{
    // Iterate over each byte in the input buffer (view)
    for (uint32 i = 0; i < view.GetLength(); ++i) {
        // XOR the byte with the corresponding character from the key (repeating key if necessary)
        uint8 xorResult = static_cast<uint8>(view[i] ^ key[i % key.length()]);

        // Add the XOR result to the output buffer
        output.Add(string_view((char*) &xorResult, 1));
    }
}

// Function to decode Hex to ASCII (without XOR)
bool ApplyXORGeneric(BufferView view, Buffer& output)
{
    XORKeyWindow win("XOR Window key");
    const auto result = win.Show();
    if (result != Dialogs::Result::Ok) {
        return false;
    }

    std::string key = win.GetKey();
    if (key.empty()) {
        Dialogs::MessageBox::ShowError("Error", "Key cannot be empty!");
        return false;
    }
    ApplyXOR(view, key, output);
    return output.GetLength() > 0;
}

void Encode(BufferView view, Buffer& output)
{
    ApplyXORGeneric(view, output);
}

bool Decode(BufferView view, Buffer& output)
{
    return ApplyXORGeneric(view, output);
}

} // namespace GView::Decoding::XOREncoding