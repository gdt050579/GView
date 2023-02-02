#include "BufferViewer.hpp"

namespace GView::View::BufferViewer
{
constexpr int32 BTN_ID_OK                        = 1;
constexpr int32 BTN_ID_CANCEL                    = 2;
constexpr int32 RADIOBOX_ID_COPY_ASCII           = 3;
constexpr int32 RADIOBOX_ID_COPY_UNICODE         = 4;
constexpr int32 CHECKBOX_ID_COPY_UNICODE_AS_SEEN = 5;
constexpr int32 RADIOBOX_ID_COPY_DUMP_BUFFER     = 6;
constexpr int32 RADIOBOX_ID_COPY_HEX             = 7;
constexpr int32 RADIOBOX_ID_COPY_ARRAY           = 8;
constexpr int32 RADIOBOX_ID_COPY_FILE            = 9;
constexpr int32 RADIOBOX_ID_COPY_SELECTION       = 10;

constexpr int32 GROUD_ID_COPY_TYPE      = 1;
constexpr int32 GROUD_ID_SELECTION_TYPE = 2;

CopyDialog::CopyDialog(Reference<GView::View::BufferViewer::Instance> instance)
    : Window("Copy to Clipboard", "d:c,w:20%,h:15", WindowFlags::ProcessReturn)
{
    copyAscii = Factory::RadioBox::Create(this, "Copy as &ascii text", "x:5%,y:1,w:60%,h:1", GROUD_ID_COPY_TYPE, RADIOBOX_ID_COPY_ASCII);
    copyAscii->SetChecked(true);

    copyUnicode = Factory::RadioBox::Create(
          this, "Copy as &unicode text(UCS-2)", "x:5%,y:2,w:60%,h:1", GROUD_ID_COPY_TYPE, RADIOBOX_ID_COPY_UNICODE);

    copyUnicodeAsSeen = Factory::CheckBox::Create(this, "As seen", "x:70%,y:2,w:40%,h:1", CHECKBOX_ID_COPY_UNICODE_AS_SEEN);
    copyUnicodeAsSeen->SetChecked(true);

    copyDump =
          Factory::RadioBox::Create(this, "Copy as dump &buffer", "x:5%,y:3,w:60%,h:1", GROUD_ID_COPY_TYPE, RADIOBOX_ID_COPY_DUMP_BUFFER);

    copyHex = Factory::RadioBox::Create(this, "Copy as &hex dump", "x:5%,y:4,w:60%,h:1", GROUD_ID_COPY_TYPE, RADIOBOX_ID_COPY_HEX);

    copyArray = Factory::RadioBox::Create(this, "Copy as C/C++ a&rray", "x:5%,y:5,w:60%,h:1", GROUD_ID_COPY_TYPE, RADIOBOX_ID_COPY_ARRAY);

    const bool isAtLeastOneZoneSelected = instance->GetObject()->GetContentType()->GetSelectionZonesCount() > 0;

    copyFile = Factory::RadioBox::Create(this, "Copy entire &file", "x:5%,y:7,w:60%,h:1", GROUD_ID_SELECTION_TYPE, RADIOBOX_ID_COPY_FILE);
    copyFile->SetEnabled(isAtLeastOneZoneSelected);

    copySelection =
          Factory::RadioBox::Create(this, "Copy &selection", "x:5%,y:8,w:60%,h:1", GROUD_ID_SELECTION_TYPE, RADIOBOX_ID_COPY_SELECTION);
    copySelection->SetChecked(true);
    copySelection->SetEnabled(isAtLeastOneZoneSelected);

    Factory::Button::Create(this, "&OK", "x:25%,y:100%,a:b,w:12", BTN_ID_OK)->SetFocus();
    Factory::Button::Create(this, "&Cancel", "x:75%,y:100%,a:b,w:12", BTN_ID_CANCEL);
}

bool CopyDialog::OnEvent(Reference<Control>, Event eventType, int ID)
{
    switch (eventType)
    {
    case Event::ButtonClicked:
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            if (Process())
            {
                ShowCopiedDataInformation();
            }
            Exit(Dialogs::Result::Ok);
            return true;
        }
        break;
    case Event::WindowAccept:
        if (Process())
        {
            ShowCopiedDataInformation();
        }
        Exit(Dialogs::Result::Ok);
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}

bool CopyDialog::Process()
{
    const auto cacheSize = instance->GetObject()->GetData().GetCacheSize();
    const auto zonesNo   = instance->GetObject()->GetContentType()->GetSelectionZonesCount();

    Buffer b{};
    BufferView bf{};

    if (zonesNo == 0)
    {
        bf = instance->GetObject()->GetData().GetEntireFile();
        if (bf.IsValid() == false)
        {
            LocalString<128> message;
            CHECK(message.AddFormat(
                        "File size is larger than cache size (%llu bytes vs %llu bytes)!",
                        instance->GetObject()->GetData().GetSize(),
                        cacheSize),
                  false,
                  "");
            Dialogs::MessageBox::ShowError("Error copying to clipboard", message);
            return false;
        }
    }
    else
    {
        for (uint32 i = 0; i < zonesNo; i++)
        {
            const auto z             = instance->GetObject()->GetContentType()->GetSelectionZone(i);
            const auto selectionSize = (uint32) (z.end - z.start + 1);

            if (selectionSize > cacheSize)
            {
                LocalString<128> message;
                CHECK(message.AddFormat("Selection #%u is larger than cache size (%llu bytes vs %llu bytes)!", i, selectionSize, cacheSize),
                      false,
                      "");
                Dialogs::MessageBox::ShowError("Error copying to clipboard", message);
                return false;
            }

            b.Add(instance->GetObject()->GetData().CopyToBuffer(z.start, selectionSize));
        }

        bf = b;
    }

    if (bf.IsValid() == false)
    {
        LocalString<128> message;
        message.AddFormat("File size %llu bytes, cache size %llu bytes!", instance->GetObject()->GetData().GetSize(), cacheSize);
        Dialogs::MessageBox::ShowError("Error copying to clipboard (preprocessing)!", message);
        return false;
    }

    UnicodeStringBuilder usb{};
    if (copyAscii->IsChecked())
    {
        AppCUI::Graphics::CodePage cp(AppCUI::Graphics::CodePageID::PrintableAscii);
        for (const auto c : bf)
        {
            FixSizeString<1> cc;
            CHECK(cc.AddChar((cp[c] & 0xFF)), false, "");
            CHECK(usb.Add(cc), false, "");
        }
    }
    else if (copyUnicode->IsChecked())
    {
        if (copyUnicodeAsSeen->IsChecked())
        {
        }
        else
        {
            AppCUI::Graphics::CodePage cp(AppCUI::Graphics::CodePageID::PrintableAscii);
            for (const auto c : bf)
            {
                FixSizeUnicode<1> cc;
                CHECK(cc.AddChar(cp[c]), false, "");
                CHECK(usb.Add(cc), false, "");
            }
        }
    }
    else if (copyDump->IsChecked())
    {
        String s;
        for (auto i = 0u; i < bf.GetLength(); i++)
        {
            auto c = reinterpret_cast<const char*>(bf.GetData() + i);
            if (*c != 0)
            {
                CHECK(s.Add(c, 1), false, "");
            }
        }
        CHECK(usb.Add(s), false, "");
    }
    else if (copyHex->IsChecked())
    {
        String s;
        for (const auto c : bf)
        {
            CHECK(s.AddFormat("%02X ", c), false, "");
        }
        CHECK(usb.Add(s), false, "");
    }
    else if (copyArray->IsChecked())
    {
        String s;
        CHECK(s.Add("{"), false, "");
        for (const auto c : bf)
        {
            CHECK(s.AddFormat("%02X, ", c), false, "");
        }
        s[s.Len() - 2] = '}';
        CHECK(s.Truncate(s.Len() - 1), false, "");
        CHECK(usb.Add(s), false, "");
    }

    if (AppCUI::OS::Clipboard::SetText(usb) == false)
    {
        LocalString<128> message;
        CHECK(message.AddFormat("File size %llu bytes, cache size %llu bytes!", instance->GetObject()->GetData().GetSize(), cacheSize),
              false,
              "");
        Dialogs::MessageBox::ShowError("Error copying to clipboard (postprocessing)!", message);
        return false;
    }

    return true;
}

void CopyDialog::ShowCopiedDataInformation()
{
    LocalString<512> message;

    const auto zonesNo = instance->GetObject()->GetContentType()->GetSelectionZonesCount();
    if (zonesNo == 0)
    {
        CHECKRET(message.AddFormat("Copied entire file (%llu bytes) to clipboard.", instance->GetObject()->GetData().GetSize()), "");
    }
    else
    {
        for (uint32 i = 0; i < zonesNo; i++)
        {
            const auto z = instance->GetObject()->GetContentType()->GetSelectionZone(i);
            CHECKRET(message.AddFormat("Copied zone (offset %llu, size %llu bytes) to clipboard.", z.start, (z.end - z.start + 1)), "");
        }
    }

    Dialogs::MessageBox::ShowNotification("Data copied", message);
}
} // namespace GView::View::BufferViewer
