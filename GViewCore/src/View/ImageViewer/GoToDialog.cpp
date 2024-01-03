#include "ImageViewer.hpp"

using namespace GView::View::ImageViewer;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;
constexpr int32 RB_GROUP_ID   = 123;

GoToDialog::GoToDialog(Reference<SettingsData> settings, uint32 currentImageIndex, uint64 size)
    : Window("GoTo", "d:c,w:60,h:10", WindowFlags::ProcessReturn), maxSize(size)
{
    LocalString<512> tmp;
    resultedPos    = GView::Utils::INVALID_OFFSET;
    gotoImageIndex = true;

    for (uint32 idx = 0; idx < settings->imgList.size(); idx++)
    {
        tmp.AddFormat("%d. %u bytes,", idx + 1, static_cast<uint32>(settings->imgList[idx].end - settings->imgList[idx].start));
    }

    rbImageIndex = Factory::RadioBox::Create(this, "Select &image", "x:1,y:1,w:18", RB_GROUP_ID);
    cbImageList  = Factory::ComboBox::Create(this, "x:20,y:1,w:36", tmp.GetText());

    rbFileOffset = Factory::RadioBox::Create(this, tmp.Format("&File offset (0..%llu)", size), "x:1,y:3,w:38", RB_GROUP_ID);
    txFileOffset = Factory::TextField::Create(this, "0", "x:40,y:3,w:16");

    Factory::Button::Create(this, "&OK", "l:16,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:31,b:0,w:13", BTN_ID_CANCEL);

    cbImageList->SetCurentItemIndex(currentImageIndex);
    rbImageIndex->SetChecked(true);
    UpdateEnableStatus();
}

void GoToDialog::UpdateEnableStatus()
{
    cbImageList->SetEnabled(rbImageIndex->IsChecked());
    txFileOffset->SetEnabled(rbFileOffset->IsChecked());
    if (cbImageList->IsEnabled())
        cbImageList->SetFocus();
    if (txFileOffset->IsEnabled())
        txFileOffset->SetFocus();
}
void GoToDialog::Validate()
{
    LocalString<128> tmp;
    LocalString<256> error;
    NumberParseFlags flags = NumberParseFlags::BaseAuto;

    if (rbFileOffset->IsChecked())
    {
        if (tmp.Set(txFileOffset->GetText()) == false)
        {
            Dialogs::MessageBox::ShowError("Error", "Fail to get the value of the numerical field !");
            txFileOffset->SetFocus();
            return;
        }
        auto ofs = Number::ToUInt64(tmp, flags);
        if (!ofs.has_value())
        {
            Dialogs::MessageBox::ShowError("Error", error.Format("Value `%s` is not a valid number !", tmp.GetText()));
            txFileOffset->SetFocus();
            return;
        }

        // all good
        auto newPos = ofs.value();
        if (newPos >= maxSize)
        {
            Dialogs::MessageBox::ShowError("Error", error.Format("Offset `%llu` is bigger than the offset size: `%llu`", newPos, maxSize));
            txFileOffset->SetFocus();
            return;
        }
        gotoImageIndex = false;
        resultedPos    = newPos;
    }
    else
    {
        gotoImageIndex = true;
        resultedPos    = cbImageList->GetCurrentItemIndex();
    }
    Exit(Dialogs::Result::Ok);
}

bool GoToDialog::OnEvent(Reference<Control>, Event eventType, int ID)
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
            Validate();
            return true;
        }
        break;
    case Event::CheckedStatusChanged:
        UpdateEnableStatus();
        return true;
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
