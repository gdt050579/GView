#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK      = 1;
constexpr int32 BTN_ID_CANCEL  = 2;
constexpr int32 BTN_ID_BROWSER = 3;

std::string_view newLineFormats[] = { "\r\n", "\n", "\r", "\n\r" };

SaveAsDialog::SaveAsDialog(Reference<Object> obj) : Window("Save As", "d:c,w:70,h:17", WindowFlags::ProcessReturn)
{
    Factory::Label::Create(this, "File &path", "x:1,y:1,w:10");
    txPath = Factory::TextField::Create(this, "", "l:1,t:2,r:15,h:2");
    txPath->SetHotKey('P');
    Factory::Button::Create(this, "&Browse", "x:67,y:2,a:rt,w:13", BTN_ID_BROWSER);

    auto currentPath = obj->GetPath();
    auto indexExt    = currentPath.find_last_of('.');
    if (currentPath.empty() == false)
    {
        LocalUnicodeStringBuilder<256> temp;
        if (indexExt != u16string_view::npos)
        {
            // extension is present
            temp.Set(currentPath.substr(0, indexExt));
        }
        else
        {
            temp.Set(currentPath);
        }
        temp.Add(".formated");
        if (indexExt != u16string_view::npos)
        {
            temp.Add(currentPath.substr(indexExt));
        }
        else
        {
            temp.Add(".output");
        }
        txPath->SetText(temp);
    }

    Factory::Label::Create(this, "&Encoding", "x:1,y:5,w:10");
    comboEncoding = Factory::ComboBox::Create(this, "l:12,t:5,r:1", "UTF-8 (with BOM),UTF-8 (without BOM),ASCII-Z,UTF-16 (LE),UTF-16 (BE)");
    comboEncoding->SetCurentItemIndex(0);
    comboEncoding->SetHotKey('E');

    Factory::Label::Create(this, "&New line", "x:1,y:7,w:10");
    comboNewLine = Factory::ComboBox::Create(this, "l:12,t:7,r:1", "CRLF (Windows),LF (Unix),CR,LFCR");
    comboNewLine->SetCurentItemIndex(0);
    comboNewLine->SetHotKey('N');

    cbOpenInNewWindow     = Factory::CheckBox::Create(this, "Open the file in a new &window after saving it", "l:1,t:9,r:1");
    cbBackupOriginalFile  = Factory::CheckBox::Create(this, "Backup of the original file (when overwriting content)", "l:1,t:10,r:1");
    cIgnoreMetadataOnSave = Factory::CheckBox::Create(this, "Ignore metadata on saving file", "l:1,t:11,r:1");

    Factory::Button::Create(this, "&OK", "l:21,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:36,b:0,w:13", BTN_ID_CANCEL);
    txPath->SetFocus();
    cbBackupOriginalFile->SetChecked(true);
}
std::string_view SaveAsDialog::GetNewLineFormat()
{
    return newLineFormats[comboNewLine->GetCurrentItemIndex()];
}
CharacterEncoding::Encoding SaveAsDialog::GetTextEncoding()
{
    switch (comboEncoding->GetCurrentItemIndex())
    {
    case 0:
    case 1:
        return CharacterEncoding::Encoding::UTF8;
    case 2:
        return CharacterEncoding::Encoding::Ascii;
    case 3:
        return CharacterEncoding::Encoding::Unicode16LE;
    case 4:
        return CharacterEncoding::Encoding::Unicode16BE;
    default:
        return CharacterEncoding::Encoding::Binary;
    }
}
bool SaveAsDialog::HasBOM()
{
    const auto idx = comboEncoding->GetCurrentItemIndex();
    return (idx != 1) && (idx != 2);
}
void SaveAsDialog::BrowseForFile()
{
    auto& path                                        = txPath->GetText();
    auto pathBuffer                                   = path.GetBuffer();
    uint32 index                                      = 0xFFFFFFFF;
    std::optional<std::filesystem::path> selectedPath = std::nullopt;
    for (auto i = 0U; i < path.Len(); i++)
        if ((pathBuffer[i].Code == '\\') || (pathBuffer[i].Code == '/'))
            index = i;
    if (index == 0xFFFFFFFF)
    {
        // current folder
        selectedPath = Dialogs::FileDialog::ShowSaveFileWindow("", "", ".");
    }
    else
    {
        LocalUnicodeStringBuilder<256> temp(path.SubString(0, index));
        selectedPath = Dialogs::FileDialog::ShowSaveFileWindow("", "", temp);
    }
    if (selectedPath.has_value())
    {
        txPath->SetText(selectedPath.value().u16string());
        txPath->SetFocus();
    }
}
void SaveAsDialog::Validate()
{
    if (txPath->GetText().Len() == 0)
    {
        AppCUI::Dialogs::MessageBox::ShowError("Error", "You need to specify a file name !");
        txPath->SetFocus();
        return;
    }
    Exit(Dialogs::Result::Ok);
}
bool SaveAsDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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
        case BTN_ID_BROWSER:
            BrowseForFile();
            return true;
        }
        break;
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::View::LexicalViewer