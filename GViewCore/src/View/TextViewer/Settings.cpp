#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    this->tabSize              = 4;
    this->wordWrap             = true;
    this->highlightCurrentLine = true;
    this->showTabCharacter     = false;
    this->encoding             = CharacterEncoding::Encoding::Binary;
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetLoadImageCallback(Reference<LoadImageInterface> cbk)
{
}
void Settings::AddImage(uint64 offset, uint64 size)
{
}
