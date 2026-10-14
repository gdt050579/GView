#include "TextViewer.hpp"

using namespace GView::View::TextViewer;
using namespace AppCUI::Input;

SettingsData::SettingsData()
{
    this->tabSize              = 4;
    this->wrapMethod           = WrapMethod::Bullets;
    this->highlightCurrentLine = true;
    this->showTabCharacter     = false;
    this->encoding             = CharacterEncoding::Encoding::Binary;
}
Settings::Settings()
{
    this->data = new SettingsData();
}
void Settings::SetWrapMethod(WrapMethod method)
{
    reinterpret_cast<SettingsData*>(this->data)->wrapMethod = method;
}
void Settings::SetTabSize(uint32 tabSize)
{
    tabSize                                              = std::max<>(1U, tabSize); // clamp to [1, 32]
    tabSize                                              = std::min<>(32U, tabSize);
    reinterpret_cast<SettingsData*>(this->data)->tabSize = tabSize;
}
void Settings::ShowTabCharacter(bool show)
{
    reinterpret_cast<SettingsData*>(this->data)->showTabCharacter = show;
}
void Settings::HightlightCurrentLine(bool highlight)
{
    reinterpret_cast<SettingsData*>(this->data)->highlightCurrentLine = highlight;
}

bool Settings::SetName(std::string_view name)
{
    return ((SettingsData*) (this->data))->name.Set(name);
}
