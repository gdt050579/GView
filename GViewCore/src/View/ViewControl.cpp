#include "GView.hpp"

using namespace GView::View;

int ViewControl::WriteCursorInfo(
      AppCUI::Graphics::Renderer& renderer, int x, int y, int width, std::string_view key, std::string_view value)
{
    if (this->HasFocus())
    {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Highlighted);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Normal);
        renderer.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, Cfg.Lines.Normal);
    }
    else
    {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Inactive);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Inactive);
        renderer.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, Cfg.Lines.Inactive);
    }
    return x + width + 1;
}
void ViewControl::WriteCusorInfoLine(AppCUI::Graphics::Renderer& renderer, int x, int y, std::string_view key, const ConstString& value)
{
    if (this->HasFocus())
    {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Highlighted);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Normal);
    }
    else
    {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Inactive);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Inactive);
    }
}
