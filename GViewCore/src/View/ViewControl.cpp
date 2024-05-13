#include "GView.hpp"

using namespace GView::View;

int ViewControl::WriteCursorInfo(AppCUI::Graphics::Renderer& renderer, int x, int y, int width, std::string_view key, std::string_view value)
{
    if (this->HasFocus()) {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Highlighted);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Normal);
        renderer.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, Cfg.Lines.Normal);
    } else {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Inactive);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Inactive);
        renderer.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, Cfg.Lines.Inactive);
    }
    return x + width + 1;
}

int ViewControl::WriteCursorInfo(AppCUI::Graphics::Renderer& renderer, int x, int y, int width, std::string_view key, std::u16string_view value)
{
    if (this->HasFocus()) {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Highlighted);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Normal);
        renderer.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, Cfg.Lines.Normal);
    } else {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Inactive);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Inactive);
        renderer.WriteSpecialCharacter(x + width, y, SpecialChars::BoxVerticalSingleLine, Cfg.Lines.Inactive);
    }
    return x + width + 1;
}

void ViewControl::WriteCusorInfoLine(AppCUI::Graphics::Renderer& renderer, int x, int y, std::string_view key, const ConstString& value)
{
    if (this->HasFocus()) {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Highlighted);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Normal);
    } else {
        renderer.WriteSingleLineText(x, y, key, Cfg.Text.Inactive);
        renderer.WriteSingleLineText(x + (int) key.size(), y, value, Cfg.Text.Inactive);
    }
}

bool ViewControl::SetBufferColorProcessorCallback(Reference<BufferColorInterface>)
{
    return false;
}

bool ViewControl::SetOnStartViewMoveCallback(Reference<OnStartViewMoveInterface>)
{
    return false;
}

bool ViewControl::GetViewData(ViewData&, uint64)
{
    return false;
}

bool ViewControl::AdvanceStartView(int64)
{
    return false;
}

bool ViewControl::SetObjectsHighlightingZonesList(GView::Utils::ZonesList& zones)
{
    return false;
}

GView::Utils::ZonesList& ViewControl::GetObjectsHighlightingZonesList()
{
    static GView::Utils::ZonesList zl{};
    return zl;
}

bool ViewControl::OnKeyEvent(AppCUI::Input::Key keyCode, char16 charCode)
{
    if (this->HasFocus() == false) {
        return false;
    }

    auto desktop         = AppCUI::Application::GetDesktop();
    const auto windowsNo = desktop->GetChildrenCount();
    if (windowsNo <= 1) {
        return false;
    }

    switch (keyCode) {
    case AppCUI::Input::Key::Tab:
        for (uint32 i = 0; i < windowsNo; i++) {
            auto window = desktop->GetChild(i);
            if (window->HasFocus()) {
                window = desktop->GetChild(i == windowsNo - 1 ? 0 : i + 1);
                window->SetFocus();
                return true;
            }
        }
        return false;
    case AppCUI::Input::Key::Tab | AppCUI::Input::Key::Shift:
        for (uint32 i = 0; i < windowsNo; i++) {
            auto window = desktop->GetChild(i);
            if (window->HasFocus()) {
                window = desktop->GetChild(i == 0 ? windowsNo - 1 : i - 1);
                window->SetFocus();
                return true;
            }
        }
        return false;
    default:
        return false;
    }
}
