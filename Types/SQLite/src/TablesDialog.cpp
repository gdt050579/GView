#include "sqlite.hpp"

using namespace GView::Type::SQLite;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK                      = 1;
constexpr int32 BTN_ID_CANCEL                  = 2;
constexpr int32 DESCRIPTION_HEIGHT_TEXT_FORMAT = 3;

PluginDialogs::TablesDialog::TablesDialog(Reference<GView::Type::SQLite::SQLiteFile> _sqlite)
    : Window("Tables", "d:c,w:60%,h:24", WindowFlags::ProcessReturn | WindowFlags::Sizeable)
{
    sqlite = _sqlite;

    statementDescription = Factory::CanvasViewer::Create(
          this, "d:t,h:6", this->GetWidth(), DESCRIPTION_HEIGHT_TEXT_FORMAT, Controls::ViewerFlags::Border | Controls::ViewerFlags::HideScrollBar);
    statementDescription->SetText("Query");
    textArea = Factory::TextArea::Create(statementDescription, "", "l:1,r:1,t:1,b:1");
    Factory::Button::Create(this, "&OK", "x:25%,y:9,a:b,w:12", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "x:75%,y:9,a:b,w:12", BTN_ID_CANCEL);

    tables                            = Factory::ListView::Create(this, "x:0,y:10,w:100%,h:10", { "n:Name,w:20", "n:Original SQL,w:100" }, ListViewFlags::None);
    tables->Handlers()->OnItemPressed = this;

    Update();
}

bool PluginDialogs::TablesDialog::OnEvent(Reference<Control>, Event eventType, int ID)
{
    if (eventType == Event::ButtonClicked) {
        switch (ID) {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            CHECK(ProcessInput(), false, "");
            Exit(Dialogs::Result::Ok);
            return true;
        }
    }

    switch (eventType) {
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}

void PluginDialogs::TablesDialog::OnFocus()
{
    if (this->textArea.IsValid()) {
        this->textArea->SetFocus();
    }
    return Window::OnFocus();
}

bool PluginDialogs::TablesDialog::OnKeyEvent(Input::Key keyCode, char16 UnicodeChar)
{
    if (keyCode == (Input::Key::Alt | Input::Key::I)) {
        textArea->SetFocus();
        return true;
    }
    return Window::OnKeyEvent(keyCode, UnicodeChar);
}

bool PluginDialogs::TablesDialog::ProcessInput()
{
    auto content = (std::string) textArea->GetText();
    if (content.size() == 0) {
        Dialogs::MessageBox::ShowError("Error!", "Missing input!");
        return false;
    }

    sqlite->GetStatementResult(content, false);
    return true;
}

void PluginDialogs::TablesDialog::Update()
{
    UpdateTablesInformation();
}

void PluginDialogs::TablesDialog::UpdateTablesInformation()
{
    tables->DeleteAllItems();

    auto data = sqlite->db.GetTableInfo();
    for (auto& table : data) {
        tables->AddItem({ table.first, table.second });
    }
}

void PluginDialogs::TablesDialog::OnListViewItemPressed(Reference<Controls::ListView> lv, Controls::ListViewItem item)
{
    sqlite->GetStatementResult((std::string) item.GetText(0), true);
    Exit(Dialogs::Result::Ok);
}
