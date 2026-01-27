#include "msi.hpp"

using namespace GView::Type::MSI;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;

namespace GView::Type::MSI::Dialogs
{
TableViewer::TableViewer(Reference<MSIFile> msi, const std::string& tableName) 
        : Window(tableName, "d:c,w:90%,h:80%", WindowFlags::Sizeable)
{
    // 1. Create the List View
    list = Factory::ListView::Create(this, "x:0,y:0,w:100%,h:100%", {}, ListViewFlags::AllowMultipleItemsSelection);

    // 2. Setup Columns from Definition
    auto def = msi->GetTableDefinition(tableName);
    if (def) {
        for (const auto& col : def->columns) {
            // Format: "n:ColName,a:l,w:16" (Name, Align Left, Width 16)
            AppCUI::Utils::LocalString<128> colFormat;
            colFormat.Format("n:%s,a:l,w:20", col.name.c_str());
            list->AddColumn(colFormat.GetText());
        }
    }

    // 3. Populate Data
    auto rows = msi->ReadTableData(tableName);
    for (const auto& row : rows) {
        if (row.empty()) continue;

        // Add first column item
        auto item = list->AddItem(row[0]);
            
        // Set subsequent columns
        for (size_t i = 1; i < row.size(); i++) {
            item.SetText((uint32)i, row[i]);
        }
    }

    // Focus the list so the user can scroll immediately
    list->SetFocus();
}

bool TableViewer::OnEvent(Reference<Control>, Event eventType, int ID)
{
    // Close window on Escape
    if (eventType == Event::WindowClose) {
        Exit(AppCUI::Dialogs::Result(0));
        return true;
    }
    return false;
}

bool TableViewer::OnKeyEvent(AppCUI::Input::Key keyCode, char16 UnicodeChar)
{
    if (keyCode == Key::Escape) {
        Exit(AppCUI::Dialogs::Result(0));
        return true;
    }
    return Window::OnKeyEvent(keyCode, UnicodeChar);
}
} // namespace GView::Type::MSI::Dialogs
