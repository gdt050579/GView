#include "sqlite.hpp"

using namespace AppCUI;
using namespace AppCUI::Utils;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace GView::Utils;
using namespace GView::Type;
using namespace GView;
using namespace GView::View;

extern "C" {

PLUGIN_EXPORT bool Validate(const AppCUI::Utils::BufferView& buf, const std::string_view& extension)
{
    if (buf.GetLength() < sizeof(SQLite::SQLITE3_MAGIC)) {
        return false;
    }

    // Note that \0 is part of the magic
    if (memcmp(buf.GetData(), SQLite::SQLITE3_MAGIC, sizeof(SQLite::SQLITE3_MAGIC)) != 0) {
        return false;
    }

    return true;
}

PLUGIN_EXPORT TypeInterface* CreateInstance()
{
    return new SQLite::SQLiteFile();
}

PLUGIN_EXPORT bool PopulateWindow(Reference<GView::View::WindowInterface> win)
{
    auto sqlite = win->GetObject()->GetContentType<SQLite::SQLiteFile>();
    sqlite->Update();

    BufferViewer::Settings settings;
    win->CreateViewer(settings);

    win->AddPanel(Pointer<TabPage>(new SQLite::Panels::Information(sqlite)), true);
    win->AddPanel(Pointer<TabPage>(new SQLite::Panels::Count(sqlite)), true);

    return true;
}

PLUGIN_EXPORT void UpdateSettings(IniSection sect)
{
    sect["Description"]              = "Executable and Linkable Format (for UNIX systems)";
    sect["Extension"]                = { "db" };
    sect["Command.ShowTablesDialog"] = AppCUI::Input::Key::Shift | AppCUI::Input::Key::F10;
    sect["Priority"]                 = 1;
}
}
