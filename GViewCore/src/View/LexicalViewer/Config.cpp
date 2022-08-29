#include "LexicalViewer.hpp"

using namespace GView::View::LexicalViewer;
using namespace AppCUI::Input;

void Config::Update(IniSection sect)
{
    sect.UpdateValue("Key.Plugins", Key::F1, true);
    sect.UpdateValue("Key.ShowMetaData", Key::F2, true);
    sect.UpdateValue("Key.PrettyFormt", Key::F3, true);
    sect.UpdateValue("Key.ChangeSelectionType", Key::F9, true);
    sect.UpdateValue("Key.FoldAll", Key::F8, true);
    sect.UpdateValue("Key.ExpandAll", Key::Ctrl | Key::F8, true);
}
void Config::Initialize()
{
    auto ini = AppCUI::Application::GetAppSettings();
    if (ini)
    {
        auto sect                      = ini->GetSection("View.Lexical");
        this->Keys.showPlugins       = sect.GetValue("Key.Plugins").ToKey(Key::F1);
        this->Keys.showMetaData        = sect.GetValue("Key.ShowMetaData").ToKey(Key::F2);
        this->Keys.prettyFormat        = sect.GetValue("Key.PrettyFormt").ToKey(Key::F3);
        this->Keys.changeSelectionType = sect.GetValue("Key.ChangeSelectionType").ToKey(Key::F9);
        this->Keys.foldAll             = sect.GetValue("Key.FoldAll").ToKey(Key::F8);
        this->Keys.expandAll           = sect.GetValue("Key.ExpandAll").ToKey(Key::Ctrl | Key::F8);
    }
    else
    {
        this->Keys.showPlugins         = Key::F1;
        this->Keys.showMetaData        = Key::F2;
        this->Keys.prettyFormat        = Key::F3;
        this->Keys.changeSelectionType = Key::F9;
        this->Keys.foldAll             = Key::F8;
        this->Keys.expandAll           = Key::Ctrl | Key::F8;
    }

    this->Loaded = true;
}