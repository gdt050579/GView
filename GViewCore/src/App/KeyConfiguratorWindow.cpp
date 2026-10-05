#include "Internal.hpp"

#include <algorithm>

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Input;
using namespace AppCUI::Utils;

// "Keyboard shortcuts" window: the central place where every GView key is listed and can be changed.
//  - top list   : the type plugin (its commands and panels), the generic plugins and the GView keys
//  - bottom list: the current viewer (or every viewer in the "All keys" scope)
// All edits are done on a copy of the key bindings registry and applied only when the user saves them.
namespace
{
constexpr int BTN_EDIT        = 1;
constexpr int BTN_UNASSIGN    = 2;
constexpr int BTN_RESET       = 3;
constexpr int BTN_RESET_ALL   = 4;
constexpr int BTN_SAVE        = 5;
constexpr int BTN_CLOSE       = 6;
constexpr int CMD_EDIT        = 100;
constexpr int CMD_UNASSIGN    = 101;
constexpr int CMD_RESET       = 102;
constexpr int CMD_SAVE        = 103;
constexpr uint64 NO_ROW       = 0xFFFFFFFFFFFFFFFFULL;
constexpr uint32 LIST_TOP     = 0;
constexpr uint32 LIST_BOTTOM  = 1;
constexpr std::string_view SHOW_KEYS_CAPTION = "ShowKeys";

bool IsShowKeysBinding(const Keys::Row& r)
{
    return (r.section == Keys::SECTION_GVIEW) && (r.caption == SHOW_KEYS_CAPTION);
}

// display text of a key (with the -previewed- modifier profile applied)
void KeyToDisplay(const Keys::Row& r, const ModifierMap& map, String& text)
{
    if (r.displayOnly)
    {
        text.Set(r.keyText);
        return;
    }
    if (r.key == Key::None)
    {
        text.Set("(unassigned)");
        return;
    }
    if (!KeyUtils::ToDisplayString(r.key, map, text))
        text.Set("?");
}

//============================================================================================ KeyEditDialog ===
class KeyEditDialog : public Window
{
    const std::vector<Keys::Row>& rows;
    uint32 rowIndex;
    const ModifierMap& map;
    Reference<KeySelector> selector;
    Reference<CheckBox> cbCtrl, cbAlt, cbShift;
    Reference<ComboBox> cbKey;
    Reference<Label> lbConflict;
    Key result;
    bool updating;

    static constexpr int ID_CTRL     = 1;
    static constexpr int ID_ALT      = 2;
    static constexpr int ID_SHIFT    = 3;
    static constexpr int ID_OK       = 5;
    static constexpr int ID_UNASSIGN = 6;
    static constexpr int ID_DEFAULT  = 7;
    static constexpr int ID_CANCEL   = 8;

    Key ComposeKey()
    {
        const auto keyIndex = static_cast<uint32>(cbKey->GetCurrentItemUserData(0));
        if (keyIndex == 0)
            return Key::None;
        auto key = static_cast<Key>(keyIndex);
        if (cbCtrl->IsChecked())
            key |= Key::Ctrl;
        if (cbAlt->IsChecked())
            key |= Key::Alt;
        if (cbShift->IsChecked())
            key |= Key::Shift;
        return key;
    }
    void SetKey(Key key)
    {
        updating = true;
        result   = key;
        selector->SetSelectedKey(key);
        cbCtrl->SetChecked((key & Key::Ctrl) != Key::None);
        cbAlt->SetChecked((key & Key::Alt) != Key::None);
        cbShift->SetChecked((key & Key::Shift) != Key::None);
        const uint32 code = static_cast<uint32>(key) & KeyUtils::KEY_CODE_MASK;
        // combo item index == key code (item 0 is "(none)")
        cbKey->SetCurentItemIndex(code < static_cast<uint32>(Key::Count) ? code : 0);
        updating = false;
        UpdateInfo();
    }
    void UpdateInfo()
    {
        LocalString<256> text;
        const auto& row = rows[rowIndex];
        if (result == Key::None)
        {
            lbConflict->SetText("The command will have no key (still available from the command bar / menus)");
            return;
        }
        if (row.HasFlag(GView::KeyboardControlFlags::ShiftExtendsSelection) && ((result & Key::Shift) != Key::None))
        {
            lbConflict->SetText("Shift is reserved: holding Shift with this key extends the selection");
            return;
        }
        // conflicts are computed on a copy of the rows, with the candidate key
        std::vector<Keys::Row> copy = rows;
        copy[rowIndex].key          = result;
        Keys::ComputeConflicts(copy);
        const auto other = copy[rowIndex].conflictWith;
        if (other >= 0)
        {
            text.SetFormat("Conflict: also used by %s > %s", copy[other].group.c_str(), copy[other].caption.c_str());
            lbConflict->SetText(text);
        }
        else
        {
            lbConflict->SetText("No conflicts");
        }
    }

  public:
    KeyEditDialog(const std::vector<Keys::Row>& r, uint32 index, const ModifierMap& m)
        : Window("Edit key", "d:c,w:72,h:16", WindowFlags::ProcessReturn), rows(r), rowIndex(index), map(m), result(r[index].key), updating(false)
    {
        const auto& row = rows[rowIndex];
        LocalString<256> text;
        text.SetFormat("%s > %s", row.group.c_str(), row.caption.c_str());
        Factory::Label::Create(this, text, "l:1,t:0,r:1,h:1");
        Factory::Label::Create(this, row.explanation, "l:1,t:1,r:1,h:2");

        Factory::Label::Create(this, "Press the new key:", "l:1,t:4,w:19");
        selector = Factory::KeySelector::Create(this, "l:21,t:4,r:1", row.key);

        Factory::Label::Create(this, "...or compose it:", "l:1,t:6,w:19");
        cbCtrl  = Factory::CheckBox::Create(this, "C&trl", "l:21,t:6,w:8", ID_CTRL);
        cbAlt   = Factory::CheckBox::Create(this, "&Alt", "l:30,t:6,w:7", ID_ALT);
        cbShift = Factory::CheckBox::Create(this, "S&hift", "l:38,t:6,w:9", ID_SHIFT);
        cbKey   = Factory::ComboBox::Create(this, "l:48,t:6,r:1");
        cbKey->AddItem("(none)", 0ULL);
        for (uint32 code = 1; code < static_cast<uint32>(Key::Count); code++)
            cbKey->AddItem(KeyUtils::GetKeyName(static_cast<Key>(code)), static_cast<uint64>(code));

        LocalString<64> def;
        if (row.defaultKey == Key::None)
            def.Set("Default: (none)");
        else
        {
            LocalString<32> k;
            KeyUtils::ToDisplayString(row.defaultKey, map, k);
            def.SetFormat("Default: %s", k.GetText());
        }
        Factory::Label::Create(this, def, "l:1,t:8,r:1,h:1");
        lbConflict = Factory::Label::Create(this, "", "l:1,t:9,r:1,h:2");

        Factory::Button::Create(this, "&OK", "l:1,b:0,w:12", ID_OK);
        Factory::Button::Create(this, "&Unassign", "l:14,b:0,w:14", ID_UNASSIGN);
        Factory::Button::Create(this, "&Default", "l:30,b:0,w:13", ID_DEFAULT);
        Factory::Button::Create(this, "&Cancel", "r:1,b:0,w:12", ID_CANCEL);

        SetKey(row.key);
        selector->SetFocus();
    }
    Key GetResult() const
    {
        return result;
    }
    bool Validate()
    {
        const auto& row = rows[rowIndex];
        if (row.HasFlag(GView::KeyboardControlFlags::ShiftExtendsSelection) && ((result & Key::Shift) != Key::None))
        {
            Dialogs::MessageBox::ShowError("Invalid key", "Shift can not be used for this key: Shift + key extends the selection.");
            return false;
        }
        if ((result == Key::None) && IsShowKeysBinding(row))
        {
            Dialogs::MessageBox::ShowError("Invalid key", "The keyboard shortcuts window must keep a key.");
            return false;
        }
        return true;
    }
    bool OnEvent(Reference<Control>, Event eventType, int ID) override
    {
        switch (eventType)
        {
        case Event::KeySelectorChanged:
            if (!updating)
                SetKey(selector->GetSelectedKey());
            return true;
        case Event::CheckedStatusChanged:
        case Event::ComboBoxSelectedItemChanged:
            if (!updating)
                SetKey(ComposeKey());
            return true;
        case Event::WindowAccept:
            if (Validate())
                Exit(Dialogs::Result::Ok);
            return true;
        case Event::WindowClose:
            Exit(Dialogs::Result::Cancel);
            return true;
        case Event::ButtonClicked:
            switch (ID)
            {
            case ID_OK:
                if (Validate())
                    Exit(Dialogs::Result::Ok);
                return true;
            case ID_UNASSIGN:
                SetKey(Key::None);
                if (Validate())
                    Exit(Dialogs::Result::Ok);
                return true;
            case ID_DEFAULT:
                SetKey(rows[rowIndex].defaultKey);
                return true;
            case ID_CANCEL:
                Exit(Dialogs::Result::Cancel);
                return true;
            }
            break;
        default:
            break;
        }
        return false;
    }
};

//============================================================================================ KeysWindow ===
class KeysWindow : public Window
{
    Reference<Instance> instance;
    Reference<FileWindow> fileWindow;
    Keys::Registry original;
    Keys::Registry pending;
    ModifierMap originalMap;
    ModifierMap pendingMap;
    std::vector<Keys::Row> rows;
    std::vector<uint32> rowList; // LIST_TOP / LIST_BOTTOM for every row
    Reference<Splitter> splitter;
    Reference<Panel> panels[2];
    Reference<ListView> lists[2];
    Reference<ComboBox> cbScope, cbCtrlActs, cbAltActs;
    Reference<Label> lbStatus;
    bool allKeys;
    bool updatingProfile;
    uint32 lastList; // the list that had the focus last (buttons take the focus away from it)

    void BuildRows()
    {
        rows.clear();
        rowList.clear();
        Keys::Collector collector(rows);
        LocalString<128> group;

        // ---------------- top list: type plugin(s), generic plugins, GView
        const GView::Type::Plugin* currentPlugin = nullptr;
        if (fileWindow.IsValid() && fileWindow->GetTypePlugin().IsValid())
            currentPlugin = &static_cast<GView::Type::Plugin&>(fileWindow->GetTypePlugin());

        auto addTypePlugin = [&](const GView::Type::Plugin& p, bool withInstanceKeys) {
            group.SetFormat("%s plugin", std::string(p.GetName()).c_str());
            collector.SetSection(p.GetKeysSection(), group.ToStringView());
            if (withInstanceKeys)
            {
                auto content = fileWindow->GetObject()->GetContentType();
                if (content)
                    content->UpdateKeys(&collector);
            }
            collector.BeginCategory("");
            for (const auto& cmd : p.GetCommands())
                collector.AddCommand(cmd.name, "Plugin command", cmd.key, cmd.defaultKey);
        };
        if (allKeys)
        {
            // sorted by name -> the same order every time (the settings order is not guaranteed)
            std::vector<const GView::Type::Plugin*> plugins;
            for (const auto& p : instance->GetTypePlugins())
                plugins.push_back(&p);
            std::sort(plugins.begin(), plugins.end(), [](auto a, auto b) { return a->GetName() < b->GetName(); });
            for (auto p : plugins)
            {
                const bool isCurrent = (currentPlugin != nullptr) && (p->GetName() == currentPlugin->GetName());
                if (p->GetCommands().empty() && !isCurrent)
                    continue;
                addTypePlugin(*p, isCurrent);
            }
        }
        else if (currentPlugin)
        {
            addTypePlugin(*currentPlugin, true);
        }

        std::vector<const GView::Generic::Plugin*> genericPlugins;
        for (const auto& g : instance->GetGenericPlugins())
            genericPlugins.push_back(&g);
        std::sort(genericPlugins.begin(), genericPlugins.end(), [](auto a, auto b) { return a->GetName() < b->GetName(); });
        for (auto gp : genericPlugins)
        {
            const auto& g = *gp;
            if (g.GetCommandsCount() == 0)
                continue;
            group.SetFormat("Generic plugin: %s", std::string(g.GetName()).c_str());
            collector.SetSection(g.GetKeysSection(), group.ToStringView());
            LocalString<128> explanation;
            for (uint32 i = 0; i < g.GetCommandsCount(); i++)
            {
                explanation.SetFormat("%s (generic plugin command)", std::string(g.GetCommandName(i)).c_str());
                collector.AddCommand(g.GetCommandName(i), explanation.ToStringView(), g.GetCommandKey(i), g.GetCommandDefaultKey(i));
            }
        }

        collector.SetSection(Keys::SECTION_GVIEW, "GView");
        InstanceCommands::RegisterGViewKeys(&collector);
        rowList.resize(rows.size(), LIST_TOP);

        // ---------------- bottom list: viewer(s)
        const Keys::ViewerKeys* currentViewer = nullptr;
        if (fileWindow.IsValid())
            currentViewer = Keys::GetViewerKeys(fileWindow->GetCurrentView());
        if ((!allKeys) && (currentViewer))
        {
            group.SetFormat("%s (%s)", std::string(fileWindow->GetCurrentView()->GetName()).c_str(), std::string(currentViewer->title).c_str());
            collector.SetSection(currentViewer->section, group.ToStringView());
            currentViewer->registerKeys(&collector);
        }
        else
        {
            for (const auto& v : Keys::GetAllViewerKeys())
            {
                collector.SetSection(v.section, v.title);
                v.registerKeys(&collector);
            }
        }
        rowList.resize(rows.size(), LIST_BOTTOM);

        Keys::ResolveRows(rows, pending);
        Keys::ComputeConflicts(rows);
    }

    void FillList(uint32 listIndex, uint64 selectRow)
    {
        auto list = lists[listIndex];
        list->DeleteAllItems();
        LocalString<256> title, keyText, status;
        std::string lastGroup, lastCategory;
        bool first = true;
        ListViewItem toSelect, firstItem;
        for (uint32 i = 0; i < static_cast<uint32>(rows.size()); i++)
        {
            if (rowList[i] != listIndex)
                continue;
            const auto& r = rows[i];
            if (first || (r.group != lastGroup) || (r.category != lastCategory))
            {
                if (r.category.empty())
                    title.Set(r.group);
                else
                    title.SetFormat("%s > %s", r.group.c_str(), r.category.c_str());
                auto cat = list->AddItem({ title });
                cat.SetType(ListViewItem::Type::Category);
                cat.SetData(NO_ROW);
                lastGroup    = r.group;
                lastCategory = r.category;
                first        = false;
            }
            KeyToDisplay(r, pendingMap, keyText);

            // status
            auto type = ListViewItem::Type::Normal;
            status.Clear();
            if (r.conflictWith >= 0)
            {
                const auto& o = rows[r.conflictWith];
                status.SetFormat("Conflict: %s > %s", o.group.c_str(), o.caption.c_str());
                type = ListViewItem::Type::ErrorInformation;
            }
            else if (!r.IsEditable())
            {
                status.Set("fixed");
                type = ListViewItem::Type::GrayedOut;
            }
            else
            {
                const auto saved = original.Resolve(r.section, r.caption, r.defaultKey);
                if (r.key != saved)
                {
                    status.Set(r.HasFlag(GView::KeyboardControlFlags::RequiresRestart) ? "changed (restart)" : "changed (unsaved)");
                    type = ListViewItem::Type::Emphasized_2;
                }
                else if (r.key != r.defaultKey)
                {
                    LocalString<32> def;
                    if (r.defaultKey == Key::None)
                        def.Set("none");
                    else
                        KeyUtils::ToDisplayString(r.defaultKey, pendingMap, def);
                    status.SetFormat("custom (default %s)", def.GetText());
                    type = ListViewItem::Type::Emphasized_1;
                }
                else if (r.key == Key::None)
                {
                    status.Set("unassigned");
                    type = ListViewItem::Type::GrayedOut;
                }
            }
            auto item = list->AddItem({ keyText, r.caption, r.explanation, status });
            item.SetType(type);
            item.SetData(static_cast<uint64>(i));
            if (static_cast<uint64>(i) == selectRow)
                toSelect = item;
            if (!firstItem.IsValid())
                firstItem = item;
        }
        // never start on a category row
        if (toSelect.IsValid())
            list->SetCurrentItem(toSelect);
        else if (firstItem.IsValid())
            list->SetCurrentItem(firstItem);
    }

    void UpdateStatus()
    {
        uint32 changes = 0, conflicts = 0;
        for (const auto& r : rows)
        {
            if (r.conflictWith >= 0)
                conflicts++;
            if (r.IsEditable() && (r.key != original.Resolve(r.section, r.caption, r.defaultKey)))
                changes++;
        }
        const bool profileChanged = (pendingMap.GetCtrlActsAs() != originalMap.GetCtrlActsAs());
        LocalString<256> text;
        text.SetFormat(
              "%u unsaved change(s)%s  |  %u conflict(s)  |  Enter: edit  F3: reset  F4: unassign  F2: save",
              changes,
              profileChanged ? " + keyboard profile" : "",
              conflicts);
        lbStatus->SetText(text);
    }

    void Refresh(uint64 selectTop = NO_ROW, uint64 selectBottom = NO_ROW)
    {
        BuildRows();
        FillList(LIST_TOP, selectTop);
        FillList(LIST_BOTTOM, selectBottom);
        UpdateStatus();
    }

    // after an edit the rows are rebuilt -> keep the selection on the same (section, caption)
    void RefreshKeepSelection(const std::string& section, const std::string& caption)
    {
        BuildRows();
        uint64 sel[2] = { NO_ROW, NO_ROW };
        for (uint32 i = 0; i < static_cast<uint32>(rows.size()); i++)
            if ((rows[i].section == section) && (rows[i].caption == caption) && (!rows[i].displayOnly))
                sel[rowList[i]] = i;
        FillList(LIST_TOP, sel[LIST_TOP]);
        FillList(LIST_BOTTOM, sel[LIST_BOTTOM]);
        UpdateStatus();
    }

    std::optional<uint32> GetCurrentRow()
    {
        if (lists[LIST_TOP]->HasFocus())
            lastList = LIST_TOP;
        else if (lists[LIST_BOTTOM]->HasFocus())
            lastList = LIST_BOTTOM;
        auto item = lists[lastList]->GetCurrentItem();
        if (!item.IsValid())
            return std::nullopt;
        const auto data = item.GetData(NO_ROW);
        if ((data == NO_ROW) || (data >= rows.size()))
            return std::nullopt;
        return static_cast<uint32>(data);
    }
    std::optional<uint32> GetEditableRow()
    {
        auto row = GetCurrentRow();
        if (!row.has_value())
        {
            Dialogs::MessageBox::ShowNotification("Keyboard shortcuts", "Select a key in one of the lists first.");
            return std::nullopt;
        }
        if (!rows[row.value()].IsEditable())
        {
            Dialogs::MessageBox::ShowNotification("Keyboard shortcuts", "This key is handled by a UI control and can not be changed.");
            return std::nullopt;
        }
        return row;
    }
    void SetPendingKey(uint32 rowIndex, Key key)
    {
        const auto r = rows[rowIndex]; // copy (rows are rebuilt)
        if (key == r.defaultKey)
            pending.ClearOverride(r.section, r.caption);
        else
            pending.SetOverride(r.section, r.caption, key);
        RefreshKeepSelection(r.section, r.caption);
    }

    void EditCurrent()
    {
        auto row = GetEditableRow();
        if (!row.has_value())
            return;
        KeyEditDialog dlg(rows, row.value(), pendingMap);
        if (dlg.Show() == Dialogs::Result::Ok)
            SetPendingKey(row.value(), dlg.GetResult());
    }
    void UnassignCurrent()
    {
        auto row = GetEditableRow();
        if (!row.has_value())
            return;
        if (IsShowKeysBinding(rows[row.value()]))
        {
            Dialogs::MessageBox::ShowError("Invalid key", "The keyboard shortcuts window must keep a key.");
            return;
        }
        SetPendingKey(row.value(), Key::None);
    }
    void ResetCurrent()
    {
        auto row = GetEditableRow();
        if (!row.has_value())
            return;
        SetPendingKey(row.value(), rows[row.value()].defaultKey);
    }
    void ResetAll()
    {
        if (Dialogs::MessageBox::ShowOkCancel("Reset all", "Restore the default key for every shortcut and the standard keyboard profile?") !=
            Dialogs::Result::Ok)
            return;
        pending.ClearAllOverrides();
        pendingMap = ModifierMap::Identity();
        SyncProfileCombos();
        Refresh();
    }
    bool HasUnsavedChanges()
    {
        if (pendingMap.GetCtrlActsAs() != originalMap.GetCtrlActsAs())
            return true;
        for (const auto& r : rows)
            if (r.IsEditable() && (r.key != original.Resolve(r.section, r.caption, r.defaultKey)))
                return true;
        // overrides of keys that are not listed in the current scope
        return pending.GetOverrides() != original.GetOverrides();
    }
    bool Save()
    {
        uint32 conflicts = 0;
        for (const auto& r : rows)
            if (r.conflictWith >= 0)
                conflicts++;
        if (conflicts > 0)
        {
            LocalString<128> msg;
            msg.SetFormat("%u key(s) are in conflict (only one of them will work). Save anyway?", conflicts);
            if (Dialogs::MessageBox::ShowOkCancel("Conflicts", msg) != Dialogs::Result::Ok)
                return false;
        }
        auto ini = AppCUI::Application::GetAppSettings();
        if (!ini)
        {
            Dialogs::MessageBox::ShowError("Error", "The settings are not available.");
            return false;
        }
        instance->GetKeyBindings() = pending;
        instance->GetKeyBindings().Save(*ini);
        AppCUI::Application::SetModifierMap(pendingMap);
        if (!AppCUI::Application::SaveAppSettings())
        {
            Dialogs::MessageBox::ShowError("Error", "Fail to save the settings file !");
            return false;
        }
        instance->ApplyKeyBindings();
        original    = instance->GetKeyBindings();
        pending     = original;
        originalMap = pendingMap;
        Refresh();
        return true;
    }
    void Close()
    {
        if (HasUnsavedChanges())
        {
            const auto res = Dialogs::MessageBox::ShowYesNoCancel("Keyboard shortcuts", "Save the changes?");
            if (res == Dialogs::Result::Cancel)
                return;
            if ((res == Dialogs::Result::Yes) && (!Save()))
                return;
        }
        Exit(Dialogs::Result::Cancel);
    }

    void SyncProfileCombos()
    {
        updatingProfile = true;
        const bool swapped = pendingMap.GetCtrlActsAs() == Key::Alt;
        cbCtrlActs->SetCurentItemIndex(swapped ? 1 : 0);
        cbAltActs->SetCurentItemIndex(swapped ? 1 : 0);
        updatingProfile = false;
    }
    void OnProfileChanged(bool fromCtrlCombo)
    {
        if (updatingProfile)
            return;
        // the only bijective choices are "standard" and "swapped" -> keep both combos consistent
        const bool swapped = (fromCtrlCombo ? cbCtrlActs->GetCurrentItemIndex() : cbAltActs->GetCurrentItemIndex()) == 1;
        auto map           = ModifierMap::FromAssignments(swapped ? Key::Alt : Key::Ctrl, swapped ? Key::Ctrl : Key::Alt);
        if (map.has_value())
            pendingMap = map.value();
        SyncProfileCombos();
        Refresh();
    }

  public:
    KeysWindow(Reference<Instance> inst, Reference<FileWindow> fw)
        : Window("Keyboard shortcuts", "d:c,w:80%,h:80%", WindowFlags::Sizeable), instance(inst), fileWindow(fw), allKeys(!fw.IsValid()),
          updatingProfile(false), lastList(LIST_BOTTOM)
    {
        original    = instance->GetKeyBindings();
        pending     = original;
        originalMap = AppCUI::Application::GetModifierMap();
        pendingMap  = originalMap;

        LocalString<256> title;
        if (fileWindow.IsValid())
        {
            title.Set("Keyboard shortcuts - ");
            if (fileWindow->GetTypePlugin().IsValid())
            {
                title.Add(fileWindow->GetTypePlugin()->GetName());
                title.Add(" / ");
            }
            title.Add(fileWindow->GetCurrentView()->GetName());
            SetText(title);
        }

        // ---- first line: scope + keyboard profile
        Factory::Label::Create(this, "&Show", "l:1,t:0,w:5");
        cbScope = Factory::ComboBox::Create(this, "l:7,t:0,w:22");
        cbScope->AddItem("This file");
        cbScope->AddItem("All keys");
        cbScope->SetCurentItemIndex(allKeys ? 1 : 0);
        cbScope->SetHotKey('S');
        if (!fileWindow.IsValid())
            cbScope->SetEnabled(false);

        Factory::Label::Create(this, "Ctrl key acts as", "l:31,t:0,w:16");
        cbCtrlActs = Factory::ComboBox::Create(this, "l:48,t:0,w:10");
        cbCtrlActs->AddItem("Ctrl");
        cbCtrlActs->AddItem("Alt");
#ifdef BUILD_FOR_OSX
        Factory::Label::Create(this, "Option key acts as", "l:60,t:0,w:18");
        cbAltActs = Factory::ComboBox::Create(this, "l:79,t:0,w:10");
#else
        Factory::Label::Create(this, "Alt key acts as", "l:60,t:0,w:15");
        cbAltActs = Factory::ComboBox::Create(this, "l:76,t:0,w:10");
#endif
        cbAltActs->AddItem("Alt");
        cbAltActs->AddItem("Ctrl");
        SyncProfileCombos();

#ifdef BUILD_FOR_OSX
        Factory::Label::Create(
              this,
              "macOS: for Alt (Opt) shortcuts enable \"Use Option as Meta key\" (Terminal) or \"Option: Esc+\" (iTerm2), or swap Ctrl and Alt above.",
              "l:1,t:1,r:1,h:1");
#else
        Factory::Label::Create(this, "Shortcuts are saved in the [Keys.*] sections of the settings file; only the changed keys are stored.", "l:1,t:1,r:1,h:1");
#endif

        // ---- the two lists
        splitter  = Factory::Splitter::Create(this, "l:0,t:2,r:0,b:3", SplitterFlags::Horizontal);
        panels[0] = Factory::Panel::Create(splitter, "Plugin & GView", "d:c");
        panels[1] = Factory::Panel::Create(splitter, "Viewer", "d:c");
        for (uint32 i = 0; i < 2; i++)
        {
            lists[i] = Factory::ListView::Create(
                  panels[i],
                  "d:c",
                  { "n:Key,w:18%", "n:Command,w:22%", "n:Description,w:42%", "n:Status,w:18%" },
                  ListViewFlags::PopupSearchBar | ListViewFlags::HideBorder);
        }

        // ---- status + buttons
        lbStatus = Factory::Label::Create(this, "", "l:1,b:2,r:1,h:1");
        Factory::Button::Create(this, "&Edit", "l:1,b:0,w:10", BTN_EDIT);
        Factory::Button::Create(this, "&Unassign", "l:12,b:0,w:13", BTN_UNASSIGN);
        Factory::Button::Create(this, "&Reset", "l:26,b:0,w:10", BTN_RESET);
        Factory::Button::Create(this, "Reset &all", "l:37,b:0,w:14", BTN_RESET_ALL);
        Factory::Button::Create(this, "Sa&ve", "l:52,b:0,w:10", BTN_SAVE);
        Factory::Button::Create(this, "&Close", "r:1,b:0,w:11", BTN_CLOSE);

        Refresh();
        UpdatePanelTitles();
        ResizeLists();
        lists[LIST_BOTTOM]->SetFocus();
    }

    void UpdatePanelTitles()
    {
        panels[0]->SetText(allKeys ? "Plugins & GView (all)" : "Plugin & GView");
        panels[1]->SetText(allKeys ? "Viewers (all)" : "Viewer");
    }
    void ResizeLists()
    {
        // split the height proportionally with the number of rows (each list gets 30% .. 70%)
        uint32 counts[2] = { 0, 0 };
        for (auto l : rowList)
            counts[l]++;
        const int32 total = splitter->GetHeight();
        if (total <= 6)
            return;
        const double ratio = (counts[0] + counts[1]) > 0 ? static_cast<double>(counts[1]) / static_cast<double>(counts[0] + counts[1]) : 0.5;
        const double clamped = std::min<double>(0.7, std::max<double>(0.3, ratio));
        splitter->SetSecondPanelSize(static_cast<uint32>(total * clamped));
    }

    bool OnKeyEvent(Key keyCode, char16 unicode) override
    {
        switch (keyCode)
        {
        case Key::F2:
            Save();
            return true;
        case Key::F3:
            ResetCurrent();
            return true;
        case Key::F4:
        case Key::Delete:
            UnassignCurrent();
            return true;
        case Key::Escape:
            Close();
            return true;
        default:
            break;
        }
        return Window::OnKeyEvent(keyCode, unicode);
    }
    bool OnUpdateCommandBar(AppCUI::Application::CommandBar& commandBar) override
    {
        commandBar.SetCommand(Key::Enter, "Edit", CMD_EDIT);
        commandBar.SetCommand(Key::F2, "Save", CMD_SAVE);
        commandBar.SetCommand(Key::F3, "Reset", CMD_RESET);
        commandBar.SetCommand(Key::F4, "Unassign", CMD_UNASSIGN);
        return true;
    }
    bool OnEvent(Reference<Control> control, Event eventType, int ID) override
    {
        switch (eventType)
        {
        case Event::ListViewItemPressed:
            EditCurrent();
            return true;
        case Event::ListViewCurrentItemChanged:
            if (control == lists[LIST_TOP].ToBase<Control>())
                lastList = LIST_TOP;
            else if (control == lists[LIST_BOTTOM].ToBase<Control>())
                lastList = LIST_BOTTOM;
            return true;
        case Event::ComboBoxSelectedItemChanged:
            if (control == cbScope.ToBase<Control>())
            {
                allKeys = cbScope->GetCurrentItemIndex() == 1;
                UpdatePanelTitles();
                Refresh();
                ResizeLists();
            }
            else if (control == cbCtrlActs.ToBase<Control>())
                OnProfileChanged(true);
            else if (control == cbAltActs.ToBase<Control>())
                OnProfileChanged(false);
            return true;
        case Event::Command:
            switch (ID)
            {
            case CMD_EDIT:
                EditCurrent();
                return true;
            case CMD_SAVE:
                Save();
                return true;
            case CMD_RESET:
                ResetCurrent();
                return true;
            case CMD_UNASSIGN:
                UnassignCurrent();
                return true;
            }
            break;
        case Event::ButtonClicked:
            switch (ID)
            {
            case BTN_EDIT:
                EditCurrent();
                return true;
            case BTN_UNASSIGN:
                UnassignCurrent();
                return true;
            case BTN_RESET:
                ResetCurrent();
                return true;
            case BTN_RESET_ALL:
                ResetAll();
                return true;
            case BTN_SAVE:
                Save();
                return true;
            case BTN_CLOSE:
                Close();
                return true;
            }
            break;
        case Event::WindowClose:
            Close();
            return true;
        case Event::WindowAccept:
            return true; // Enter is used to edit the current key
        default:
            break;
        }
        return Window::OnEvent(control, eventType, ID);
    }
};
} // namespace

void GView::App::ShowKeyboardShortcutsWindow(Reference<Instance> instance, Reference<FileWindow> fileWindow)
{
    if (!instance.IsValid())
        return;
    KeysWindow window(instance, fileWindow);
    window.Show();
}
