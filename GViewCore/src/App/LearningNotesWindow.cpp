// Course notes of Learning and Evaluation Mode (plans/LEARNING_MODE_PROTOCOL_SPEC.md §10.11).
//
// "My notes" are private notes of the student, kept by the course server; they are edited here and saved
// automatically (LearningSession::PumpNotes: ~2 s after the last keystroke, when the window closes and when the
// session ends). "Course notes" are written by the teachers: read-only for students, editable by course staff.
// Note text is never written to disk by GView and never goes to telemetry; the editor is plain text and offers no way
// to insert task content (no "insert selection" under a policy that disables Copy).

#include "Internal.hpp"
#include "Learning/LearningSession.hpp"

#include <chrono>
#include <ctime>
#include <set>

#undef MessageBox

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;
namespace Learning = GView::Security::Learning;

namespace
{
constexpr int BTN_NEW          = 1;
constexpr int BTN_DELETE       = 2;
constexpr int BTN_SAVE_NOW     = 3;
constexpr int BTN_REFRESH      = 4;
constexpr int BTN_CLOSE        = 5;
constexpr int BTN_NEW_COURSE   = 6;
constexpr int BTN_SAVE_COURSE  = 7;
constexpr int BTN_DELETE_COURSE = 8;
constexpr int CHK_ENABLED      = 9;

constexpr uint64 ROW_NONE      = 0xFFFFFFFFFFFFFFFFull;
constexpr uint64 ROW_MINE      = 1ull << 56;
constexpr uint64 ROW_TEACHER   = 2ull << 56;
constexpr uint64 ROW_KIND_MASK = 0xFFull << 56;

constexpr std::string_view DISABLED_TEXT = "Course notes are disabled by your teacher.";

ConstString Utf8(const std::string& s)
{
    return std::u8string_view(reinterpret_cast<const char8_t*>(s.data()), s.size());
}

std::string ToUtf8(const CharacterBuffer& text)
{
    std::string r;
    text.ToString(r);
    return r;
}

std::string FormatTime(uint64 t)
{
    if (t == 0)
        return "";
    const time_t tt = static_cast<time_t>(t);
    struct tm tmv
    {
    };
#ifdef BUILD_FOR_WINDOWS
    if (localtime_s(&tmv, &tt) != 0)
        return "";
#else
    if (localtime_r(&tt, &tmv) == nullptr)
        return "";
#endif
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min);
    return buf;
}

std::string DisplayTitle(const std::string& title)
{
    return title.empty() ? std::string("(untitled)") : title;
}

class LearningNotesWindow : public Window, public Handlers::OnTreeViewCurrentItemChangedInterface
{
    enum class Selection : uint8 { None, Mine, Teacher, TeacherDraft };

    Learning::NoteScope focusScope; // the open catalogue item (General when none)
    std::string focusTitle;
    const void* taskObject; // the task window this was opened from (note_add telemetry), or nullptr
    bool openNoteForItem;   // Ctrl+F11 in a task window: open (or start) the note of this item

    Reference<Label> lbHeader, lbStatus, lbCounter, lbAudience, lbOrder;
    Reference<TreeView> list;
    Reference<TextField> titleField, orderField;
    Reference<ComboBox> scopeCombo, audienceCombo;
    Reference<CheckBox> enabledCheck;
    Reference<TextArea> bodyArea;
    Reference<Button> newButton, deleteButton, saveNowButton, refreshButton, newCourseButton, saveCourseButton, deleteCourseButton;

    std::vector<Learning::NoteScope> scopeOptions;
    std::vector<std::string> rowMine;
    std::vector<int64> rowTeacher;
    std::string listSignature;

    Selection selection{ Selection::None };
    std::string selectedId;
    int64 selectedTeacherId{ 0 };
    std::set<std::string> createdHere; // created in this window, note_add not recorded yet (recorded at the first text)
    // what the editor shows of the selected note (loaded from the store, or typed): a different store value means the
    // sync replaced the note
    std::string editorTitle, editorBody;
    Learning::NoteScope editorScope;
    TreeViewItem selectedRow; // row of the selected own note (valid until the next rebuild)

    bool loading{ false }; // programmatic changes of the editor: not edits
    bool teacherSaving{ false };
    bool openDone{ false };
    bool shownDisabled{ false };
    uint64 shownVersion{ ~0ull };
    std::shared_ptr<bool> alive = std::make_shared<bool>(true);

    Learning::LearningSession& Session()
    {
        return Learning::GetSession();
    }
    uint64 NowMs() const
    {
        return static_cast<uint64>(
              std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }

  public:
    LearningNotesWindow(Learning::NoteScope focus, std::string_view title, const void* task, bool openForItem)
        : Window("Course notes", "d:c,w:98%,h:96%", WindowFlags::Sizeable), focusScope(std::move(focus)), focusTitle(title),
          taskObject(task), openNoteForItem(openForItem)
    {
        lbHeader = Factory::Label::Create(this, "", "l:1,t:0,r:1,h:1");
        list     = Factory::TreeView::Create(this, "l:1,t:2,w:40%,b:3", { "n:Note,w:34", "n:Scope / updated,w:30" }, TreeViewFlags::Searchable);
        list->Handlers()->OnCurrentItemChanged = this;

        Factory::Label::Create(this, "&Title:", "l:42%,t:2,w:7");
        titleField = Factory::TextField::Create(this, "", "l:50%,t:2,r:1");
        Factory::Label::Create(this, "Sc&ope:", "l:42%,t:4,w:7");
        scopeCombo = Factory::ComboBox::Create(this, "l:50%,t:4,r:1");
        bodyArea   = Factory::TextArea::Create(this, "", "l:42%,t:6,r:1,b:6", TextAreaFlags::Border | TextAreaFlags::ScrollBars);
        lbCounter  = Factory::Label::Create(this, "", "l:42%,b:5,r:1,h:1");
        lbStatus   = Factory::Label::Create(this, "", "l:42%,b:4,r:1,h:1");

        // teacher (course staff) controls
        lbAudience    = Factory::Label::Create(this, "Audience:", "l:42%,b:2,w:10");
        audienceCombo = Factory::ComboBox::Create(this, "l:53%,b:2,w:10", "all,G1,G2");
        enabledCheck  = Factory::CheckBox::Create(this, "&Enabled", "l:66%,b:2,w:12", CHK_ENABLED);
        lbOrder       = Factory::Label::Create(this, "Order:", "l:80%,b:2,w:7");
        orderField    = Factory::TextField::Create(this, "0", "l:87%,b:2,r:1");

        newButton          = Factory::Button::Create(this, "&New note", "l:1,b:0,w:12", BTN_NEW, ButtonFlags::Flat);
        deleteButton       = Factory::Button::Create(this, "&Delete", "l:14,b:0,w:10", BTN_DELETE, ButtonFlags::Flat);
        saveNowButton      = Factory::Button::Create(this, "Sa&ve now", "l:25,b:0,w:12", BTN_SAVE_NOW, ButtonFlags::Flat);
        refreshButton      = Factory::Button::Create(this, "&Refresh", "l:38,b:0,w:11", BTN_REFRESH, ButtonFlags::Flat);
        newCourseButton    = Factory::Button::Create(this, "New co&urse note", "l:50,b:0,w:18", BTN_NEW_COURSE, ButtonFlags::Flat);
        saveCourseButton   = Factory::Button::Create(this, "Save course note", "l:69,b:0,w:18", BTN_SAVE_COURSE, ButtonFlags::Flat);
        deleteCourseButton = Factory::Button::Create(this, "Delete course note", "l:88,b:0,w:20", BTN_DELETE_COURSE, ButtonFlags::Flat);
        Factory::Button::Create(this, "C&lose", "r:1,b:0,w:10", BTN_CLOSE, ButtonFlags::Flat);

        BuildScopeOptions();
        LoadEditor();
        Refresh(true);
        // a fresh copy each time the window opens (local changes are kept by the merge)
        if (Session().CanUseNotes())
            Session().RefreshNotes();
        Refresh(false); // frontends without frame updates ran the request inline: show its result now
    }
    ~LearningNotesWindow() override
    {
        *alive = false;
    }

    bool OnFrameUpdate() override
    {
        auto& s = Session();
        s.NotifyFrameUpdatesAvailable();
        bool repaint = s.DrainCompletions() > 0;
        s.Tick();
        for (const auto& notice : s.TakeNotesNotices())
        {
            if (notice != DISABLED_TEXT)
                Dialogs::MessageBox::ShowNotification("Course notes", notice);
            repaint = true;
        }
        if (s.NotesVersion() != shownVersion)
        {
            Refresh(false);
            repaint = true;
        }
        repaint |= UpdateStatusLine();
        return repaint;
    }

    void OnTreeViewCurrentItemChanged(Reference<TreeView>, TreeViewItem& item) override
    {
        if (loading)
            return;
        const uint64 data = item.IsValid() ? item.GetData(ROW_NONE) : ROW_NONE;
        Select(data);
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::TextChanged && (c == titleField || c == bodyArea || c == orderField))
        {
            OnEditorChanged();
            return true;
        }
        if (eventType == Event::ComboBoxSelectedItemChanged && (c == scopeCombo || c == audienceCombo))
        {
            OnEditorChanged();
            return true;
        }
        if (eventType == Event::CheckedStatusChanged && id == CHK_ENABLED)
            return true;
        if (eventType == Event::ButtonClicked)
        {
            switch (id)
            {
            case BTN_NEW:
                NewNote();
                break;
            case BTN_DELETE:
                DeleteSelected();
                break;
            case BTN_SAVE_NOW:
                Session().PumpNotes(true);
                break;
            case BTN_REFRESH:
                if (auto st = Session().RefreshNotes(); !st.ok)
                    Dialogs::MessageBox::ShowError("Course notes", st.message);
                break;
            case BTN_NEW_COURSE:
                NewCourseNote();
                break;
            case BTN_SAVE_COURSE:
                SaveCourseNote();
                break;
            case BTN_DELETE_COURSE:
                DeleteCourseNote();
                break;
            case BTN_CLOSE:
                Close();
                return true;
            default:
                return Window::OnEvent(c, eventType, id);
            }
            // frontends without frame updates (ncurses) ran the request inline and get no OnFrameUpdate
            Refresh(false);
            UpdateStatusLine();
            return true;
        }
        if (eventType == Event::WindowClose)
        {
            Close();
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }

  private:
    void Close()
    {
        // drop the new notes nobody typed into, then save everything now (spec §10.11: save on close)
        Session().Notes().DropEmptyDrafts();
        Session().PumpNotes(true);
        Exit(Dialogs::Result::Ok);
    }

    // ------------------------------------------------------------ scopes
    void BuildScopeOptions()
    {
        scopeOptions.clear();
        scopeOptions.push_back({});
        for (const auto& w : Session().GetCatalogue().weeks)
        {
            scopeOptions.push_back({ Learning::NoteScopeKind::Week, w.name });
            for (const auto& p : w.problems)
                scopeOptions.push_back({ Learning::NoteScopeKind::Problem, p.name });
            for (const auto& r : w.resources)
                scopeOptions.push_back({ Learning::NoteScopeKind::Resource, r.name });
        }
        if (std::find(scopeOptions.begin(), scopeOptions.end(), focusScope) == scopeOptions.end())
            scopeOptions.push_back(focusScope);
    }

    std::string ScopeLabel(const Learning::NoteScope& s)
    {
        const auto& cat = Session().GetCatalogue();
        if (s.kind == Learning::NoteScopeKind::Problem || s.kind == Learning::NoteScopeKind::Resource)
        {
            if (const auto* it = cat.Find(s.name, s.kind == Learning::NoteScopeKind::Problem); it != nullptr && it->title != it->name)
                return Learning::DescribeNoteScope(s) + " - " + it->title;
        }
        return Learning::DescribeNoteScope(s);
    }

    void FillScopeCombo(const Learning::NoteScope& selected)
    {
        if (std::find(scopeOptions.begin(), scopeOptions.end(), selected) == scopeOptions.end())
            scopeOptions.push_back(selected); // e.g. an item that is hidden now: the note keeps its scope
        scopeCombo->DeleteAllItems();
        uint32 index = 0;
        for (uint32 i = 0; i < scopeOptions.size(); i++)
        {
            scopeCombo->AddItem(Utf8(ScopeLabel(scopeOptions[i])), static_cast<uint64>(i));
            if (scopeOptions[i] == selected)
                index = i;
        }
        scopeCombo->SetCurentItemIndex(index);
    }

    Learning::NoteScope SelectedScope()
    {
        const uint64 idx = scopeCombo->GetCurrentItemUserData(ROW_NONE);
        return idx < scopeOptions.size() ? scopeOptions[idx] : Learning::NoteScope{};
    }

    bool IsFocusScope(const Learning::NoteScope& s) const
    {
        return !focusScope.IsGeneral() && s == focusScope;
    }

    // ------------------------------------------------------------ list
    void Refresh(bool force)
    {
        auto& s           = Session();
        shownVersion      = s.NotesVersion();
        const auto avail  = s.GetNotesAvailability();
        const bool usable = avail == Learning::NotesAvailability::Available;

        std::string header = focusScope.IsGeneral() ? std::string("Notes") : "Notes for: " + ScopeLabel(focusScope);
        if (usable && s.CanEditTeacherNotes())
            header += "   [course staff: course notes can be edited]";
        lbHeader->SetText(Utf8(header));

        if (!usable)
        {
            // 403 / notes off: the Notes UI is hidden, only the explanation remains
            if (!shownDisabled || force)
            {
                shownDisabled = true;
                loading       = true;
                list->ClearItems();
                selectedRow = TreeViewItem();
                rowMine.clear();
                rowTeacher.clear();
                listSignature.clear();
                loading   = false;
                selection = Selection::None;
                LoadEditor();
            }
            const bool disabled = avail == Learning::NotesAvailability::DisabledByPolicy || avail == Learning::NotesAvailability::DisabledByServer;
            lbStatus->SetText(disabled ? std::string(DISABLED_TEXT) : std::string("Course notes are not available in the current session state."));
            UpdateButtons();
            return;
        }
        shownDisabled = false;

        // rebuild the list only when what it shows changed (not on every keystroke of a note body)
        std::string sig;
        const auto& notes = s.Notes().Notes();
        for (const auto& n : notes)
        {
            if (n.deleted)
                continue;
            // the title of the note being edited is updated in its row directly (no rebuild per keystroke)
            const bool editing = selection == Selection::Mine && n.id == selectedId;
            sig += n.id + '\x1f' + (editing ? std::string() : n.title) + '\x1f' + std::string(Learning::NoteScopeKindName(n.scope.kind)) + n.scope.name + '\x1f' +
                   std::to_string(n.updatedAt) + '\x1e';
        }
        sig += '\x1d';
        for (const auto& t : s.TeacherNotes())
            sig += std::to_string(t.id) + '\x1f' + std::to_string(t.revision) + '\x1f' + t.title + (t.enabled ? "1" : "0") + '\x1e';
        sig += s.NotesLoaded() ? "L" : "-";
        sig += s.NotesError();
        if (sig != listSignature || force)
        {
            listSignature = std::move(sig);
            RebuildList();
        }

        if (!openDone && openNoteForItem && (s.NotesLoaded() || !s.NotesError().empty()))
        {
            openDone = true;
            OpenNoteOfFocusItem();
        }
        // the selected note may have been replaced (conflict) or removed (deleted elsewhere)
        if (selection == Selection::Mine)
        {
            const auto* n = s.Notes().Find(selectedId);
            if (n == nullptr || n->deleted)
            {
                selection = Selection::None;
                LoadEditor();
            }
            else if (!loading && (n->title != editorTitle || n->body != editorBody || n->scope != editorScope))
                LoadEditor(); // changed by the sync (server copy after a conflict, a refresh), not by typing here
        }
        else if (selection == Selection::Teacher)
        {
            const auto& tn = s.TeacherNotes();
            const auto it  = std::find_if(tn.begin(), tn.end(), [&](const Learning::TeacherNote& t) { return t.id == selectedTeacherId; });
            if (it == tn.end())
            {
                selection = Selection::None;
                LoadEditor();
            }
        }
        UpdateButtons();
    }

    void RebuildList()
    {
        auto& s = Session();
        loading = true;
        list->ClearItems();
        rowMine.clear();
        rowTeacher.clear();
        selectedRow = TreeViewItem();
        TreeViewItem toSelect;

        auto mine = list->AddItem("My notes", true);
        mine.SetType(TreeViewItem::Type::Category);
        mine.SetData(ROW_NONE);
        auto addMine = [&](const Learning::LocalNote& n) {
            auto node = mine.AddChild(Utf8(DisplayTitle(n.title)));
            std::string info = ScopeLabel(n.scope);
            if (n.updatedAt != 0)
                info += "  " + FormatTime(n.updatedAt);
            node.SetText(1, Utf8(info));
            if (IsFocusScope(n.scope))
                node.SetType(TreeViewItem::Type::Emphasized_1);
            rowMine.push_back(n.id);
            node.SetData(ROW_MINE | static_cast<uint64>(rowMine.size() - 1));
            if (selection == Selection::Mine && n.id == selectedId)
                toSelect = node;
            if (n.id == selectedId)
                selectedRow = node;
        };
        const auto& notes = s.Notes().Notes();
        for (const auto& n : notes) // the notes of the open item first
            if (!n.deleted && IsFocusScope(n.scope))
                addMine(n);
        for (const auto& n : notes)
            if (!n.deleted && !IsFocusScope(n.scope))
                addMine(n);
        if (notes.empty())
        {
            auto info = mine.AddChild(s.NotesLoaded() ? "(no notes yet - New note)" : "(loading...)");
            info.SetType(TreeViewItem::Type::GrayedOut);
            info.SetData(ROW_NONE);
        }
        mine.Unfold();

        auto course = list->AddItem("Course notes", true);
        course.SetType(TreeViewItem::Type::Category);
        course.SetData(ROW_NONE);
        const auto& teacher = s.TeacherNotes();
        // groups: the open item first, then general, then per week / item in the order they appear
        std::vector<Learning::NoteScope> groups;
        if (!focusScope.IsGeneral())
            groups.push_back(focusScope);
        groups.push_back({});
        for (const auto& t : teacher)
            if (std::find(groups.begin(), groups.end(), t.scope) == groups.end())
                groups.push_back(t.scope);
        for (const auto& g : groups)
        {
            TreeViewItem groupNode;
            for (const auto& t : teacher)
            {
                if (t.scope != g)
                    continue;
                if (!groupNode.IsValid())
                {
                    groupNode = course.AddChild(Utf8(IsFocusScope(g) ? "For this item: " + ScopeLabel(g) : ScopeLabel(g)), true);
                    groupNode.SetType(TreeViewItem::Type::Category);
                    groupNode.SetData(ROW_NONE);
                }
                auto node        = groupNode.AddChild(Utf8(DisplayTitle(t.title) + (t.enabled ? "" : "  (hidden)")));
                std::string info = s.CanEditTeacherNotes() || t.audience != Learning::NoteAudience::All
                                         ? "for " + std::string(Learning::NoteAudienceName(t.audience))
                                         : std::string();
                if (t.updatedAt != 0)
                    info += (info.empty() ? "" : "  ") + FormatTime(t.updatedAt);
                node.SetText(1, Utf8(info));
                if (!t.enabled)
                    node.SetType(TreeViewItem::Type::GrayedOut);
                rowTeacher.push_back(t.id);
                node.SetData(ROW_TEACHER | static_cast<uint64>(rowTeacher.size() - 1));
                if (selection == Selection::Teacher && t.id == selectedTeacherId)
                    toSelect = node;
            }
            if (groupNode.IsValid())
                groupNode.Unfold();
        }
        if (teacher.empty())
        {
            auto info = course.AddChild(s.NotesLoaded() ? "(none)" : "(loading...)");
            info.SetType(TreeViewItem::Type::GrayedOut);
            info.SetData(ROW_NONE);
        }
        course.Unfold();
        if (!s.NotesError().empty())
        {
            auto err = list->AddItem(Utf8("Could not load the notes: " + s.NotesError()));
            err.SetType(TreeViewItem::Type::ErrorInformation);
            err.SetData(ROW_NONE);
        }
        if (toSelect.IsValid())
            toSelect.SetCurrent();
        loading = false;
    }

    void Select(uint64 data)
    {
        if (data == ROW_NONE)
            return;
        const uint64 kind = data & ROW_KIND_MASK;
        const uint64 idx  = data & ~ROW_KIND_MASK;
        if (kind == ROW_MINE && idx < rowMine.size())
        {
            if (selection == Selection::Mine && selectedId == rowMine[idx])
                return;
            selection  = Selection::Mine;
            selectedId = rowMine[idx];
        }
        else if (kind == ROW_TEACHER && idx < rowTeacher.size())
        {
            if (selection == Selection::Teacher && selectedTeacherId == rowTeacher[idx])
                return;
            selection         = Selection::Teacher;
            selectedTeacherId = rowTeacher[idx];
        }
        else
            return;
        LoadEditor();
        UpdateButtons();
    }

    // ------------------------------------------------------------ editor
    void LoadEditor()
    {
        auto& s = Session();
        loading = true;
        Learning::NoteScope scope = focusScope;
        std::string title, body;
        bool editable      = false;
        bool teacherFields = false;
        Learning::NoteAudience audience = Learning::NoteAudience::All;
        bool enabled                    = true;
        int64 order                     = 0;
        if (selection == Selection::Mine)
        {
            if (const auto* n = s.Notes().Find(selectedId); n != nullptr)
            {
                title    = n->title;
                body     = n->body;
                scope    = n->scope;
                editable = true;
            }
        }
        else if (selection == Selection::Teacher)
        {
            for (const auto& t : s.TeacherNotes())
            {
                if (t.id != selectedTeacherId)
                    continue;
                title    = t.title;
                body     = t.body;
                scope    = t.scope;
                audience = t.audience;
                enabled  = t.enabled;
                order    = t.order;
                editable = teacherFields = s.CanEditTeacherNotes();
            }
        }
        else if (selection == Selection::TeacherDraft)
        {
            editable = teacherFields = s.CanEditTeacherNotes();
        }
        titleField->SetText(Utf8(title));
        bodyArea->SetText(Utf8(body));
        FillScopeCombo(scope);
        editorTitle = title;
        editorBody  = body;
        editorScope = scope;
        audienceCombo->SetCurentItemIndex(static_cast<uint32>(audience));
        enabledCheck->SetChecked(enabled);
        orderField->SetText(std::to_string(order));

        // course notes are read-only for students
        titleField->SetEnabled(editable);
        bodyArea->SetEnabled(selection != Selection::None);
        bodyArea->SetReadOnly(!editable);
        scopeCombo->SetEnabled(editable);
        const bool staff = s.CanEditTeacherNotes();
        for (Control* c : std::initializer_list<Control*>{ lbAudience.operator->(), audienceCombo.operator->(), enabledCheck.operator->(),
                                                           lbOrder.operator->(), orderField.operator->() })
            c->SetVisible(staff);
        audienceCombo->SetEnabled(teacherFields);
        enabledCheck->SetEnabled(teacherFields);
        orderField->SetEnabled(teacherFields);
        loading = false;
        UpdateCounter();
        UpdateStatusLine();
    }

    void UpdateButtons()
    {
        auto& s           = Session();
        const bool usable = s.CanUseNotes();
        const bool staff  = s.CanEditTeacherNotes();
        newButton->SetEnabled(usable);
        deleteButton->SetEnabled(usable && selection == Selection::Mine);
        saveNowButton->SetEnabled(usable);
        refreshButton->SetEnabled(usable);
        newCourseButton->SetVisible(staff);
        saveCourseButton->SetVisible(staff);
        deleteCourseButton->SetVisible(staff);
        saveCourseButton->SetEnabled(staff && !teacherSaving && (selection == Selection::Teacher || selection == Selection::TeacherDraft));
        deleteCourseButton->SetEnabled(staff && !teacherSaving && selection == Selection::Teacher);
    }

    void UpdateCounter()
    {
        const size_t len = Learning::Utf8Length(ToUtf8(bodyArea->GetText()));
        const uint32 max = Session().Notes().MaxChars();
        LocalString<96> tmp;
        tmp.SetFormat("%zu / %u characters", len, max);
        if (len > max)
            tmp.Add("  - too long, it will not be saved!");
        lbCounter->SetText(tmp);
    }

    bool UpdateStatusLine()
    {
        if (!Session().CanUseNotes())
            return false;
        std::string text;
        switch (selection)
        {
        case Selection::None:
            text = "Select a note, or press New note.";
            break;
        case Selection::Teacher:
            text = Session().CanEditTeacherNotes() ? "Course note: edit it, then press Save course note." : "Course note (read-only).";
            break;
        case Selection::TeacherDraft:
            text = teacherSaving ? "Saving the course note..." : "New course note: press Save course note to publish it.";
            break;
        case Selection::Mine:
            if (const auto* n = Session().Notes().Find(selectedId); n != nullptr)
            {
                switch (Session().Notes().StateOf(*n))
                {
                case Learning::NoteSyncState::Saved:
                    text = n->revision.has_value() ? "Saved (revision " + std::to_string(*n->revision) + ")." : "New note: start typing.";
                    break;
                case Learning::NoteSyncState::Unsaved:
                    text = !n->revision.has_value() && !n->createSent && n->title.empty() && n->body.empty() ? "New note: start typing."
                                                                                                           : "Unsaved changes (saved automatically).";
                    break;
                case Learning::NoteSyncState::Saving:
                    text = "Saving...";
                    break;
                case Learning::NoteSyncState::Retrying:
                    text = "Not delivered yet (network) - retrying automatically; the text is kept.";
                    break;
                case Learning::NoteSyncState::Error:
                    text = n->error;
                    break;
                }
            }
            break;
        }
        std::string current;
        lbStatus->GetText().ToString(current);
        if (current == text)
            return false;
        lbStatus->SetText(Utf8(text));
        return true;
    }

    void OnEditorChanged()
    {
        if (loading)
            return;
        UpdateCounter();
        if (selection != Selection::Mine)
            return; // course notes are saved explicitly
        const std::string title = ToUtf8(titleField->GetText());
        const std::string body  = ToUtf8(bodyArea->GetText());
        Session().Notes().Edit(selectedId, title, body, SelectedScope(), NowMs());
        if (const auto* n = Session().Notes().Find(selectedId); n != nullptr)
        {
            if (n->title != editorTitle && selectedRow.IsValid())
                selectedRow.SetText(Utf8(DisplayTitle(n->title)));
            editorTitle = n->title;
            editorBody  = n->body;
            editorScope = n->scope;
        }
        if (taskObject != nullptr && createdHere.count(selectedId) > 0 && (!title.empty() || !body.empty()))
        {
            createdHere.erase(selectedId);
            Session().RecordNoteAdd(taskObject); // a bare count, never the text
        }
        UpdateStatusLine();
    }

    // ------------------------------------------------------------ student actions
    void NewNote()
    {
        if (!Session().CanUseNotes())
            return;
        const auto id = Session().Notes().Create("", "", focusScope, NowMs());
        if (id.empty())
        {
            Dialogs::MessageBox::ShowError("Course notes", "Could not generate a note id.");
            return;
        }
        createdHere.insert(id);
        selection  = Selection::Mine;
        selectedId = id;
        Refresh(true);
        LoadEditor();
        titleField->SetFocus();
    }

    void OpenNoteOfFocusItem()
    {
        if (focusScope.IsGeneral() || !Session().CanUseNotes())
            return;
        if (!Session().NotesLoaded())
            return; // the existing notes are unknown (GetNotes failed): never start a second note for the item blindly
        for (const auto& n : Session().Notes().Notes()) // newest first
        {
            if (!n.deleted && n.scope == focusScope)
            {
                selection  = Selection::Mine;
                selectedId = n.id;
                RebuildList();
                LoadEditor();
                bodyArea->SetFocus();
                return;
            }
        }
        NewNote();
        bodyArea->SetFocus();
    }

    void DeleteSelected()
    {
        if (selection != Selection::Mine)
            return;
        const auto* n = Session().Notes().Find(selectedId);
        if (n == nullptr)
            return;
        const std::string q = "Delete the note \"" + DisplayTitle(n->title) + "\"? It is removed from the course server.";
        if (Dialogs::MessageBox::ShowOkCancel("Delete note", Utf8(q)) != Dialogs::Result::Ok)
            return;
        Session().Notes().Delete(selectedId);
        selection = Selection::None;
        Session().PumpNotes(true);
        Refresh(true);
        LoadEditor();
    }

    // ------------------------------------------------------------ teacher actions (course staff)
    void NewCourseNote()
    {
        if (!Session().CanEditTeacherNotes())
            return;
        selection = Selection::TeacherDraft;
        LoadEditor();
        titleField->SetFocus();
        UpdateButtons();
    }

    void SaveCourseNote()
    {
        auto& s = Session();
        if (!s.CanEditTeacherNotes() || teacherSaving || (selection != Selection::Teacher && selection != Selection::TeacherDraft))
            return;
        Learning::SaveTeacherNoteRequest req;
        req.title    = ToUtf8(titleField->GetText());
        req.body     = ToUtf8(bodyArea->GetText());
        req.scope    = SelectedScope();
        req.audience = static_cast<Learning::NoteAudience>(std::min<uint32>(audienceCombo->GetCurrentItemIndex(), 2));
        req.enabled  = enabledCheck->IsChecked();
        std::string orderText = ToUtf8(orderField->GetText());
        int64 order           = 0;
        bool negative         = !orderText.empty() && orderText[0] == '-';
        for (size_t i = negative ? 1 : 0; i < orderText.size() && i < 10; i++)
        {
            if (orderText[i] < '0' || orderText[i] > '9')
            {
                Dialogs::MessageBox::ShowError("Course note", "Order must be an integer.");
                return;
            }
            order = order * 10 + (orderText[i] - '0');
        }
        req.order = negative ? -order : order;
        if (selection == Selection::Teacher)
        {
            const auto& tn = s.TeacherNotes();
            const auto it  = std::find_if(tn.begin(), tn.end(), [&](const Learning::TeacherNote& t) { return t.id == selectedTeacherId; });
            if (it == tn.end())
                return;
            req.id       = it->id;
            req.revision = it->revision; // compare-and-set: a 409 means another teacher changed it
        }
        std::weak_ptr<bool> weak = alive;
        const bool creating      = selection == Selection::TeacherDraft;
        teacherSaving            = true; // before the call: frontends without frame updates answer inline
        auto st                  = s.SaveTeacherNote(std::move(req), [this, weak, creating](const Learning::NoteOpOutcome& o) {
            auto a = weak.lock();
            if (!a || !*a)
                return;
            teacherSaving = false;
            if (o.status.ok)
            {
                if (creating)
                {
                    selection         = Selection::Teacher; // the new note, once the list is reloaded
                    selectedTeacherId = o.result.teacherId;
                }
                lbStatus->SetText("Course note saved.");
            }
            else if (o.error.code == Learning::ErrorCode::Conflict)
                Dialogs::MessageBox::ShowWarning(
                      "Course note",
                      "Another teacher changed this course note in the meantime. The list now shows the server version; your text is "
                      "still in the editor - press Save course note again to replace the server version with it.");
            else
                Dialogs::MessageBox::ShowError("Course note", "Not saved (your text is still in the editor): " + o.status.message);
            UpdateButtons();
        });
        if (!st.ok)
        {
            teacherSaving = false;
            Dialogs::MessageBox::ShowError("Course note", st.message);
        }
        UpdateButtons();
    }

    void DeleteCourseNote()
    {
        auto& s = Session();
        if (!s.CanEditTeacherNotes() || selection != Selection::Teacher)
            return;
        if (Dialogs::MessageBox::ShowOkCancel("Delete course note", "Delete this course note for every student?") != Dialogs::Result::Ok)
            return;
        std::weak_ptr<bool> weak = alive;
        teacherSaving            = true;
        auto st                  = s.DeleteTeacherNote(selectedTeacherId, [this, weak](const Learning::NoteOpOutcome& o) {
            auto a = weak.lock();
            if (!a || !*a)
                return;
            teacherSaving = false;
            if (!o.status.ok && o.error.code != Learning::ErrorCode::NotFound)
                Dialogs::MessageBox::ShowError("Course note", "Not deleted: " + o.status.message);
            UpdateButtons();
        });
        if (!st.ok)
        {
            teacherSaving = false;
            Dialogs::MessageBox::ShowError("Course note", st.message);
        }
        UpdateButtons();
    }
};

Learning::NoteScope ScopeOfItem(std::string_view item, bool problem)
{
    if (item.empty() || !Learning::IsValidItemName(item))
        return {};
    return { problem ? Learning::NoteScopeKind::Problem : Learning::NoteScopeKind::Resource, std::string(item) };
}
} // namespace

void GView::App::ShowLearningNotesWindow(std::string_view focusItem, bool focusIsProblem, const void* taskObject, bool openNoteForItem)
{
    auto& session = Learning::GetSession();
    switch (session.GetNotesAvailability())
    {
    case Learning::NotesAvailability::Absent:
        Dialogs::MessageBox::ShowError("Course notes", "This course server does not provide course notes.");
        return;
    case Learning::NotesAvailability::DisabledByPolicy:
    case Learning::NotesAvailability::DisabledByServer:
        Dialogs::MessageBox::ShowNotification("Course notes", std::string(DISABLED_TEXT));
        return;
    case Learning::NotesAvailability::Unavailable:
        Dialogs::MessageBox::ShowError(
              "Course notes",
              session.GetState() == Learning::SessionState::Expired ? "The course policy has expired: course notes are not available."
                                                                     : "Course notes are not available in the current session state.");
        return;
    case Learning::NotesAvailability::Available:
        break;
    }
    std::string title(focusItem);
    if (const auto* it = session.GetCatalogue().Find(focusItem, focusIsProblem); it != nullptr)
        title = it->title;
    LearningNotesWindow dlg(ScopeOfItem(focusItem, focusIsProblem), title, taskObject, openNoteForItem);
    dlg.Show();
}

bool GView::Security::Learning::Hooks::OpenNoteForObject(const GView::Object* obj)
{
    auto& session = Learning::GetSession();
    const auto* b = session.FindBinding(obj);
    if (b == nullptr)
        return false; // not a window opened from the course catalogue: the local note, as outside Learning mode
    if (session.GetNotesAvailability() == Learning::NotesAvailability::Absent)
        return false; // server without course notes
    const std::string item = b->item;
    const bool problem     = b->problem;
    GView::App::ShowLearningNotesWindow(item, problem, obj, true);
    return true;
}
