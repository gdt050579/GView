// Course work and teacher solutions of Learning and Evaluation Mode (spec §10.12): the "Course" menu of a task window
// (F12), saving / resuming the student's work, the close prompt, publishing a solution (course staff), and the
// windows of a teacher's solution (compare side by side, replay).
//
// Every request is started from a modal LearningJobDialog that pumps the session itself (task windows only Tick the session;
// the desktop drains completions once per frame) and copes with frontends without frame updates, where the request runs
// inline and its answer is there before the dialog would be shown.

#include "Internal.hpp"
#include "LearningCourse.hpp"
#include "Learning/LearningSession.hpp"
#include "Learning/LearningFormat.hpp"
#include "DissasmViewer.hpp"
#include "DissasmReplayRecorder.hpp"
#include "DissasmReplayController.hpp"
#include "DissasmWorkDocument.hpp"

#include <nlohmann/json.hpp>

#include <cstring>
#include <memory>
#include <optional>

#undef MessageBox

using namespace GView::App;
using namespace AppCUI::Application;
using namespace AppCUI::Controls;
using namespace AppCUI::Utils;
namespace Learning = GView::Security::Learning;
namespace DV       = GView::View::DissasmViewer;
using Learning::WorkspaceRole;
using GView::App::Course::CourseAction;
using GView::App::Course::CourseMenuContext;
using GView::App::Course::CourseMenuRow;
using GView::App::Course::WorkState;

// ================================================================================== the menu model (pure) ===
std::vector<CourseMenuRow> GView::App::Course::BuildCourseMenuRows(const CourseMenuContext& ctx)
{
    std::vector<CourseMenuRow> rows;
    if (ctx.role == WorkspaceRole::Solution || ctx.role == WorkspaceRole::Replay)
    {
        rows.push_back({ CourseAction::CloseSolutionWindow,
                         "Close solution window",
                         ctx.role == WorkspaceRole::Replay ? "the replay of the teacher's solution" : "the teacher's solution (read only)",
                         true });
        return rows;
    }

    const bool workOn = ctx.work == WorkState::Available;
    std::string why;
    if (ctx.work == WorkState::Disabled)
        why = "disabled by your teacher";
    else if (ctx.work == WorkState::NotConnected)
        why = "not connected to the course";
    else if (!ctx.hasDissasmView)
        why = "this window has no disassembly view";
    const bool canWork = workOn && ctx.hasDissasmView;

    if (ctx.work != WorkState::Hidden)
    {
        CourseMenuRow save{ CourseAction::SaveWork, "Save work to course", "", canWork };
        if (!canWork)
            save.detail = why;
        else if (ctx.documentSize > 0)
        {
            save.detail = Learning::FormatSize(ctx.documentSize);
            if (ctx.replaySteps > 0)
                save.detail += ", " + std::to_string(ctx.replaySteps) + " replay steps";
        }
        else
            save.detail = "names, comments and the replay journal";
        rows.push_back(std::move(save));

        CourseMenuRow resume{ CourseAction::ResumeWork, "Resume work from course", "", canWork && ctx.workSavedAt != 0 };
        if (!canWork)
            resume.detail = why;
        else if (ctx.workSavedAt == 0)
            resume.detail = "(no saved work)";
        else
            resume.detail = "saved " + Learning::FormatLocalTime(ctx.workSavedAt);
        rows.push_back(std::move(resume));

        // the solution windows need the course session (GetSolution), not the disassembly view of this window
        const std::string solutionWhy = ctx.work == WorkState::Disabled ? "disabled by your teacher" : "not connected to the course";
        if (ctx.solutionAvailable)
        {
            rows.push_back({ CourseAction::CompareSolution,
                             "Compare with the teacher's solution",
                             workOn ? "side by side, read only" : solutionWhy,
                             workOn });
            if (ctx.solutionHasReplay)
                rows.push_back({ CourseAction::ReplaySolution,
                                 "Replay the teacher's solution",
                                 workOn ? "step by step: Alt+Left / Alt+Right" : solutionWhy,
                                 workOn });
        }
    }
    if (ctx.notesAvailable)
        rows.push_back({ CourseAction::CourseNote, "Course note", "your note of this task", true });
    if (ctx.canSubmit)
        rows.push_back({ CourseAction::SubmitFlag, "Submit flag", "", true });
    if (ctx.canPublishSolutions)
        rows.push_back({ CourseAction::PublishSolution,
                         "Publish solution...",
                         ctx.hasDissasmView ? "course staff: this window as the solution" : "this window has no disassembly view",
                         ctx.hasDissasmView });
    if (ctx.courseStaff)
        rows.push_back({ CourseAction::EditReplayJournal,
                         "Edit replay journal...",
                         ctx.hasDissasmView ? "course staff: remove steps before publishing" : "this window has no disassembly view",
                         ctx.hasDissasmView });
    return rows;
}

namespace
{
constexpr int BTN_FIRST  = 1;
constexpr int BTN_SECOND = 2;
constexpr int BTN_THIRD  = 3;

std::u8string_view AsU8(std::string_view utf8)
{
    return std::u8string_view(reinterpret_cast<const char8_t*>(utf8.data()), utf8.size());
}

void ShowError(std::string_view title, std::string_view message)
{
    Dialogs::MessageBox::ShowError(title, AsU8(message));
}

void ShowInfo(std::string_view title, std::string_view message)
{
    Dialogs::MessageBox::ShowNotification(title, AsU8(message));
}

// the message of a failed request (the session's status, or what the error envelope says)
std::string FailureText(const GView::Utils::GStatus& status, const Learning::ServerError& error)
{
    if (!status.message.empty())
        return status.message;
    return Learning::DescribeError(error);
}

// ---------------------------------------------------------------------------------- LearningJobDialog
// A modal progress dialog with Cancel while one request of the session runs; it pumps the session itself
class LearningJobDialog : public Window
{
    std::shared_ptr<bool> done;

  public:
    LearningJobDialog(std::string_view title, std::string_view message, std::shared_ptr<bool> finished)
        : Window(title, "d:c,w:66,h:8", WindowFlags::None), done(std::move(finished))
    {
        Factory::Label::Create(this, AsU8(message), "l:2,t:1,r:2,h:2");
        Factory::Button::Create(this, "&Cancel", "l:26,b:0,w:13", BTN_SECOND);
    }

    bool OnFrameUpdate() override
    {
        auto& s = Learning::GetSession();
        s.NotifyFrameUpdatesAvailable();
        bool repaint = s.DrainCompletions() > 0;
        s.Tick();
        if (*done)
        {
            Exit(Dialogs::Result::Ok);
            return true;
        }
        return repaint;
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if ((eventType == Event::ButtonClicked && id == BTN_SECOND) || eventType == Event::WindowClose)
        {
            Exit(Dialogs::Result::Cancel); // the request goes on; its answer is dropped
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }
};

// Starts one request: start(finished) returns the session's refusal (shown, false) or Ok; the callback of the request stores
// its result and calls finished(). True when the answer arrived (also before the dialog: the request ran inline), false when
// it was refused or cancelled (a late answer only lands in the caller's shared result, which nobody reads any more).
template <typename Start>
bool RunLearningJob(std::string_view title, std::string_view message, Start&& start)
{
    auto done     = std::make_shared<bool>(false);
    const auto st = start([done]() { *done = true; });
    if (!st.ok)
    {
        ShowError(title, st.message);
        return false;
    }
    if (*done)
        return true;
    LearningJobDialog dlg(title, message, done);
    dlg.Show();
    return *done;
}

template <typename T>
using Box = std::shared_ptr<std::optional<T>>;

// ---------------------------------------------------------------------------------- a question with up to 3 answers
class ChoiceDialog : public Window
{
    int choice{ -1 };

  public:
    // labels: 2 or 3 buttons; the last one is the Cancel answer (also Escape / the close button)
    ChoiceDialog(std::string_view title, std::string_view message, std::initializer_list<std::string_view> labels)
        : Window(title, "d:c,w:78,h:10", WindowFlags::None)
    {
        Factory::Label::Create(this, AsU8(message), "l:2,t:1,r:2,h:4");
        const int count = static_cast<int>(labels.size());
        int x           = count == 3 ? 3 : 18;
        int id          = BTN_FIRST;
        Reference<Button> first;
        for (const auto label : labels)
        {
            LocalString<32> layout;
            layout.SetFormat("l:%d,b:0,w:22", x);
            auto b = Factory::Button::Create(this, label, layout.GetText(), id++);
            if (!first.IsValid())
                first = b;
            x += 24;
        }
        cancelId = count;
        if (first.IsValid())
            first->SetFocus();
    }
    int cancelId{ 0 };

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::ButtonClicked)
        {
            choice = id;
            Exit(Dialogs::Result::Ok);
            return true;
        }
        if (eventType == Event::WindowClose)
        {
            choice = cancelId;
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }
    // 1-based: the button chosen (the last one: cancel)
    int Ask()
    {
        Show();
        return choice < 0 ? cancelId : choice;
    }
};

// ---------------------------------------------------------------------------------- the window of the command
struct TaskWindow {
    FileWindow* window{ nullptr };
    GView::Object* object{ nullptr };
    std::string item; // the problem
    Learning::DeliveryMode mode{ Learning::DeliveryMode::File };
    uint32 version{ 0 };
    WorkspaceRole role{ WorkspaceRole::Normal };
    DV::Instance* view{ nullptr }; // its disassembly view (nullptr: none)
};

bool GetTaskWindow(FileWindow* window, TaskWindow& out)
{
    if (window == nullptr || window->GetObjectPtr() == nullptr)
        return false;
    const auto* binding = Learning::GetSession().FindBinding(window->GetObjectPtr());
    if (binding == nullptr || !binding->problem)
        return false;
    out.window  = window;
    out.object  = window->GetObjectPtr();
    out.item    = binding->item;
    out.mode    = binding->mode;
    out.version = binding->version;
    out.role    = binding->role;
    out.view    = window->FindDissasmView();
    return true;
}

const Learning::CatalogueItem* CatalogueItemOf(std::string_view problem)
{
    return Learning::GetSession().GetCatalogue().Find(problem, true);
}

// the work document of the window (empty: nothing analysed yet; the error was shown)
std::string BuildDocument(const TaskWindow& task, std::string_view kind, bool includeReplay)
{
    DV::DissasmWorkMeta meta;
    meta.kind          = std::string(kind);
    meta.clientVersion = Learning::ClientVersion();
    meta.savedAt       = Learning::NowUnix();
    meta.problem       = task.item;
    meta.itemVersion   = task.version;
    if (const auto* item = CatalogueItemOf(task.item); item != nullptr)
        meta.sha256 = item->sha256;
    return task.view->BuildWorkDocumentText(meta, includeReplay);
}

uint32 ReplayStepsOf(DV::Instance* view)
{
    auto* recorder = view != nullptr ? view->GetReplayRecorder() : nullptr;
    return recorder != nullptr ? static_cast<uint32>(recorder->Journal().events.size()) : 0;
}

// what a work document holds (shown before it is sent)
struct DocumentCounts {
    size_t names{ 0 }, comments{ 0 }, variables{ 0 }, zones{ 0 }, bookmarks{ 0 };
};
DocumentCounts CountDocument(std::string_view json)
{
    DocumentCounts c;
    const auto doc = nlohmann::json::parse(json.begin(), json.end(), nullptr, false);
    if (doc.is_discarded() || !doc.is_object() || !doc.contains("zones") || !doc["zones"].is_array())
        return c;
    const auto count = [](const nlohmann::json& zone, const char* key) -> size_t {
        const auto it = zone.find(key);
        return it != zone.end() && (it->is_array() || it->is_object()) ? it->size() : 0;
    };
    for (const auto& zone : doc["zones"])
    {
        if (!zone.is_object())
            continue;
        c.names += count(zone, "names");
        c.comments += count(zone, "comments") + count(zone, "repeatableComments");
        c.variables += count(zone, "variables");
        c.zones += count(zone, "collapsibleZones");
        c.bookmarks += count(zone, "bookmarks");
    }
    return c;
}

std::string WorkUnavailableText()
{
    switch (Learning::GetSession().GetWorkAvailability())
    {
    case Learning::WorkAvailability::Absent:
        return "This course server does not store course work.";
    case Learning::WorkAvailability::DisabledByPolicy:
    case Learning::WorkAvailability::DisabledByServer:
        return "Saving course work is disabled by your teacher.";
    case Learning::WorkAvailability::Unavailable:
        return "The course session is not active: reconnect in the Learning and Evaluation Mode window.";
    default:
        return {};
    }
}

bool CheckWorkWindow(const TaskWindow& task, std::string_view title)
{
    if (!Learning::GetSession().CanUseWork())
    {
        ShowError(title, WorkUnavailableText());
        return false;
    }
    if (task.view == nullptr)
    {
        ShowError(title, "This window has no disassembly view: the course work is made of its names, comments and replay journal.");
        return false;
    }
    if (task.view->IsReadOnlyRole())
    {
        ShowError(title, "This window shows the teacher's solution.");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------- resume
// a saved work made on another version of the task file: asked first
bool ConfirmDocumentFile(const TaskWindow& task, std::string_view document, std::string_view title)
{
    const auto json = nlohmann::json::parse(document.begin(), document.end(), nullptr, false);
    if (json.is_discarded())
        return true; // ApplyWorkDocument reports it
    DV::DissasmWorkDocument parsed;
    std::string error;
    if (!DV::ParseWorkDocument(json, parsed, error))
        return true;
    const auto* item = CatalogueItemOf(task.item);
    if (item == nullptr || item->sha256.empty() || parsed.meta.sha256.empty() || parsed.meta.sha256 == item->sha256)
        return true;
    return Dialogs::MessageBox::ShowOkCancel(
                 title,
                 "The saved work was made on another version of the task file: some names and comments may not match this "
                 "analysis (they are skipped). Load it anyway?") == Dialogs::Result::Ok;
}

// the work of the server added to the window; the window is clean afterwards (it shows what the server has)
bool ApplyServerWork(const TaskWindow& task, const Learning::WorkResponse& work, bool showSummary)
{
    if (!ConfirmDocumentFile(task, work.document, "Resume work"))
        return false;
    if (!task.view->HasAnalysedCodeZones())
    {
        // the zones are analysed when they are drawn: the document waits for it (ApplyPendingWorkDocument)
        task.view->QueueWorkDocument(work.document);
        task.window->ShowDissasmView();
        if (showSummary)
            ShowInfo("Resume work", "The saved work is loaded as soon as the disassembly is shown.");
        return true;
    }
    std::string summary;
    if (!task.view->ApplyWorkDocument(work.document, DV::DissasmReplayImportSource::ServerWork, &summary))
    {
        ShowError("Resume work", summary.empty() ? std::string_view("The saved work could not be loaded.") : std::string_view(summary));
        return false;
    }
    task.view->MarkCourseWorkSaved(static_cast<uint64>(work.revision));
    if (showSummary)
    {
        std::string text = "Saved work loaded (revision " + std::to_string(work.revision);
        if (work.updatedAt != 0)
            text += ", saved " + Learning::FormatLocalTime(work.updatedAt);
        text += ").\n" + summary;
        ShowInfo("Resume work", text);
    }
    return true;
}

// GetWork behind a progress dialog; nullopt: refused / cancelled / failed (shown)
std::optional<Learning::WorkResponse> FetchWork(std::string_view problem, std::string_view title)
{
    Box<Learning::WorkResult> box = std::make_shared<std::optional<Learning::WorkResult>>();
    const std::string name(problem);
    if (!RunLearningJob(title, "Asking the course server for your saved work...", [&](auto finished) {
            return Learning::GetSession().GetWork(name, [box, finished](Learning::WorkResult& r) {
                *box = std::move(r);
                finished();
            });
        }))
        return std::nullopt;
    if (!box->has_value())
        return std::nullopt;
    auto& r = box->value();
    if (!r.status.ok)
    {
        ShowError(title, FailureText(r.status, r.error));
        return std::nullopt;
    }
    return std::move(r.response);
}

bool ResumeWork(const TaskWindow& task, bool ask)
{
    if (!CheckWorkWindow(task, "Resume work"))
        return false;
    if (ask && Dialogs::MessageBox::ShowOkCancel(
                     "Resume work",
                     "Add the saved work to this window? Existing names and comments are kept; where both have one, the saved "
                     "work wins.") != Dialogs::Result::Ok)
        return false;
    const auto work = FetchWork(task.item, "Resume work");
    if (!work.has_value())
        return false;
    if (!work->workError.empty())
    {
        ShowError("Resume work", "The saved work can not be loaded: " + work->workError);
        return false;
    }
    if (!work->hasWork || work->document.empty())
    {
        ShowInfo("Resume work", "There is no saved work for this problem on the course server.");
        return false;
    }
    return ApplyServerWork(task, *work, true);
}

// ---------------------------------------------------------------------------------- save
enum class SaveResult : uint8 { Saved, NotSaved };

// SaveWork with the conflict path; `savedText`: "Saved: revision N (size) at time"
SaveResult SaveDocument(const TaskWindow& task, const std::string& document, bool hasReplay, uint32 steps, std::string& savedText)
{
    auto& session = Learning::GetSession();
    if (document.size() > session.WorkMaxBytes())
    {
        ShowError(
              "Save work",
              "The work document is " + Learning::FormatSize(document.size()) + ", above the limit of the course (" +
                    Learning::FormatSize(session.WorkMaxBytes()) + "). Save it without the replay journal, or remove steps from it.");
        return SaveResult::NotSaved;
    }
    for (int attempt = 0; attempt < 2; attempt++)
    {
        Box<Learning::SaveWorkOutcome> box = std::make_shared<std::optional<Learning::SaveWorkOutcome>>();
        if (!RunLearningJob("Save work", "Saving your work to the course server...", [&](auto finished) {
                return session.SaveWork(task.item, document, hasReplay, steps, [box, finished](const Learning::SaveWorkOutcome& o) {
                    *box = o;
                    finished();
                });
            }))
            return SaveResult::NotSaved;
        if (!box->has_value())
            return SaveResult::NotSaved;
        const auto& o = box->value();
        if (o.status.ok)
        {
            task.view->MarkCourseWorkSaved(static_cast<uint64>(o.result.revision));
            savedText = "Saved: revision " + std::to_string(o.result.revision) + " (" + Learning::FormatSize(document.size()) + ") at " +
                        Learning::FormatLocalTime(o.result.updatedAt != 0 ? o.result.updatedAt : Learning::NowUnix());
            return SaveResult::Saved;
        }
        if (attempt == 0 && o.error.code == Learning::ErrorCode::NotFound)
            continue; // the work was deleted on the website: the session forgot its revision, this save creates
        if (!o.conflict || attempt > 0)
        {
            ShowError("Save work", o.conflict ? "The work was saved elsewhere again in the meantime; nothing was written." : FailureText(o.status, o.error));
            return SaveResult::NotSaved;
        }
        // 409: another computer saved in the meantime. GetWork tells when (and refreshes the revision for an overwrite)
        const auto server = FetchWork(task.item, "Save work");
        if (!server.has_value())
            return SaveResult::NotSaved;
        std::string message = "The server has a newer version of your work";
        if (server->updatedAt != 0)
            message += " (saved " + Learning::FormatLocalTime(server->updatedAt) + ")";
        message += ".\n\nKeep server copy: load it into this window (your changes stay, the server's win where both have one).\n"
                   "Overwrite: replace it with the work of this window.";
        ChoiceDialog ask("Save work", message, { "&Keep server copy", "&Overwrite", "&Cancel" });
        const int choice = ask.Ask();
        if (choice == BTN_FIRST)
        {
            if (!server->workError.empty())
                ShowError("Save work", "The server copy can not be loaded: " + server->workError);
            else if (server->hasWork && !server->document.empty())
                ApplyServerWork(task, *server, true);
            return SaveResult::NotSaved;
        }
        if (choice != BTN_SECOND)
            return SaveResult::NotSaved;
        // Overwrite: GetWork cached the server's revision, the next SaveWork replaces it
    }
    return SaveResult::NotSaved;
}

class SaveWorkDialog : public Window
{
    const TaskWindow& task;
    std::string withReplay, withoutReplay;
    uint32 steps;
    Reference<CheckBox> includeReplay;
    Reference<Label> sizeLabel, resultLabel;
    Reference<Button> saveButton;

    const std::string& Document()
    {
        return includeReplay->IsChecked() ? withReplay : withoutReplay;
    }
    void UpdateSize()
    {
        const size_t size = Document().size();
        const size_t max  = Learning::GetSession().WorkMaxBytes();
        std::string text  = "Size: " + Learning::FormatSize(size) + " (the course accepts up to " + Learning::FormatSize(max) + ")";
        if (size > max)
            text += " - too large!";
        sizeLabel->SetText(AsU8(text));
    }

  public:
    bool saved{ false };

    SaveWorkDialog(const TaskWindow& t, std::string replayDocument, std::string plainDocument, uint32 replaySteps)
        : Window("Save work to course", "d:c,w:80,h:14", WindowFlags::None), task(t), withReplay(std::move(replayDocument)),
          withoutReplay(std::move(plainDocument)), steps(replaySteps)
    {
        const auto c       = CountDocument(withoutReplay);
        std::string title  = "Problem: " + task.item;
        if (const auto* item = CatalogueItemOf(task.item); item != nullptr && !item->title.empty() && item->title != task.item)
            title += " - " + item->title;
        Factory::Label::Create(this, AsU8(title), "l:2,t:1,r:2,h:1");
        const std::string counts = "Names: " + std::to_string(c.names) + ", comments: " + std::to_string(c.comments) + ", variables: " +
                                   std::to_string(c.variables) + ", collapsible zones: " + std::to_string(c.zones) +
                                   ", bookmarks: " + std::to_string(c.bookmarks);
        Factory::Label::Create(this, AsU8(counts), "l:2,t:2,r:2,h:1");
        const std::string replayCaption = "Include replay journal (" + std::to_string(steps) + " steps)";
        includeReplay                   = Factory::CheckBox::Create(this, AsU8(replayCaption), "l:2,t:4,r:2", BTN_THIRD);
        includeReplay->SetChecked(steps > 0);
        includeReplay->SetEnabled(steps > 0);
        sizeLabel   = Factory::Label::Create(this, "", "l:2,t:6,r:2,h:1");
        resultLabel = Factory::Label::Create(this, "Only your names, comments, variables, zones and the replay journal are sent.", "l:2,t:8,r:2,h:2");
        saveButton  = Factory::Button::Create(this, "&Save", "l:20,b:0,w:14", BTN_FIRST);
        Factory::Button::Create(this, "&Close", "l:42,b:0,w:14", BTN_SECOND);
        UpdateSize();
        saveButton->SetFocus();
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::CheckedStatusChanged)
        {
            UpdateSize();
            return true;
        }
        if (eventType == Event::ButtonClicked && id == BTN_FIRST)
        {
            std::string text;
            const bool replay = includeReplay->IsChecked() && steps > 0;
            if (SaveDocument(task, Document(), replay, replay ? steps : 0, text) == SaveResult::Saved)
            {
                saved = true;
                resultLabel->SetText(AsU8(text));
                saveButton->SetEnabled(false);
            }
            return true;
        }
        if ((eventType == Event::ButtonClicked && id == BTN_SECOND) || eventType == Event::WindowClose)
        {
            Exit(saved ? Dialogs::Result::Ok : Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }
};

void SaveWork(const TaskWindow& task)
{
    if (!CheckWorkWindow(task, "Save work"))
        return;
    std::string withReplay = BuildDocument(task, "work", true);
    if (withReplay.empty())
    {
        ShowError("Save work", "The disassembly is not analysed yet: show the disassembly view once, then save again.");
        return;
    }
    std::string withoutReplay = BuildDocument(task, "work", false);
    SaveWorkDialog dlg(task, std::move(withReplay), std::move(withoutReplay), ReplayStepsOf(task.view));
    dlg.Show();
}

// ---------------------------------------------------------------------------------- publish (course staff)
class PublishSolutionDialog : public Window
{
    const TaskWindow& task;
    std::string withReplay, withoutReplay;
    uint32 steps;
    std::vector<Learning::NoteAudience> audiences;
    Reference<ComboBox> audienceCombo;
    Reference<CheckBox> includeReplay;
    Reference<Label> sizeLabel, resultLabel;

    const std::string& Document()
    {
        return includeReplay->IsChecked() ? withReplay : withoutReplay;
    }
    Learning::NoteAudience Audience()
    {
        const uint32 index = audienceCombo->GetCurrentItemIndex();
        return index < audiences.size() ? audiences[index] : Learning::NoteAudience::All;
    }
    static std::string AudienceCaption(Learning::NoteAudience a)
    {
        return a == Learning::NoteAudience::All ? std::string("All students") : "Group " + std::string(Learning::NoteAudienceName(a));
    }
    void UpdateSize()
    {
        const size_t size = Document().size();
        const size_t max  = Learning::GetSession().WorkMaxBytes();
        std::string text  = "Size: " + Learning::FormatSize(size) + " (up to " + Learning::FormatSize(max) + ")";
        if (size > max)
            text += " - too large!";
        sizeLabel->SetText(AsU8(text));
    }

  public:
    PublishSolutionDialog(const TaskWindow& t, std::string replayDocument, std::string plainDocument, uint32 replaySteps)
        : Window("Publish solution", "d:c,w:80,h:15", WindowFlags::None), task(t), withReplay(std::move(replayDocument)),
          withoutReplay(std::move(plainDocument)), steps(replaySteps), audiences(Learning::GetSession().SolutionAudiences())
    {
        Factory::Label::Create(this, AsU8("Problem: " + task.item + " - the annotations of this window are the solution"), "l:2,t:1,r:2,h:1");
        Factory::Label::Create(this, "Audience:", "l:2,t:3,w:10");
        std::string items;
        for (const auto a : audiences)
        {
            if (!items.empty())
                items += ",";
            items += AudienceCaption(a);
        }
        audienceCombo = Factory::ComboBox::Create(this, "l:13,t:3,w:24", items);
        audienceCombo->SetCurentItemIndex(0);
        const std::string replayCaption = "Include replay (" + std::to_string(steps) + " steps)";
        includeReplay                   = Factory::CheckBox::Create(this, AsU8(replayCaption), "l:2,t:5,r:2", BTN_THIRD);
        includeReplay->SetChecked(steps > 0);
        includeReplay->SetEnabled(steps > 0);
        sizeLabel   = Factory::Label::Create(this, "", "l:2,t:7,r:2,h:1");
        resultLabel = Factory::Label::Create(this, "", "l:2,t:9,r:2,h:2");
        Factory::Button::Create(this, "&Publish", "l:20,b:0,w:14", BTN_FIRST);
        Factory::Button::Create(this, "&Close", "l:42,b:0,w:14", BTN_SECOND);
        UpdateSize();
    }

    bool OnEvent(Reference<Control> c, Event eventType, int id) override
    {
        if (eventType == Event::CheckedStatusChanged)
        {
            UpdateSize();
            return true;
        }
        if (eventType == Event::ButtonClicked && id == BTN_FIRST)
        {
            Publish();
            return true;
        }
        if ((eventType == Event::ButtonClicked && id == BTN_SECOND) || eventType == Event::WindowClose)
        {
            Exit(Dialogs::Result::Cancel);
            return true;
        }
        return Window::OnEvent(c, eventType, id);
    }

  private:
    void Publish()
    {
        auto& session = Learning::GetSession();
        if (!session.CanPublishSolutions()) // re-checked: the capability comes from the last GetWork
        {
            ShowError("Publish solution", "Only course staff can publish solutions.");
            return;
        }
        const auto& document = Document();
        if (document.size() > session.WorkMaxBytes())
        {
            ShowError("Publish solution", "The solution is above the size limit of the course: publish it without the replay, or remove steps.");
            return;
        }
        const auto audience = Audience();
        const std::string question =
              "Publish this solution of " + task.item + " for " + AudienceCaption(audience) + "? They can open it from GView (compare" +
              (includeReplay->IsChecked() ? std::string(", replay") : std::string()) + ").";
        if (Dialogs::MessageBox::ShowOkCancel("Publish solution", AsU8(question)) != Dialogs::Result::Ok)
            return;

        Learning::PublishSolutionRequest req;
        req.problem     = task.item;
        req.audience    = audience;
        req.document    = document;
        req.hasReplay   = includeReplay->IsChecked() && steps > 0;
        req.replaySteps = req.hasReplay ? steps : 0;
        req.enabled     = true;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            Box<Learning::PublishOutcome> box = std::make_shared<std::optional<Learning::PublishOutcome>>();
            if (!RunLearningJob("Publish solution", "Publishing the solution...", [&](auto finished) {
                    return session.PublishSolution(req, [box, finished](const Learning::PublishOutcome& o) {
                        *box = o;
                        finished();
                    });
                }))
                return;
            if (!box->has_value())
                return;
            const auto& o = box->value();
            if (o.status.ok)
            {
                const std::string text = "Published: solution #" + std::to_string(o.result.id) + ", revision " +
                                         std::to_string(o.result.revision) + (o.result.created ? " (new)" : "") + " for " +
                                         AudienceCaption(audience) + ".";
                resultLabel->SetText(AsU8(text));
                // the catalogue says "solution" / "solution+replay" (Learning window, student menus); its answer lands in a frame
                session.RefreshCatalogue([](const GView::Utils::GStatus&) {});
                return;
            }
            if (attempt == 0 && o.conflict && o.existingId.has_value())
            {
                // one solution per (problem, audience): replace the existing one with its id / revision
                const std::string replace = "A solution for " + AudienceCaption(audience) + " is already published (#" +
                                            std::to_string(*o.existingId) + "). Replace it?";
                if (Dialogs::MessageBox::ShowOkCancel("Publish solution", AsU8(replace)) != Dialogs::Result::Ok)
                    return;
                req.id       = o.existingId;
                req.revision = o.existingRevision.has_value() ? o.existingRevision : std::optional<int64>(1);
                continue;
            }
            ShowError("Publish solution",
                      o.conflict ? std::string("The solution was changed in the meantime (on the website?): open the dialog again.")
                                 : FailureText(o.status, o.error));
            return;
        }
    }
};

void PublishSolution(const TaskWindow& task)
{
    if (!Learning::GetSession().CanPublishSolutions())
    {
        ShowError("Publish solution", "Only course staff can publish solutions.");
        return;
    }
    if (task.view == nullptr)
    {
        ShowError("Publish solution", "This window has no disassembly view.");
        return;
    }
    std::string withReplay = BuildDocument(task, "solution", true);
    if (withReplay.empty())
    {
        ShowError("Publish solution", "The disassembly is not analysed yet: show the disassembly view once, then publish again.");
        return;
    }
    std::string withoutReplay = BuildDocument(task, "solution", false);
    PublishSolutionDialog dlg(task, std::move(withReplay), std::move(withoutReplay), ReplayStepsOf(task.view));
    dlg.Show();
}

// ---------------------------------------------------------------------------------- the solution windows
FileWindow* AsFileWindow(Reference<Control> control)
{
    return control.IsValid() ? dynamic_cast<FileWindow*>(control.operator->()) : nullptr;
}

// the window bound to `item` with `role` (not `exclude`): the current window first (just opened), then the newest one
FileWindow* FindBoundWindow(std::string_view item, WorkspaceRole role, const FileWindow* exclude)
{
    auto& session      = Learning::GetSession();
    const auto matches = [&](FileWindow* fw) {
        if (fw == nullptr || fw == exclude)
            return false;
        const auto* b = session.FindBinding(fw->GetObjectPtr());
        return b != nullptr && b->problem && b->item == item && b->role == role;
    };
    if (auto* current = AsFileWindow(AppCUI::Application::GetCurrentWindow().ToBase<Control>()); matches(current))
        return current;
    auto desktop = AppCUI::Application::GetDesktop();
    if (!desktop.IsValid())
        return nullptr;
    for (uint32 index = desktop->GetChildrenCount(); index-- > 0;)
        if (auto* fw = AsFileWindow(desktop->GetChild(index)); matches(fw))
            return fw;
    return nullptr;
}

// exactly these two windows side by side (not ArrangeWindows: the other windows stay where they are); the focus on the left one
void TileSideBySide(FileWindow* left, FileWindow* right)
{
    auto desktop = AppCUI::Application::GetDesktop();
    if (!desktop.IsValid())
        return;
    const auto size   = desktop->GetClientSize();
    const int width   = static_cast<int>(size.Width);
    const int height  = static_cast<int>(size.Height);
    if (width < 20 || height < 6)
        return; // too small to split: the windows stay as they are
    const int half = width / 2;
    left->MoveTo(0, 0);
    left->Resize(half, height);
    right->MoveTo(half, 0);
    right->Resize(width - half, height);
    left->SetFocus();
}

struct FetchedSolution {
    std::string document;
    bool hasReplay{ false };
    uint32 replaySteps{ 0 };
};

std::optional<FetchedSolution> FetchSolution(std::string_view problem, bool replay)
{
    const std::string title = replay ? "Replay the teacher's solution" : "Teacher solution";
    Box<Learning::SolutionResult> box = std::make_shared<std::optional<Learning::SolutionResult>>();
    const std::string name(problem);
    if (!RunLearningJob(title, "Downloading the teacher's solution...", [&](auto finished) {
            return Learning::GetSession().GetSolution(name, std::nullopt, [box, finished](Learning::SolutionResult& r) {
                *box = std::move(r);
                finished();
            });
        }))
        return std::nullopt;
    if (!box->has_value())
        return std::nullopt;
    auto& r = box->value();
    if (!r.status.ok)
    {
        ShowError(title, r.error.code == Learning::ErrorCode::NotFound ? std::string("No solution of the teacher is available for you yet.")
                                                                         : FailureText(r.status, r.error));
        return std::nullopt;
    }
    if (replay && !r.solution.info.hasReplay)
    {
        ShowError(title, "This solution has no replay journal: use Compare with the teacher's solution.");
        return std::nullopt;
    }
    return FetchedSolution{ std::move(r.solution.document), r.solution.info.hasReplay, r.solution.info.replaySteps };
}

// the journal of a solution document (Replay); nullopt: none / unreadable (shown)
std::optional<DV::DissasmReplayJournal> JournalOf(const std::string& document)
{
    const auto json = nlohmann::json::parse(document.begin(), document.end(), nullptr, false);
    DV::DissasmWorkDocument parsed;
    std::string error;
    if (json.is_discarded() || !DV::ParseWorkDocument(json, parsed, error))
    {
        ShowError("Replay", error.empty() ? std::string("The solution is not a valid work document.") : error);
        return std::nullopt;
    }
    if (parsed.journal.events.empty())
    {
        ShowError("Replay", "The replay journal of this solution is empty.");
        return std::nullopt;
    }
    return std::move(parsed.journal);
}

struct OpenRequest {
    std::string item;
    uint32 version{ 0 };
    WorkspaceRole role{ WorkspaceRole::Solution };
    std::filesystem::path file;                 // file mode: the task file
    std::unique_ptr<Learning::LockedBuffer> bytes; // memory: a copy of the bytes
    std::u16string name;                        // memory: the name of the window
};

// opens the window of a solution and binds it (role, document); nullptr when it could not be opened (shown)
FileWindow* OpenBoundWindow(OpenRequest& req, const std::string& document, const FileWindow* exclude)
{
    auto& session = Learning::GetSession();
    Learning::ItemBinding binding;
    binding.item    = req.item;
    binding.problem = true;
    binding.mode    = req.bytes ? Learning::DeliveryMode::Memory : Learning::DeliveryMode::File; // a copy in memory: memory-only
    binding.version = req.version;
    session.SetPendingBinding(binding);
    // a Replay window takes only the journal of the document (its annotations come with the steps)
    session.SetPendingWorkDocument(document, req.role);
    bool opened = true;
    if (req.bytes)
    {
        auto data                  = std::make_unique<Learning::LockedMemoryDataObject>(std::move(*req.bytes));
        const std::u16string_view name = req.name;
        opened = GView::App::OpenDataObject(std::move(data), name, name, GView::App::OpenMethod::BestMatch, "", nullptr, "Teacher solution");
    }
    else
        GView::App::OpenFile(req.file, GView::App::OpenMethod::BestMatch, "", nullptr, "Teacher solution");
    session.ClearPendingBinding();
    FileWindow* window = opened ? FindBoundWindow(req.item, req.role, exclude) : nullptr;
    if (window == nullptr)
    {
        ShowError("Teacher solution", "GView could not open the task for the teacher's solution.");
        return nullptr;
    }
    if (const auto* item = CatalogueItemOf(req.item); item != nullptr)
        session.RecordItemOpened(*item, binding.mode, req.version, req.role); // no telemetry for a solution window
    window->ShowDissasmView();
    return window;
}

// the solution window after it was opened: the replay controller (Replay role)
bool PrepareSolutionWindow(FileWindow* window, WorkspaceRole role, const std::string& document)
{
    if (role != WorkspaceRole::Replay)
        return true;
    auto* view = window->FindDissasmView();
    if (view == nullptr)
    {
        ShowError("Replay", "The task has no disassembly view: the replay can not be shown.");
        return false;
    }
    auto journal = JournalOf(document);
    if (!journal.has_value())
        return false;
    view->CreateReplayController(std::move(*journal));
    return true;
}

// a copy of the content of the object (memory-only)
std::unique_ptr<Learning::LockedBuffer> CopyObjectBytes(GView::Object* object)
{
    auto& data        = object->GetData();
    const uint64 size = data.GetSize();
    if (size == 0 || size > Learning::LockedBuffer::MAX_SIZE)
        return nullptr;
    auto buffer = std::make_unique<Learning::LockedBuffer>();
    if (!buffer->Allocate(static_cast<size_t>(size)))
        return nullptr;
    const uint32 chunk = std::max<uint32>(4096u, data.GetCacheSize());
    for (uint64 offset = 0; offset < size;)
    {
        const uint32 part = static_cast<uint32>(std::min<uint64>(chunk, size - offset));
        const auto view   = data.Get(offset, part, true);
        if (view.GetLength() != part)
            return nullptr;
        memcpy(buffer->Data() + offset, view.GetData(), part);
        offset += part;
    }
    return buffer;
}
} // namespace

// ================================================================================== public entry points ===
bool GView::App::OpenSolutionCompare(FileWindow* studentWindow, std::string_view problem, bool replay)
{
    TaskWindow task;
    if (!GetTaskWindow(studentWindow, task) || task.role != WorkspaceRole::Student)
        return false;
    if (!Learning::GetSession().CanUseWork())
    {
        ShowError("Teacher solution", WorkUnavailableText());
        return false;
    }
    auto solution = FetchSolution(problem, replay);
    if (!solution.has_value())
        return false;

    OpenRequest req;
    req.item    = std::string(problem);
    req.version = task.version;
    req.role    = replay ? WorkspaceRole::Replay : WorkspaceRole::Solution;
    // file mode: the same task file (the role keeps the solution window away from the student's .dissasm.cache); memory mode
    // (or a task without a file): a copy of the bytes, memory-only like the task
    const auto path = std::filesystem::path(task.object->GetPath());
    std::error_code ec;
    if (task.mode == Learning::DeliveryMode::File && task.object->GetObjectType() == GView::Object::Type::File && std::filesystem::is_regular_file(path, ec))
        req.file = path;
    else
    {
        req.bytes = CopyObjectBytes(task.object);
        req.name  = std::u16string(task.object->GetName());
        if (!req.bytes)
        {
            ShowError("Teacher solution", "The content of the task could not be copied for the solution window.");
            return false;
        }
    }
    FileWindow* window = OpenBoundWindow(req, solution->document, studentWindow);
    if (window == nullptr)
        return false;
    if (!PrepareSolutionWindow(window, req.role, solution->document))
    {
        window->RemoveMe(); // a replay window without its journal: nothing to show
        return false;
    }
    TileSideBySide(studentWindow, window); // student left, solution right, the focus back on the student
    return true;
}

bool GView::App::Course::OpenSolutionStandalone(
      const Learning::CatalogueItem& item, uint32 itemVersion, const SolutionSource& source, bool replay)
{
    if (!Learning::GetSession().CanUseWork())
    {
        ShowError("Teacher solution", WorkUnavailableText());
        return false;
    }
    auto solution = FetchSolution(item.name, replay);
    if (!solution.has_value())
        return false;
    OpenRequest req;
    req.item    = item.name;
    req.version = itemVersion;
    req.role    = replay ? WorkspaceRole::Replay : WorkspaceRole::Solution;
    if (!source.file.empty())
        req.file = source.file;
    else if (source.bytes != nullptr)
    {
        req.bytes  = std::make_unique<Learning::LockedBuffer>(std::move(*source.bytes));
        const auto name = std::u8string_view(reinterpret_cast<const char8_t*>(source.name.data()), source.name.size());
        LocalUnicodeStringBuilder<256> u16;
        u16.Set(name);
        req.name = std::u16string(u16.ToStringView());
    }
    else
        return false;
    FileWindow* window = OpenBoundWindow(req, solution->document, nullptr);
    if (window == nullptr)
        return false;
    if (!PrepareSolutionWindow(window, req.role, solution->document))
    {
        window->RemoveMe(); // a replay window without its journal: nothing to show
        return false;
    }
    return true;
}

void GView::App::Course::OfferResumeCourseWork(std::string_view itemName, bool ask)
{
    auto& session = Learning::GetSession();
    const auto* item = session.GetCatalogue().Find(itemName, true);
    if (item == nullptr || !session.CanUseWork())
        return;
    if (ask && (!item->hasMe || item->me.workSavedAt == 0))
        return;
    const uint64 savedAt = item->hasMe ? item->me.workSavedAt : 0;
    TaskWindow task;
    if (!GetTaskWindow(FindBoundWindow(itemName, WorkspaceRole::Student, nullptr), task) || task.view == nullptr)
        return;
    if (ask)
    {
        // only an empty window: a window with a cache / edits keeps what it has (Resume from the Course menu adds the saved work)
        if (!task.view->IsCourseStateEmpty() || task.view->HasQueuedWorkDocument())
            return;
        const std::string question =
              "You saved work for this problem on the course server (" + Learning::FormatLocalTime(savedAt) + "). Load it into the task window?";
        if (Dialogs::MessageBox::ShowYesNoCancel("Resume work", AsU8(question)) != Dialogs::Result::Yes)
            return;
    }
    const auto work = FetchWork(task.item, "Resume work");
    if (!work.has_value())
        return;
    if (!work->workError.empty())
    {
        ShowError("Resume work", "The saved work can not be loaded: " + work->workError);
        return;
    }
    if (!work->hasWork || work->document.empty())
    {
        if (!ask)
            ShowInfo("Resume work", "There is no saved work for this problem on the course server.");
        return;
    }
    if (!ConfirmDocumentFile(task, work->document, "Resume work"))
        return;
    // the window was just opened: its zones are analysed at its first paint, the document waits for it (the window is clean then)
    task.view->QueueWorkDocument(work->document);
    task.window->ShowDissasmView();
}

bool GView::App::ConfirmCloseCourseWorkWindow(FileWindow* window)
{
    TaskWindow task;
    if (!GetTaskWindow(window, task) || task.role != WorkspaceRole::Student || task.view == nullptr)
        return true;
    if (!task.view->HasUnsavedCourseChanges() || !Learning::GetSession().CanUseWork())
        return true; // nothing to save, or it can not be saved now (the local cache keeps it)
    ChoiceDialog ask(
          "Course work",
          "Your work on " + task.item + " has changes that are not saved on the course server.\n\nSave them before closing the window?",
          { "&Save and close", "Close &without saving", "&Cancel" });
    switch (ask.Ask())
    {
    case BTN_FIRST:
    {
        std::string document = BuildDocument(task, "work", true);
        if (document.empty())
            return true; // nothing analysed: nothing to save
        const uint32 steps = ReplayStepsOf(task.view);
        bool withReplay    = steps > 0;
        if (document.size() > Learning::GetSession().WorkMaxBytes())
        {
            document   = BuildDocument(task, "work", false); // too large with the journal: the annotations at least
            withReplay = false;
        }
        std::string text;
        return SaveDocument(task, document, withReplay, withReplay ? steps : 0, text) == SaveResult::Saved;
    }
    case BTN_SECOND:
        return true;
    default:
        return false;
    }
}

void GView::App::ShowLearningCourseMenu(FileWindow* window)
{
    TaskWindow task;
    if (!GetTaskWindow(window, task))
        return;
    auto& session = Learning::GetSession();

    CourseMenuContext ctx;
    ctx.role           = task.role;
    ctx.hasDissasmView = task.view != nullptr;
    switch (session.GetWorkAvailability())
    {
    case Learning::WorkAvailability::Absent:
        ctx.work = WorkState::Hidden;
        break;
    case Learning::WorkAvailability::DisabledByPolicy:
    case Learning::WorkAvailability::DisabledByServer:
        ctx.work = WorkState::Disabled;
        break;
    case Learning::WorkAvailability::Unavailable:
        ctx.work = WorkState::NotConnected;
        break;
    case Learning::WorkAvailability::Available:
        ctx.work = WorkState::Available;
        break;
    }
    if (const auto* item = CatalogueItemOf(task.item); item != nullptr)
    {
        ctx.workSavedAt       = item->hasMe ? item->me.workSavedAt : 0;
        ctx.solutionAvailable = item->solutionAvailable;
        ctx.solutionHasReplay = item->solutionHasReplay;
    }
    ctx.canPublishSolutions = session.CanPublishSolutions();
    ctx.courseStaff         = session.IsCourseStaff();
    ctx.notesAvailable      = session.CanUseNotes();
    ctx.canSubmit           = session.CanSubmit() && task.role == WorkspaceRole::Student;
    if (task.view != nullptr && task.role == WorkspaceRole::Student && task.view->HasAnalysedCodeZones())
    {
        ctx.replaySteps = ReplayStepsOf(task.view); // the size of the document is known once it is built (the Save dialog)
    }
    const auto rows = Course::BuildCourseMenuRows(ctx);
    if (rows.empty())
    {
        ShowInfo("Course", "There is no course command for this window.");
        return;
    }

    // ---- the menu
    class CourseMenuDialog : public Window
    {
        Reference<ListView> list;
        const std::vector<CourseMenuRow>& rows;

      public:
        std::optional<size_t> chosen;
        CourseMenuDialog(const std::vector<CourseMenuRow>& r, std::string_view problem)
            : Window("Course", "d:c,w:96,h:16", WindowFlags::None), rows(r)
        {
            Factory::Label::Create(this, AsU8("Task: " + std::string(problem)), "l:1,t:0,r:1,h:1");
            list = Factory::ListView::Create(this, "l:1,t:1,r:1,b:3", { "n:Command,w:40", "n:Details,w:52" }, ListViewFlags::None);
            for (size_t index = 0; index < rows.size(); index++)
            {
                auto item = list->AddItem({ std::string_view(rows[index].caption), std::string_view(rows[index].detail) });
                item.SetData(static_cast<uint64>(index));
                if (!rows[index].enabled)
                    item.SetType(ListViewItem::Type::GrayedOut);
            }
            Factory::Button::Create(this, "&Run", "l:30,b:0,w:12", BTN_FIRST);
            Factory::Button::Create(this, "&Close", "l:50,b:0,w:12", BTN_SECOND);
            list->SetFocus();
        }
        bool OnEvent(Reference<Control> c, Event eventType, int id) override
        {
            if (eventType == Event::ListViewItemPressed || (eventType == Event::ButtonClicked && id == BTN_FIRST))
            {
                if (list->GetItemsCount() == 0)
                    return true;
                auto item = list->GetCurrentItem();
                const uint64 index = item.IsValid() ? item.GetData(UINT64_MAX) : UINT64_MAX;
                if (index >= rows.size())
                    return true;
                if (!rows[index].enabled)
                {
                    ShowInfo("Course", rows[index].detail.empty() ? std::string_view("Not available now.") : std::string_view(rows[index].detail));
                    return true;
                }
                chosen = static_cast<size_t>(index);
                Exit(Dialogs::Result::Ok);
                return true;
            }
            if ((eventType == Event::ButtonClicked && id == BTN_SECOND) || eventType == Event::WindowClose)
            {
                Exit(Dialogs::Result::Cancel);
                return true;
            }
            return Window::OnEvent(c, eventType, id);
        }
    };
    CourseMenuDialog menu(rows, task.item);
    if (menu.Show() != Dialogs::Result::Ok || !menu.chosen.has_value())
        return;

    switch (rows[menu.chosen.value()].action)
    {
    case CourseAction::SaveWork:
        SaveWork(task);
        break;
    case CourseAction::ResumeWork:
        ResumeWork(task, true);
        break;
    case CourseAction::CompareSolution:
        OpenSolutionCompare(window, task.item, false);
        break;
    case CourseAction::ReplaySolution:
        OpenSolutionCompare(window, task.item, true);
        break;
    case CourseAction::CourseNote:
        GView::Security::Learning::Hooks::OpenNoteForObject(task.object);
        break;
    case CourseAction::SubmitFlag:
        GView::Security::Learning::Hooks::ShowSubmitDialogForObject(task.object);
        break;
    case CourseAction::PublishSolution:
        PublishSolution(task);
        break;
    case CourseAction::EditReplayJournal:
        if (task.view != nullptr)
            task.view->EditReplayJournal();
        break;
    case CourseAction::CloseSolutionWindow:
        window->RemoveMe(); // the last thing: the window is gone after this
        break;
    }
}
