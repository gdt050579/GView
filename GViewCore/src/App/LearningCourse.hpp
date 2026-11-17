#pragma once

// Course work and teacher solutions of Learning and Evaluation Mode, the UI side (LearningCourseDialogs.cpp, spec §10.12).
// The "Course" menu of a task window (Ctrl+Alt+L) is built from a pure model (BuildCourseMenuRows) so that it can be unit
// tested; the dialogs and the window handling live in LearningCourseDialogs.cpp.

#include "Internal.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace GView::Security::Learning
{
class LockedBuffer;
struct CatalogueItem;
} // namespace GView::Security::Learning

namespace GView::App::Course
{
using GView::Security::Learning::WorkspaceRole;

enum class CourseAction : uint8 {
    SaveWork,            // Save work to course
    ResumeWork,          // Resume work from course
    CompareSolution,     // Compare with the teacher's solution
    ReplaySolution,      // Replay the teacher's solution
    CourseNote,          // Course note (Hooks::OpenNoteForObject)
    SubmitFlag,          // Submit flag
    PublishSolution,     // course staff: Publish solution...
    EditReplayJournal,   // course staff: Edit replay journal... (the viewer command)
    CloseSolutionWindow, // a solution / replay window: Close solution window
};

// the course work feature as seen by the menu
enum class WorkState : uint8 {
    Hidden,       // the server / the policy has no course work (WorkAvailability::Absent): no row at all
    Disabled,     // turned off by the teacher (policy or 403)
    NotConnected, // the session is not Active
    Available,
};

struct CourseMenuContext {
    WorkspaceRole role{ WorkspaceRole::Student };
    WorkState work{ WorkState::Hidden };
    bool hasDissasmView{ false };  // the window has a disassembly view (the work document is built from it)
    uint64 workSavedAt{ 0 };       // the catalogue's me.workSavedAt (0: nothing saved on the server)
    bool solutionAvailable{ false }; // the catalogue's solutionAvailable
    bool solutionHasReplay{ false };
    bool canPublishSolutions{ false }; // LearningSession::CanPublishSolutions
    bool courseStaff{ false };         // LearningSession::IsCourseStaff (the replay journal editor)
    bool notesAvailable{ false };
    bool canSubmit{ false };
    uint64 documentSize{ 0 }; // the size of the work document of the window (0: not known / nothing analysed yet)
    uint32 replaySteps{ 0 };  // the events of the replay journal of the window
};

struct CourseMenuRow {
    CourseAction action{ CourseAction::SaveWork };
    std::string caption;
    std::string detail;  // the second column: a size, a date, why the row is disabled
    bool enabled{ true }; // a disabled row is shown grayed out; choosing it shows the detail
};

// The rows of the Course menu, in order. Student windows: Save / Resume (when the server has course work), Compare / Replay
// (when a solution is published for the student / it has a replay), Course note (notes on), Submit flag (submissions on);
// course staff add Publish solution... and Edit replay journal... Solution / Replay windows: Close solution window only.
std::vector<CourseMenuRow> BuildCourseMenuRows(const CourseMenuContext& ctx);

// The teacher's solution opened from the Learning window, without a student window: from the local task file (file mode,
// `file` not empty) or from a copy of the delivered bytes (`bytes`, shown under `name`; memory only). Same roles and
// document handling as OpenSolutionCompare, no tiling. False when nothing was opened (the error was shown).
struct SolutionSource {
    std::filesystem::path file;
    std::string name;
    GView::Security::Learning::LockedBuffer* bytes{ nullptr };
};
bool OpenSolutionStandalone(const GView::Security::Learning::CatalogueItem& item, uint32 itemVersion, const SolutionSource& source, bool replay);

// After a task window was opened from the catalogue (LearningModeWindow::OpenDelivered / OpenLocalCopy):
//   ask = true  (Open): when the server has saved work for it and the window is still empty, asks whether to load it;
//   ask = false (Open with work): loads the saved work without asking (import semantics: the document wins, nothing deleted).
// The document is applied once the disassembly is analysed (the window is clean then).
void OfferResumeCourseWork(std::string_view itemName, bool ask);
} // namespace GView::App::Course
