#include "LearningCourse.hpp"
#include "DissasmReplayEditor.hpp"

#include <catch.hpp>

using namespace GView::App::Course;
using GView::Security::Learning::WorkspaceRole;
namespace DV = GView::View::DissasmViewer;

namespace
{
std::vector<CourseAction> Actions(const std::vector<CourseMenuRow>& rows)
{
    std::vector<CourseAction> actions;
    for (const auto& row : rows)
        actions.push_back(row.action);
    return actions;
}

const CourseMenuRow& RowOf(const std::vector<CourseMenuRow>& rows, CourseAction action)
{
    for (const auto& row : rows)
        if (row.action == action)
            return row;
    FAIL("no row for the action");
    return rows.front();
}

CourseMenuContext StudentContext()
{
    CourseMenuContext ctx;
    ctx.role           = WorkspaceRole::Student;
    ctx.work           = WorkState::Available;
    ctx.hasDissasmView = true;
    return ctx;
}
} // namespace

//================================================================================== the Course menu ===
TEST_CASE("CourseMenuStudentWithoutSavedWork", "[learningcourse]")
{
    auto ctx         = StudentContext();
    ctx.documentSize = 12 * 1024 + 300;
    ctx.replaySteps  = 57;
    const auto rows  = BuildCourseMenuRows(ctx);
    REQUIRE(Actions(rows) == std::vector<CourseAction>{ CourseAction::SaveWork, CourseAction::ResumeWork });
    REQUIRE(rows[0].enabled);
    REQUIRE(rows[0].caption == "Save work to course");
    REQUIRE(rows[0].detail == "12.3 KiB, 57 replay steps");
    // nothing saved on the server: Resume is shown, disabled, and says why
    REQUIRE_FALSE(rows[1].enabled);
    REQUIRE(rows[1].detail == "(no saved work)");
}

TEST_CASE("CourseMenuStudentWithSolution", "[learningcourse]")
{
    auto ctx              = StudentContext();
    ctx.workSavedAt       = 1760000000;
    ctx.solutionAvailable = true;
    ctx.solutionHasReplay = true;
    ctx.notesAvailable    = true;
    ctx.canSubmit         = true;
    const auto rows       = BuildCourseMenuRows(ctx);
    REQUIRE(Actions(rows) == std::vector<CourseAction>{ CourseAction::SaveWork,
                                                         CourseAction::ResumeWork,
                                                         CourseAction::CompareSolution,
                                                         CourseAction::ReplaySolution,
                                                         CourseAction::CourseNote,
                                                         CourseAction::SubmitFlag });
    for (const auto& row : rows)
        REQUIRE(row.enabled);
    REQUIRE(RowOf(rows, CourseAction::ResumeWork).detail.rfind("saved ", 0) == 0);
    REQUIRE(RowOf(rows, CourseAction::CompareSolution).caption == "Compare with the teacher's solution");
    REQUIRE(RowOf(rows, CourseAction::ReplaySolution).caption == "Replay the teacher's solution");
    // no staff rows for a student
    REQUIRE(Actions(rows).size() == 6);

    // a solution without a replay: no Replay row
    ctx.solutionHasReplay = false;
    const auto noReplay   = BuildCourseMenuRows(ctx);
    REQUIRE(RowOf(noReplay, CourseAction::CompareSolution).enabled);
    for (const auto& row : noReplay)
        REQUIRE(row.action != CourseAction::ReplaySolution);
}

TEST_CASE("CourseMenuStaff", "[learningcourse]")
{
    auto ctx                = StudentContext();
    ctx.canPublishSolutions = true;
    ctx.courseStaff         = true;
    const auto rows         = BuildCourseMenuRows(ctx);
    REQUIRE(Actions(rows) == std::vector<CourseAction>{
                                   CourseAction::SaveWork, CourseAction::ResumeWork, CourseAction::PublishSolution, CourseAction::EditReplayJournal });
    REQUIRE(RowOf(rows, CourseAction::PublishSolution).enabled);
    REQUIRE(RowOf(rows, CourseAction::EditReplayJournal).enabled);

    // a teacher-notes-only token (no solutions): the editor, no Publish
    ctx.canPublishSolutions = false;
    const auto notesStaff   = BuildCourseMenuRows(ctx);
    REQUIRE(Actions(notesStaff) == std::vector<CourseAction>{ CourseAction::SaveWork, CourseAction::ResumeWork, CourseAction::EditReplayJournal });

    // a window without a disassembly view: the rows that need it are disabled with the reason
    ctx.canPublishSolutions = true;
    ctx.hasDissasmView      = false;
    const auto noView       = BuildCourseMenuRows(ctx);
    REQUIRE_FALSE(RowOf(noView, CourseAction::SaveWork).enabled);
    REQUIRE(RowOf(noView, CourseAction::SaveWork).detail == "this window has no disassembly view");
    REQUIRE_FALSE(RowOf(noView, CourseAction::PublishSolution).enabled);
    REQUIRE_FALSE(RowOf(noView, CourseAction::EditReplayJournal).enabled);
}

TEST_CASE("CourseMenuWorkStates", "[learningcourse]")
{
    // a server without course work: no Save / Resume / Compare at all (the solution flag of the catalogue does not matter)
    auto ctx              = StudentContext();
    ctx.work              = WorkState::Hidden;
    ctx.solutionAvailable = true;
    ctx.canSubmit         = true;
    REQUIRE(Actions(BuildCourseMenuRows(ctx)) == std::vector<CourseAction>{ CourseAction::SubmitFlag });

    // turned off by the teacher: shown, disabled, with the reason
    ctx.work        = WorkState::Disabled;
    ctx.workSavedAt = 1760000000;
    auto rows       = BuildCourseMenuRows(ctx);
    REQUIRE(Actions(rows) == std::vector<CourseAction>{
                                   CourseAction::SaveWork, CourseAction::ResumeWork, CourseAction::CompareSolution, CourseAction::SubmitFlag });
    for (const auto action : { CourseAction::SaveWork, CourseAction::ResumeWork, CourseAction::CompareSolution }) {
        REQUIRE_FALSE(RowOf(rows, action).enabled);
        REQUIRE(RowOf(rows, action).detail == "disabled by your teacher");
    }
    REQUIRE(RowOf(rows, CourseAction::SubmitFlag).enabled);

    // not connected (expired policy, reconnecting)
    ctx.work = WorkState::NotConnected;
    rows     = BuildCourseMenuRows(ctx);
    REQUIRE_FALSE(RowOf(rows, CourseAction::SaveWork).enabled);
    REQUIRE(RowOf(rows, CourseAction::SaveWork).detail == "not connected to the course");
    REQUIRE_FALSE(RowOf(rows, CourseAction::CompareSolution).enabled);
}

TEST_CASE("CourseMenuSolutionWindows", "[learningcourse]")
{
    // the windows of a teacher's solution are read only: the only command closes them (also for course staff)
    for (const auto role : { WorkspaceRole::Solution, WorkspaceRole::Replay }) {
        auto ctx                = StudentContext();
        ctx.role                = role;
        ctx.workSavedAt         = 1760000000;
        ctx.solutionAvailable   = true;
        ctx.solutionHasReplay   = true;
        ctx.canPublishSolutions = true;
        ctx.courseStaff         = true;
        ctx.notesAvailable      = true;
        ctx.canSubmit           = true;
        const auto rows         = BuildCourseMenuRows(ctx);
        REQUIRE(Actions(rows) == std::vector<CourseAction>{ CourseAction::CloseSolutionWindow });
        REQUIRE(rows[0].enabled);
        REQUIRE(rows[0].caption == "Close solution window");
    }
}

//================================================================================== the replay editor rows ===
TEST_CASE("ReplayEditorRows", "[learningcourse]")
{
    using Kind   = DV::DissasmReplayEvent::Kind;
    using Anchor = DV::DissasmCommentAnchor::Kind;
    DV::DissasmReplayJournal journal;
    journal.startedAt = 1760000000;
    journal.zones.push_back({ 0x400, 0x401000 });

    DV::DissasmReplayEvent visit;
    visit.kind                = Kind::Visit;
    visit.time                = 5;
    visit.place.anchor.kind   = Anchor::Instruction;
    visit.place.anchor.address = 0x10;
    journal.events.push_back(visit);

    DV::DissasmReplayEvent jump;
    jump.kind                 = Kind::Jump;
    jump.time                 = 47;
    jump.from                 = visit.place;
    jump.place.anchor.kind    = Anchor::Label;
    jump.place.anchor.address = 0x80;
    jump.jumpKind             = DV::DissasmReplayJumpKind::Follow;
    jump.mnemonic             = "call";
    journal.events.push_back(jump);

    DV::DissasmReplayEvent rename;
    rename.kind  = Kind::Edit;
    rename.time  = 47 + 185;
    rename.place = jump.place;
    DV::DissasmReplayEdit edit;
    edit.kind    = DV::DissasmEdit::Kind::LabelName;
    edit.before  = "sub_401080";
    edit.after   = "decrypt";
    rename.edit  = edit;
    journal.events.push_back(rename);

    DV::DissasmReplayEvent import;
    import.kind         = Kind::Import;
    import.time         = 232 + 3700;
    import.importSource = DV::DissasmReplayImportSource::ServerWork;
    journal.events.push_back(import);

    DV::DissasmReplayEvent analysis;
    analysis.kind = Kind::Reanalysis;
    analysis.time = import.time;
    journal.events.push_back(analysis);

    auto row = DV::FormatReplayRow(journal, 0);
    REQUIRE(row[0] == "1");
    REQUIRE(row[1] == "+5s");
    REQUIRE(row[2] == "visit");
    REQUIRE(row[3] == "0x401010");
    REQUIRE(row[4] == "visit 0x401010");

    row = DV::FormatReplayRow(journal, 1);
    REQUIRE(row[0] == "2");
    REQUIRE(row[1] == "+42s");
    REQUIRE(row[2] == "jump");
    REQUIRE(row[3] == "0x401080");
    REQUIRE(row[4].find("call") != std::string::npos);
    REQUIRE(row[4].find("0x401010") != std::string::npos);

    row = DV::FormatReplayRow(journal, 2);
    REQUIRE(row[1] == "+3m05s");
    REQUIRE(row[2] == "edit");
    REQUIRE(row[3] == "0x401080 decrypt"); // a rename: the new name with the address
    REQUIRE(row[4] == "rename 0x401080 sub_401080 -> decrypt");

    row = DV::FormatReplayRow(journal, 3);
    REQUIRE(row[1] == "+1h01m");
    REQUIRE(row[2] == "import");
    REQUIRE(row[3].empty());
    REQUIRE(row[4] == "saved work loaded from the course");

    row = DV::FormatReplayRow(journal, 4);
    REQUIRE(row[1] == "+0s");
    REQUIRE(row[2] == "analysis");
    REQUIRE(row[3] == "zone @ 0x400");

    // outside the journal: empty
    for (const auto& cell : DV::FormatReplayRow(journal, 5))
        REQUIRE(cell.empty());

    REQUIRE(DV::FormatReplayDelta(0) == "+0s");
    REQUIRE(DV::FormatReplayDelta(59) == "+59s");
    REQUIRE(DV::FormatReplayDelta(60) == "+1m00s");
    REQUIRE(DV::FormatReplayDelta(3599) == "+59m59s");
    REQUIRE(DV::FormatReplayDelta(7260) == "+2h01m");
}
