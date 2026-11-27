#pragma once

// How a student sees the catalogue in the Learning and Evaluation Mode window: the order of the weeks (newest first by
// default), the weeks the student folded, and what a folded week contained when it was folded, so the window can say
// which folded weeks the teacher changed since. Kept per course server and per student in GView.ini (not secret: the
// web build mirrors GView.ini in clear into the localStorage of the page). Pure: no I/O, no globals.

#include "LearningProtocol.hpp"

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace GView::Security::Learning
{
enum class WeekOrder : uint8 { NewestFirst, OldestFirst };

// entries beyond this are dropped (a hostile or very long course cannot grow GView.ini without bound)
constexpr size_t MAX_REMEMBERED_FOLDED_WEEKS = 256;

struct WeekViewState {
    WeekOrder order{ WeekOrder::NewestFirst };
    std::map<int64, std::string> folded; // week id -> WeekContentHash of the week when the student folded it
};

// 16 lowercase hex characters (SHA-256 prefix) of what a week shows to every student: its name, title and description,
// and the published fields of its problems and resources. The fields of one student (me, current points) are not part
// of it, so a submission or the passing time never marks a week as changed. Empty if hashing fails.
std::string WeekContentHash(const Week& week);

std::string_view WeekOrderName(WeekOrder order) noexcept; // "newest" / "oldest"
WeekOrder ParseWeekOrder(std::string_view text) noexcept; // anything else -> NewestFirst

// "<id>:<hash>,<id>:<hash>" (ids in increasing order)
std::string SerializeFoldedWeeks(const std::map<int64, std::string>& folded);
// the inverse; malformed entries (bad id, hash not 16 lowercase hex characters) are skipped, never an error
std::map<int64, std::string> ParseFoldedWeeks(std::string_view text);

// indexes into catalogue.weeks in display order (the catalogue is sorted oldest first by ParseWeeks)
std::vector<size_t> WeekDisplayOrder(const Catalogue& catalogue, WeekOrder order);

// The student of a session in the name of its GView.ini section: 16 hex characters of a SHA-256 of the access token
// with its own prefix ("GView-Learning-View-v1"), so it is not the subject the policy and the server use for the token
// (SubjectForToken). Empty for an empty token or when hashing fails.
std::string ViewStateKey(const SecureString& token);

// GView.ini section of one student on one course server: "LearningCourse.<server folder>.<view state key>"; only
// letters, digits, '_' and '.' (the characters an ini section name may hold). Empty without a key (not connected).
std::string WeekViewSection(std::string_view serverUrl, std::string_view viewStateKey);

// A fold (folded = true) or an unfold of a shown week by the student. Folding stores the hash the week showed, unless
// the week already has an entry (its older hash is kept, so a change made while it was folded is still reported);
// unfolding forgets it. Over MAX_REMEMBERED_FOLDED_WEEKS the entries with the smallest ids are dropped, never the week
// being folded. Returns true when state.folded changed. Called only on a change of the week's folding, so a catalogue
// with duplicate week ids or many folded weeks never makes it report a change on every call.
bool ApplyFoldChange(WeekViewState& state, int64 weekId, std::string_view shownHash, bool folded);

// whether a week folded by the student changed since (its stored hash differs from its current one)
bool FoldedWeekChanged(const WeekViewState& state, int64 weekId, std::string_view currentHash);
} // namespace GView::Security::Learning
