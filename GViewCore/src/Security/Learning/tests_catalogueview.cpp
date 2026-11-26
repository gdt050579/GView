#include "Learning/CatalogueView.hpp"

#include <catch.hpp>

using namespace GView::Security::Learning;

namespace
{
CatalogueItem MakeItem(std::string name, bool problem)
{
    CatalogueItem it;
    it.kind        = problem ? ItemKind::Problem : ItemKind::ResourceFile;
    it.name        = name;
    it.title       = "Title of " + name;
    it.description = "Description of " + name;
    it.fileName    = name + ".bin";
    it.sha256      = std::string(64, 'a');
    it.size        = 1024;
    it.pointsMax   = problem ? 10 : 0;
    return it;
}

Week MakeWeek(int64 id)
{
    Week w;
    w.id    = id;
    w.name  = "Week " + std::to_string(id);
    w.title = "Topic " + std::to_string(id);
    w.order = id;
    w.problems.push_back(MakeItem("p" + std::to_string(id), true));
    w.resources.push_back(MakeItem("r" + std::to_string(id), false));
    return w;
}

bool IsLowerHex(const std::string& s)
{
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}
} // namespace

TEST_CASE("Learning: week content hash", "[learning][catalogueview]")
{
    const Week base   = MakeWeek(3);
    const auto hash   = WeekContentHash(base);
    REQUIRE(hash.size() == 16);
    REQUIRE(IsLowerHex(hash));
    REQUIRE(WeekContentHash(MakeWeek(3)) == hash); // stable

    SECTION("the fields of one student do not change it")
    {
        Week w                    = base;
        w.problems[0].hasMe       = true;
        w.problems[0].me.solved   = true;
        w.problems[0].me.attempts = 4;
        w.problems[0].me.workSavedAt = 1234;
        w.problems[0].pointsCurrent  = 7;
        REQUIRE(WeekContentHash(w) == hash);
    }
    SECTION("what the teacher publishes changes it")
    {
        Week w = base;
        w.problems.push_back(MakeItem("p_new", true));
        REQUIRE(WeekContentHash(w) != hash);

        w = base;
        w.resources.clear();
        REQUIRE(WeekContentHash(w) != hash);

        w                     = base;
        w.problems[0].sha256  = std::string(64, 'b');
        REQUIRE(WeekContentHash(w) != hash);

        w             = base;
        w.description = "new text";
        REQUIRE(WeekContentHash(w) != hash);

        w                       = base;
        w.problems[0].title     = "Renamed";
        REQUIRE(WeekContentHash(w) != hash);

        w                                = base;
        w.problems[0].solutionAvailable  = true;
        REQUIRE(WeekContentHash(w) != hash);
    }
    SECTION("fields are length prefixed")
    {
        Week a = base, b = base;
        a.title = "ab";
        a.description = "c";
        b.title = "a";
        b.description = "bc";
        REQUIRE(WeekContentHash(a) != WeekContentHash(b));
    }
}

TEST_CASE("Learning: week order setting", "[learning][catalogueview]")
{
    REQUIRE(WeekOrderName(WeekOrder::NewestFirst) == "newest");
    REQUIRE(WeekOrderName(WeekOrder::OldestFirst) == "oldest");
    REQUIRE(ParseWeekOrder("oldest") == WeekOrder::OldestFirst);
    REQUIRE(ParseWeekOrder(" oldest ") == WeekOrder::OldestFirst);
    REQUIRE(ParseWeekOrder("newest") == WeekOrder::NewestFirst);
    REQUIRE(ParseWeekOrder("") == WeekOrder::NewestFirst);
    REQUIRE(ParseWeekOrder("OLDEST?") == WeekOrder::NewestFirst);

    Catalogue cat;
    for (int64 id = 1; id <= 4; id++)
        cat.weeks.push_back(MakeWeek(id));
    REQUIRE(WeekDisplayOrder(cat, WeekOrder::NewestFirst) == std::vector<size_t>{ 3, 2, 1, 0 });
    REQUIRE(WeekDisplayOrder(cat, WeekOrder::OldestFirst) == std::vector<size_t>{ 0, 1, 2, 3 });
    REQUIRE(WeekDisplayOrder(Catalogue{}, WeekOrder::NewestFirst).empty());
}

TEST_CASE("Learning: folded weeks are serialized and parsed defensively", "[learning][catalogueview]")
{
    const std::string h1(16, 'a'), h2 = "0123456789abcdef";
    std::map<int64, std::string> folded{ { 7, h1 }, { -2, h2 } };
    const auto text = SerializeFoldedWeeks(folded);
    REQUIRE(text == "-2:" + h2 + ",7:" + h1);
    REQUIRE(ParseFoldedWeeks(text) == folded);
    REQUIRE(ParseFoldedWeeks("").empty());

    // malformed entries are skipped, the others kept
    const auto parsed = ParseFoldedWeeks("x:" + h1 + ",3:" + h1 + ",4:ABCDEF0123456789,5," + "6:" + h1 + "00,12x:" + h1 + ", 8 : " + h2 + ",,");
    REQUIRE(parsed.size() == 2);
    REQUIRE(parsed.at(3) == h1);
    REQUIRE(parsed.at(8) == h2);

    // a bad hash is never written
    REQUIRE(SerializeFoldedWeeks({ { 1, "short" }, { 2, h1 } }) == "2:" + h1);

    // capped
    std::string many;
    for (int i = 0; i < 300; i++)
        many += std::to_string(i) + ":" + h1 + ",";
    REQUIRE(ParseFoldedWeeks(many).size() == MAX_REMEMBERED_FOLDED_WEEKS);
}


TEST_CASE("Learning: ini section of the catalogue view", "[learning][catalogueview]")
{
    REQUIRE(WeekViewSection("https://course.example.edu", "").empty());
    const auto s = WeekViewSection("https://user@Course.Example-1.edu:8443/api", "0011aabbccddeeff");
    REQUIRE(s == "LearningCourse.course.example_1.edu_8443.0011aabbccddeeff");
    for (char c : s)
        REQUIRE(((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'));
}

TEST_CASE("Learning: view state key of a token", "[learning][catalogueview]")
{
    const SecureString token = "tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd";
    const auto key           = ViewStateKey(token);
    REQUIRE(key.size() == 16);
    REQUIRE(IsLowerHex(key));
    REQUIRE(ViewStateKey(token) == key);
    REQUIRE(key != SubjectForToken(token)); // not the subject the policy and the server use
    REQUIRE(ViewStateKey(SecureString("tok_other_student_0123456789abcdefghijkl")) != key);
    REQUIRE(ViewStateKey(SecureString()).empty());
}

TEST_CASE("Learning: the view state round-trips through GView.ini", "[learning][catalogueview]")
{
    const std::string h1(16, 'a'), h2 = "0123456789abcdef";
    const std::map<int64, std::string> folded{ { -3, h1 }, { 5, h2 } };
    for (const auto* server : { "https://course.example.edu:8443", "https://[::1]:8443", "http://127.0.0.1:8771" })
    {
        const auto section = WeekViewSection(server, "0011aabbccddeeff");
        AppCUI::Utils::IniObject ini;
        REQUIRE(ini.Create());
        ini[section]["WeekOrder"]   = std::string(WeekOrderName(WeekOrder::OldestFirst));
        ini[section]["FoldedWeeks"] = SerializeFoldedWeeks(folded);
        const std::string text(ini.ToString());

        AppCUI::Utils::IniObject back;
        REQUIRE(back.CreateFromString(text));
        auto sect = back.GetSection(section);
        REQUIRE(sect.Exists());
        REQUIRE(ParseWeekOrder(sect.GetValue("WeekOrder").AsStringView().value_or(std::string_view())) == WeekOrder::OldestFirst);
        REQUIRE(ParseFoldedWeeks(sect.GetValue("FoldedWeeks").AsStringView().value_or(std::string_view())) == folded);
    }
}

TEST_CASE("Learning: folded weeks remember what they showed", "[learning][catalogueview]")
{
    const std::string oldHash(16, '1'), newHash(16, '2');
    WeekViewState st;

    // week 1 folded while it showed oldHash; a second call with the same fold changes nothing
    REQUIRE(ApplyFoldChange(st, 1, oldHash, true));
    REQUIRE(st.folded.at(1) == oldHash);
    REQUIRE_FALSE(ApplyFoldChange(st, 1, oldHash, true));
    REQUIRE_FALSE(ApplyFoldChange(st, 1, newHash, true)); // already folded: the older hash is kept
    REQUIRE(st.folded.at(1) == oldHash);

    // the teacher changed it while it was folded: reported
    REQUIRE(FoldedWeekChanged(st, 1, newHash));
    REQUIRE_FALSE(FoldedWeekChanged(st, 1, oldHash));
    REQUIRE_FALSE(FoldedWeekChanged(st, 2, newHash)); // not folded
    REQUIRE_FALSE(FoldedWeekChanged(st, 1, ""));       // no hash: never "changed"

    // unfolded (seen), then folded again: the new content is remembered
    REQUIRE(ApplyFoldChange(st, 1, newHash, false));
    REQUIRE(st.folded.empty());
    REQUIRE_FALSE(ApplyFoldChange(st, 1, newHash, false)); // unfolding an unfolded week changes nothing
    REQUIRE(ApplyFoldChange(st, 1, newHash, true));
    REQUIRE_FALSE(FoldedWeekChanged(st, 1, newHash));

    // a week without a valid hash is not remembered
    REQUIRE_FALSE(ApplyFoldChange(st, 3, "", true));
    REQUIRE_FALSE(ApplyFoldChange(st, 3, "XYZ", true));
    REQUIRE(st.folded.count(3) == 0);
}

TEST_CASE("Learning: folded weeks are capped, never the week just folded", "[learning][catalogueview]")
{
    const std::string h(16, 'c');
    WeekViewState st;
    for (int64 id = 1; id <= static_cast<int64>(MAX_REMEMBERED_FOLDED_WEEKS); id++)
        REQUIRE(ApplyFoldChange(st, id, h, true));
    REQUIRE(st.folded.size() == MAX_REMEMBERED_FOLDED_WEEKS);

    REQUIRE(ApplyFoldChange(st, 1000, h, true));
    REQUIRE(st.folded.size() == MAX_REMEMBERED_FOLDED_WEEKS);
    REQUIRE(st.folded.count(1000) == 1);
    REQUIRE(st.folded.count(1) == 0); // the smallest id went

    // the smallest id itself is the week being folded: the next one goes
    REQUIRE(ApplyFoldChange(st, -5, h, true));
    REQUIRE(st.folded.count(-5) == 1);
    REQUIRE(st.folded.count(2) == 0);
    REQUIRE(st.folded.size() == MAX_REMEMBERED_FOLDED_WEEKS);
    REQUIRE_FALSE(ApplyFoldChange(st, -5, h, true)); // stable: no change on a repeated call
}
