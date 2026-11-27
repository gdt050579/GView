// Unit tests for the download gate of the web build (BrowserDownloadGate.cpp): Learning task files are recognised by
// their content (size + SHA-256) under the task folders, links are never followed, Stored files paths under a task
// folder are recognised, task folders are found by their manifest, and the denylist of delivered hashes is bounded.

#include "Internal.hpp"

#include <catch.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace GView::App::Browser::DownloadGate;

namespace
{
void WriteBytes(const std::filesystem::path& p, std::string_view bytes)
{
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

BufferView View(const std::string& s)
{
    return BufferView(s.data(), s.size());
}

struct TempRoot {
    std::filesystem::path root;
    explicit TempRoot(std::string_view name) : root(std::filesystem::temp_directory_path() / std::string(name))
    {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
        std::filesystem::create_directories(root, ec);
    }
    ~TempRoot()
    {
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }
};
} // namespace

TEST_CASE("Learning: download gate recognises task files by content", "[learning][downloadgate]")
{
    TempRoot t("gview_downloadgate_content");
    const std::string task  = std::string("MZ\x90\x00", 4) + "task sample bytes";
    const std::string other = std::string("MZ\x90\x00", 4) + "TASK SAMPLE BYTES"; // same size, other bytes
    WriteBytes(t.root / "course.example.edu" / "Week 1" / "task.exe", task);
    WriteBytes(t.root / "course.example.edu" / "Week 1" / ".gview-items.json", "{}");

    // the same bytes under the root: refused, whatever the name the page would give the download
    REQUIRE(FindFileWithContent(t.root, View(task)) == TaskFileMatch::Match);
    // a renamed copy (in another folder under the root) is found as well
    std::filesystem::remove(t.root / "course.example.edu" / "Week 1" / "task.exe");
    WriteBytes(t.root / "elsewhere" / "deeper" / "renamed.bin", task);
    REQUIRE(FindFileWithContent(t.root, View(task)) == TaskFileMatch::Match);
    // different bytes of the same size, and other sizes: no match
    REQUIRE(FindFileWithContent(t.root, View(other)) == TaskFileMatch::None);
    REQUIRE(FindFileWithContent(t.root, View(task + "x")) == TaskFileMatch::None);
    const std::string empty;
    REQUIRE(FindFileWithContent(t.root, View(empty)) == TaskFileMatch::None);
    WriteBytes(t.root / "empty.bin", "");
    REQUIRE(FindFileWithContent(t.root, View(empty)) == TaskFileMatch::Match); // an empty task file matches an empty download
    // a root that does not exist holds nothing
    REQUIRE(FindFileWithContent(t.root / "missing", View(task)) == TaskFileMatch::None);
}

TEST_CASE("Learning: download gate fails closed beyond its scan depth", "[learning][downloadgate]")
{
    TempRoot t("gview_downloadgate_depth");
    std::filesystem::path deep = t.root;
    for (int i = 0; i < MAX_SCAN_DEPTH + 1; i++)
        deep /= "d";
    WriteBytes(deep / "x.bin", "abc");
    // the folders below the depth bound can not be checked: refused rather than skipped
    REQUIRE(FindFileWithContent(t.root, View(std::string("zzz"))) == TaskFileMatch::Error);
}

TEST_CASE("Learning: download gate never follows links", "[learning][downloadgate]")
{
    TempRoot t("gview_downloadgate_links");
    TempRoot outside("gview_downloadgate_links_outside");
    const std::string secret = "bytes that live outside the task folder";
    WriteBytes(outside.root / "file.bin", secret);
    std::error_code ec;
    std::filesystem::create_symlink(outside.root / "file.bin", t.root / "link.bin", ec);
    if (ec)
        SKIP("cannot create symbolic links here"); // needs a privilege (or developer mode) on Windows
    std::filesystem::create_directory_symlink(outside.root, t.root / "linkdir", ec);
    REQUIRE_FALSE(ec);
    // neither the file link nor the folder link is followed
    REQUIRE(FindFileWithContent(t.root, View(secret)) == TaskFileMatch::None);
    // a real copy is found
    WriteBytes(t.root / "copy.bin", secret);
    REQUIRE(FindFileWithContent(t.root, View(secret)) == TaskFileMatch::Match);
}

TEST_CASE("Learning: stored paths under a Learning task folder", "[learning][downloadgate]")
{
    const std::vector<std::string> roots{ "Documents/GView", "Courses/re/" };
    REQUIRE(IsUnderRoot("Documents/GView/course.example.edu/Week 1/task.exe", roots));
    REQUIRE(IsUnderRoot("Documents/GView", roots));
    REQUIRE(IsUnderRoot("Courses/re/x.bin", roots));
    REQUIRE(IsUnderRoot("Documents/GView/./a/../b.bin", roots));
    REQUIRE_FALSE(IsUnderRoot("Documents/GViewer/x.bin", roots)); // a prefix of the name is not a folder
    REQUIRE_FALSE(IsUnderRoot("Documents/other.bin", roots));
    REQUIRE_FALSE(IsUnderRoot("Files/task.exe", roots));
    REQUIRE_FALSE(IsUnderRoot("Documents/GView/../other.bin", roots)); // normalised first
    REQUIRE_FALSE(IsUnderRoot("../Documents/GView/x", roots));
    REQUIRE_FALSE(IsUnderRoot("Files/x.bin", {}));
    // the home folder itself as a task folder: everything in it
    REQUIRE(IsUnderRoot("Files/x.bin", { "." }));
    REQUIRE(IsUnderRoot("Files/x.bin", { "" }));
    // roots outside the folder are ignored
    REQUIRE_FALSE(IsUnderRoot("Files/x.bin", { "../elsewhere" }));
}

TEST_CASE("Learning: folders holding a task manifest", "[learning][downloadgate]")
{
    TempRoot t("gview_downloadgate_manifests");
    WriteBytes(t.root / "Documents" / "GView" / "course.example.edu" / "Week 1" / ".gview-items.json", "{}");
    WriteBytes(t.root / "Old" / "srv" / "Week 2" / ".gview-items.json", "{}");
    WriteBytes(t.root / "Files" / "gview-items.json", "{}");           // other name
    std::filesystem::create_directories(t.root / "Files" / ".gview-items.json"); // a folder, not a file
    auto found = FindFoldersWithFile(t.root, ".gview-items.json");
    std::sort(found.begin(), found.end());
    REQUIRE(found.size() == 2);
    REQUIRE(found[0] == (t.root / "Documents" / "GView" / "course.example.edu" / "Week 1").lexically_normal());
    REQUIRE(found[1] == (t.root / "Old" / "srv" / "Week 2").lexically_normal());
    REQUIRE(FindFoldersWithFile(t.root / "missing", ".gview-items.json").empty());
}

TEST_CASE("Learning: denylist of delivered task hashes", "[learning][downloadgate]")
{
    const auto hashOf = [](size_t i) {
        char buf[17];
        snprintf(buf, sizeof(buf), "%016zx", i);
        return std::string(48, 'a') + buf; // 64 lowercase hex characters
    };
    const std::string h1 = hashOf(1), h2 = hashOf(2);

    SECTION("add, dedupe and contains")
    {
        std::vector<std::string> list;
        REQUIRE(AddTaskHash(list, h1));
        REQUIRE_FALSE(AddTaskHash(list, h1)); // already there
        std::string upper = h2;
        for (auto& c : upper)
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        REQUIRE(AddTaskHash(list, upper)); // stored lowered
        REQUIRE_FALSE(AddTaskHash(list, h2));
        REQUIRE(list == std::vector<std::string>{ h1, h2 });
        REQUIRE(ContainsTaskHash(list, h1));
        REQUIRE(ContainsTaskHash(list, upper));
        REQUIRE_FALSE(ContainsTaskHash(list, hashOf(3)));
        REQUIRE_FALSE(ContainsTaskHash(list, ""));
        // malformed hashes are never added
        REQUIRE_FALSE(AddTaskHash(list, ""));
        REQUIRE_FALSE(AddTaskHash(list, h1.substr(1)));
        REQUIRE_FALSE(AddTaskHash(list, h1 + "0"));
        REQUIRE_FALSE(AddTaskHash(list, std::string(63, 'a') + "g"));
        REQUIRE(list.size() == 2);
    }
    SECTION("serialize / parse round trip; malformed input is ignored")
    {
        std::vector<std::string> list{ h1, h2 };
        const auto text = SerializeTaskHashes(list);
        REQUIRE(text == h1 + "\n" + h2);
        REQUIRE(ParseTaskHashes(text) == list);
        REQUIRE(ParseTaskHashes("").empty());
        REQUIRE(ParseTaskHashes("garbage\n\n" + h1 + "\r\nzz\n" + h1 + "\n" + std::string(64, 'x') + "\n" + h2 + "\n") ==
                std::vector<std::string>{ h1, h2 }); // "\r" lines, duplicates and non-hex dropped
    }
    SECTION("capped: the oldest entries are dropped first")
    {
        std::vector<std::string> list;
        for (size_t i = 0; i < MAX_TASK_HASHES + 5; i++)
            REQUIRE(AddTaskHash(list, hashOf(i)));
        REQUIRE(list.size() == MAX_TASK_HASHES);
        REQUIRE(list.front() == hashOf(5));
        REQUIRE(list.back() == hashOf(MAX_TASK_HASHES + 4));
        REQUIRE_FALSE(ContainsTaskHash(list, hashOf(0)));
        // the serialized list fits in a secret of the page (64 KiB)
        const auto text = SerializeTaskHashes(list);
        REQUIRE(text.size() < 64 * 1024);
        REQUIRE(ParseTaskHashes(text) == list);
        // a longer stored list keeps its newest entries
        std::string longText;
        for (size_t i = 0; i < MAX_TASK_HASHES + 10; i++)
            longText += hashOf(i) + "\n";
        const auto parsed = ParseTaskHashes(longText);
        REQUIRE(parsed.size() == MAX_TASK_HASHES);
        REQUIRE(parsed.front() == hashOf(10));
        REQUIRE(parsed.back() == hashOf(MAX_TASK_HASHES + 9));
    }
}
