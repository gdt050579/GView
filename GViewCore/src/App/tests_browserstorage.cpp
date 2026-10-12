// Unit tests for the change detection of the persistent storage of the web build (BrowserStorageDiff.cpp).

#include "Internal.hpp"

#include <catch.hpp>

using namespace GView::App::Browser::Storage;

TEST_CASE("BrowserStorage: a new file is stored once it is stable", "[browserstorage]")
{
    const Snapshot empty;
    Snapshot scan1{ { "Files/a.bin", Stamp{ 10, 1000 } } };

    // first time seen: maybe still being written
    auto c = Diff(empty, scan1, empty);
    REQUIRE(c.persist.empty());
    REQUIRE(c.remove.empty());

    // unchanged in the next scan: stored
    c = Diff(scan1, scan1, empty);
    REQUIRE(c.persist == std::vector<std::string>{ "Files/a.bin" });

    // already stored with this stamp: nothing to do
    c = Diff(scan1, scan1, scan1);
    REQUIRE(c.persist.empty());
}

TEST_CASE("BrowserStorage: a file that keeps changing is not stored", "[browserstorage]")
{
    Snapshot s1{ { "out.log", Stamp{ 10, 1000 } } };
    Snapshot s2{ { "out.log", Stamp{ 20, 1100 } } };
    Snapshot s3{ { "out.log", Stamp{ 20, 1100 } } };
    REQUIRE(Diff(s1, s2, {}).persist.empty());
    REQUIRE(Diff(s2, s3, {}).persist == std::vector<std::string>{ "out.log" });
}

TEST_CASE("BrowserStorage: a modified stored file is stored again", "[browserstorage]")
{
    Snapshot stored{ { "Files/a.bin", Stamp{ 10, 1000 } } };
    Snapshot now{ { "Files/a.bin", Stamp{ 10, 2000 } } }; // same size, newer mtime
    REQUIRE(Diff(now, now, stored).persist == std::vector<std::string>{ "Files/a.bin" });
}

TEST_CASE("BrowserStorage: deletions need two scans", "[browserstorage]")
{
    Snapshot stored{ { "x", Stamp{ 1, 1 } }, { "y", Stamp{ 2, 2 } } };
    Snapshot withX{ { "x", Stamp{ 1, 1 } }, { "y", Stamp{ 2, 2 } } };
    Snapshot withoutX{ { "y", Stamp{ 2, 2 } } };

    // gone in the latest scan only (e.g. replaced by an atomic rename in progress): kept
    auto c = Diff(withX, withoutX, stored);
    REQUIRE(c.remove.empty());

    // gone in two scans in a row: removed from the store
    c = Diff(withoutX, withoutX, stored);
    REQUIRE(c.remove == std::vector<std::string>{ "x" });
    REQUIRE(c.persist.empty());
}

TEST_CASE("BrowserStorage: files only in the store are never touched by a scan", "[browserstorage]")
{
    // "stored" only holds the files that are in memory; the others (not copied back at startup) are not in it
    Snapshot stored{ { "Files/in-memory.bin", Stamp{ 5, 5 } } };
    Snapshot scan{ { "Files/in-memory.bin", Stamp{ 5, 5 } } };
    auto c = Diff(scan, scan, stored);
    REQUIRE(c.persist.empty());
    REQUIRE(c.remove.empty());
}

TEST_CASE("BrowserStorage: storable paths", "[browserstorage]")
{
    REQUIRE(IsStorablePath("Files/a.bin"));
    REQUIRE(IsStorablePath("Documents/GView/Week 1/task (1).exe"));
    REQUIRE(IsStorablePath(".dissasm.cache"));
    REQUIRE_FALSE(IsStorablePath(""));
    REQUIRE_FALSE(IsStorablePath("/abs"));
    REQUIRE_FALSE(IsStorablePath("../escape"));
    REQUIRE_FALSE(IsStorablePath("a/../b"));
    REQUIRE_FALSE(IsStorablePath("a/./b"));
    REQUIRE_FALSE(IsStorablePath("a//b"));
    REQUIRE_FALSE(IsStorablePath("a/"));
    REQUIRE_FALSE(IsStorablePath("a\\b"));
    REQUIRE_FALSE(IsStorablePath(std::string("a\nb")));
    REQUIRE_FALSE(IsStorablePath(std::string(MAX_PATH_LENGTH + 1, 'a')));
}
