// Unit tests for the private temporary folder (TemporaryFolder.cpp). The names come from hostile archives (entry names
// with traversal sequences, separators, very long names) and the content is usually malware, so the tests check that
// files stay inside the private folder, are removed with their handle and that an unusable base folder fails closed.

#include "Internal.hpp"

#include <catch.hpp>

#include <chrono>
#include <cstring>
#include <fstream>
#include <memory>
#include <random>
#include <vector>

#if !defined(BUILD_FOR_WINDOWS)
#    include <fcntl.h>
#    include <sys/file.h>
#    include <unistd.h>
#endif

using namespace GView::App;
namespace fs = std::filesystem;

namespace
{
struct ScratchFolder {
    fs::path path;
    ScratchFolder()
    {
        std::random_device rd;
        path = fs::temp_directory_path() / ("gview-tempfolder-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
        // every test starts with a fresh private folder under this base
        TemporaryFolderAccess::RemoveFolder();
        TemporaryFolderAccess::SetBaseFolder(path);
    }
    ~ScratchFolder()
    {
        TemporaryFolderAccess::RemoveFolder();
        TemporaryFolderAccess::SetBaseFolder({});
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::vector<uint8> MakeContent(size_t size)
{
    std::vector<uint8> content(size);
    for (size_t i = 0; i < size; i++)
        content[i] = static_cast<uint8>((i * 0x9D) ^ (i >> 8));
    return content;
}

bool InitCache(GView::Utils::DataCache& cache, const std::vector<uint8>& content)
{
    auto file = std::make_unique<AppCUI::OS::MemoryFile>();
    if (!file->Create(content.data(), content.size()))
        return false;
    return cache.Init(std::move(file), 1); // 64K cache => larger contents are written in several chunks
}

std::vector<uint8> ReadFile(const fs::path& p)
{
    std::ifstream in(p, std::ios::binary);
    return std::vector<uint8>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}
} // namespace

TEST_CASE("TemporaryFolder: hostile names are sanitized", "[TemporaryFolder]")
{
    const auto S = [](std::u16string_view name) { return TemporaryFolderAccess::SanitizeFileName(name); };

    REQUIRE(S(u"sample.exe") == "sample.exe");
    REQUIRE(S(u"../../../Windows/System32/evil.dll") == "evil.dll");
    REQUIRE(S(u"..\\..\\evil.exe") == "evil.exe");
    REQUIRE(S(u"dir/") == "object");
    REQUIRE(S(u"") == "object");
    REQUIRE(S(u"..") == "object");
    REQUIRE(S(u"....") == "object");
    REQUIRE(S(u".bashrc") == "bashrc");
    REQUIRE(S(u"name.exe...") == "name.exe");
    REQUIRE(S(u"a b:c*d?e\"f<g>h|i") == "a_b_c_d_e_f_g_h_i");
    REQUIRE(S(std::u16string{ char16_t(0x0219), char16_t(0x021B) } + u".ps1") == "__.ps1"); // non-ASCII (no source-encoding dependency)
    REQUIRE(S(u"C:evil.exe") == "C_evil.exe");

    // long names keep a short extension and are capped
    const std::u16string longStem(300, u'a');
    const auto withExt = S(longStem + u".msi");
    REQUIRE(withExt.size() == TemporaryFolderAccess::MAX_NAME_LENGTH);
    REQUIRE(withExt.ends_with(".msi"));
    const auto longExt = S(u"x." + longStem);
    REQUIRE(longExt.size() == TemporaryFolderAccess::MAX_NAME_LENGTH);
    REQUIRE(S(std::u16string(100000, u'.') + u"x.exe") == "x.exe");
}

TEST_CASE("TemporaryFolder: content is written inside the private folder", "[TemporaryFolder]")
{
    ScratchFolder scratch;
    const auto content = MakeContent(300000);
    GView::Utils::DataCache cache;
    REQUIRE(InitCache(cache, content));

    std::string error;
    const auto folder = TemporaryFolderAccess::GetFolder(error);
    REQUIRE(folder.has_value());
    REQUIRE(folder->parent_path() == scratch.path);
#if !defined(BUILD_FOR_WINDOWS)
    REQUIRE((fs::status(*folder).permissions() & fs::perms::all) == fs::perms::owner_all);
#endif

    TemporaryFile tmp;
    const auto status = TemporaryFolderAccess::Write(cache, u"../../../../outside/evil.exe", tmp);
    REQUIRE(status.ok);
    REQUIRE(tmp.IsValid());
    REQUIRE(tmp.GetPath().parent_path() == *folder);
    REQUIRE(tmp.GetPath().filename().string().ends_with("-evil.exe"));
    REQUIRE(ReadFile(tmp.GetPath()) == content);
    REQUIRE_FALSE(fs::exists(scratch.path / "outside"));

    // same hint twice => two different files
    TemporaryFile second;
    REQUIRE(TemporaryFolderAccess::Write(cache, u"evil.exe", second).ok);
    REQUIRE(second.GetPath() != tmp.GetPath());

    // moving transfers ownership, destroying / reassigning removes the file
    const auto firstPath = tmp.GetPath();
    TemporaryFile moved(std::move(tmp));
    REQUIRE_FALSE(tmp.IsValid());
    REQUIRE(fs::exists(firstPath));
    const auto secondPath = second.GetPath();
    moved = std::move(second);
    REQUIRE_FALSE(fs::exists(firstPath));
    REQUIRE(fs::exists(secondPath));
    moved.Remove();
    REQUIRE_FALSE(fs::exists(secondPath));

    // the whole folder goes away (application exit)
    TemporaryFile leftover;
    REQUIRE(TemporaryFolderAccess::Write(cache, u"leftover.bin", leftover).ok);
    TemporaryFolderAccess::RemoveFolder();
    REQUIRE_FALSE(fs::exists(*folder));
}

TEST_CASE("TemporaryFolder: empty objects and unusable base folders", "[TemporaryFolder]")
{
    ScratchFolder scratch;

    GView::Utils::DataCache empty;
    REQUIRE(InitCache(empty, {}));
    TemporaryFile tmp;
    REQUIRE(TemporaryFolderAccess::Write(empty, u"empty.bin", tmp).ok);
    REQUIRE(fs::file_size(tmp.GetPath()) == 0);
    tmp.Remove();

    // a configured base that does not exist fails closed: nothing is written anywhere else
    TemporaryFolderAccess::RemoveFolder();
    TemporaryFolderAccess::SetBaseFolder(scratch.path / "missing");
    const auto content = MakeContent(100);
    GView::Utils::DataCache cache;
    REQUIRE(InitCache(cache, content));
    const auto status = TemporaryFolderAccess::Write(cache, u"x.exe", tmp);
    REQUIRE_FALSE(status.ok);
    REQUIRE_FALSE(status.message.empty());
    REQUIRE_FALSE(tmp.IsValid());
    REQUIRE_FALSE(fs::exists(scratch.path / "missing"));
}

TEST_CASE("TemporaryFolder: folders of GView instances that are gone are removed", "[TemporaryFolder]")
{
    ScratchFolder scratch;
    const auto old = fs::file_time_type::clock::now() - std::chrono::minutes(10);
    const auto makeFolder = [&](const char* name, bool withLock, bool oldLock) {
        const auto folder = scratch.path / name;
        fs::create_directories(folder / "sub");
        std::ofstream(folder / "1-sample.exe") << "MZ";
        std::ofstream(folder / "sub" / "x.bin") << "x";
        if (withLock) {
            std::ofstream(folder / ".gview-folder.lock").flush();
            if (oldLock)
                fs::last_write_time(folder / ".gview-folder.lock", old);
        }
        return folder;
    };
    const auto stale     = makeFolder("GView-STALE1", true, true);
    const auto fresh     = makeFolder("GView-FRESH1", true, false); // may be a folder that is being created right now
    const auto noLock    = makeFolder("GView-NOLOCK", false, false);
    const auto unrelated = makeFolder("Other-STALE1", true, true);
    const auto alive     = makeFolder("GView-ALIVE1", true, true);

    // a running instance holds its lock (Windows: an open handle denies the exclusive open; POSIX: flock)
#if defined(BUILD_FOR_WINDOWS)
    std::ofstream holder(alive / ".gview-folder.lock", std::ios::app);
    REQUIRE(holder.is_open());
#else
    const int holder = open((alive / ".gview-folder.lock").c_str(), O_RDWR);
    REQUIRE(holder >= 0);
    REQUIRE(flock(holder, LOCK_EX | LOCK_NB) == 0);
#endif

    std::string error;
    const auto folder = TemporaryFolderAccess::GetFolder(error); // first use => sweep
    REQUIRE(folder.has_value());
    REQUIRE(fs::exists(*folder / ".gview-folder.lock"));

    REQUIRE_FALSE(fs::exists(stale));
    REQUIRE(fs::exists(fresh / "1-sample.exe"));
    REQUIRE(fs::exists(noLock / "1-sample.exe"));
    REQUIRE(fs::exists(unrelated / "1-sample.exe"));
    REQUIRE(fs::exists(alive / "1-sample.exe"));

#if defined(BUILD_FOR_WINDOWS)
    holder.close();
#else
    close(holder);
#endif
}

#if defined(BUILD_FOR_WINDOWS)
TEST_CASE("TemporaryFolder: a copy still open at exit is removed by the next instance", "[TemporaryFolder]")
{
    ScratchFolder scratch;
    const auto content = MakeContent(1000);
    GView::Utils::DataCache cache;
    REQUIRE(InitCache(cache, content));
    TemporaryFile tmp;
    REQUIRE(TemporaryFolderAccess::Write(cache, u"inner.zip", tmp).ok);
    const auto folder = tmp.GetPath().parent_path();
    {
        // like the minizip-ng reader of a window that AppCUI never destroys: Windows can not delete the file
        std::ifstream reader(tmp.GetPath(), std::ios::binary);
        REQUIRE(reader.is_open());
        TemporaryFolderAccess::RemoveFolder(); // application exit
        REQUIRE(fs::exists(tmp.GetPath()));
        REQUIRE(fs::exists(folder / ".gview-folder.lock")); // kept so that the next instance finishes the job
    }
    fs::last_write_time(folder / ".gview-folder.lock", fs::file_time_type::clock::now() - std::chrono::minutes(10));

    std::string error;
    REQUIRE(TemporaryFolderAccess::GetFolder(error).has_value()); // next instance
    REQUIRE_FALSE(fs::exists(folder));
}
#endif

TEST_CASE("TemporaryFolder: DropToTemporaryFile writes an object", "[TemporaryFolder]")
{
    ScratchFolder scratch;
    const auto content = MakeContent(70000);
    GView::Utils::DataCache cache;
    REQUIRE(InitCache(cache, content));
    GView::Object obj(GView::Object::Type::MemoryBuffer, std::move(cache), nullptr, "inner/sample.dll", "outer.zip.drop/inner/sample.dll", 0);

    TemporaryFile tmp;
    REQUIRE_FALSE(DropToTemporaryFile(nullptr, tmp).ok);
    REQUIRE(DropToTemporaryFile(&obj, tmp).ok);
    REQUIRE(tmp.GetPath().filename().string().ends_with("-sample.dll"));
    REQUIRE(ReadFile(tmp.GetPath()) == content);
}
