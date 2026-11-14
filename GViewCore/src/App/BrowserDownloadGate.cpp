// Download gate of the web build. AppCUI hands a file of the application to the page (File dialog "Download", the
// download that follows a Save dialog, OS::DownloadFile) through Module.appcui.download(name, bytes), which calls the
// onDownload option of the page (GView/web/gview-page.js); the page asks _gview_browser_download_allowed
// (BrowserHost.cpp) before it lets the browser save anything. The hook does not see the path of the file, only its
// name and bytes, so a task file is recognised by its content.
//
// Refused:
//   * everything while Learning and Evaluation Mode is in use (any session state but Disconnected: Active, Expired,
//     Legacy, Error, ...);
//   * everything while the course policy restricts Export;
//   * any file whose SHA-256 is in the denylist of delivered items: the SHA-256 of every Learning item delivered in this
//     browser (any delivery mode), kept encrypted by the page as a secret (Browser::Secrets::LEARNING_TASK_HASHES,
//     newest MAX_TASK_HASHES entries);
//   * any file whose bytes are those of a regular file under one of the task roots (LearningTaskRoots: the default and
//     the configured download folder, and every folder of the home folder that holds a task manifest). A scan that
//     fails or reaches its bounds refuses (fail closed).
// This keeps the cleartext task files from reaching the file system of the machine through the browser; it is not data
// loss prevention: a copy whose bytes were modified (a single byte is enough) is not recognised.
//
// Task files of earlier sessions, restored from the storage of the browser into the home folder: they are kept (OPFS
// keeps them encrypted, they are in clear only in the in-memory file system of the page) and not downloadable -
// Stored files > Download refuses their paths (StoredFilesWindow.cpp), the File dialog / Save downloads refuse their
// content (this file). They are not deleted automatically; the student can delete them in File > Stored files.
//
// The matching, the folder search and the denylist are platform neutral (unit tests); the rest is web build only.

#include "Internal.hpp"

#ifdef BUILD_FOR_WASM
#    include "Learning/LearningSession.hpp"
#    include "Learning/TaskFiles.hpp"
#endif

#include <algorithm>
#include <cstring>

namespace GView::App::Browser::DownloadGate
{
namespace
{
    // 64 hex characters, lowered; empty when it is not a SHA-256
    std::string NormalizeSha256Hex(std::string_view hex)
    {
        if (hex.size() != 64)
            return {};
        std::string out(hex);
        for (auto& c : out)
        {
            if (c >= 'A' && c <= 'F')
                c = static_cast<char>(c - 'A' + 'a');
            else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return {};
        }
        return out;
    }

    std::u8string_view AsU8(std::string_view s)
    {
        return std::u8string_view(reinterpret_cast<const char8_t*>(s.data()), s.size());
    }
} // namespace

TaskFileMatch FindFileWithContent(const std::filesystem::path& root, BufferView data)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    // the root itself is resolved (a configured folder may be reached through a link); nothing under it is
    const auto rootStatus = fs::status(root, ec);
    if (ec)
        return rootStatus.type() == fs::file_type::not_found ? TaskFileMatch::None : TaskFileMatch::Error;
    if (rootStatus.type() == fs::file_type::not_found)
        return TaskFileMatch::None;
    if (rootStatus.type() != fs::file_type::directory)
        return TaskFileMatch::None; // nothing can be under it

    uint8 expected[32];
    bool hashed  = false;
    uint32 count = 0;
    // no follow_directory_symlink: a link to a folder is listed as a link and never entered
    auto it = fs::recursive_directory_iterator(root, fs::directory_options::none, ec);
    if (ec)
        return TaskFileMatch::Error;
    for (; it != fs::recursive_directory_iterator(); it.increment(ec))
    {
        if (ec)
            return TaskFileMatch::Error;
        if (++count > MAX_SCANNED_ENTRIES)
            return TaskFileMatch::Error;
        const auto type = it->symlink_status(ec).type(); // the entry itself, never the target of a link
        if (ec)
            return TaskFileMatch::Error;
        if (type == fs::file_type::directory)
        {
            // a folder that can not be scanned could hold a copy: refuse rather than skip it
            if (it.depth() + 1 >= MAX_SCAN_DEPTH)
                return TaskFileMatch::Error;
            continue;
        }
        if (type != fs::file_type::regular)
            continue; // links, devices, pipes...
        const auto size = it->file_size(ec);
        if (ec)
            return TaskFileMatch::Error;
        if (size != data.GetLength())
            continue;
        if (!hashed)
        {
            if (!Security::Crypto::Internal::ComputeSHA256(data, expected).ok)
                return TaskFileMatch::Error;
            hashed = true;
        }
        std::vector<uint8_t> actual;
        if (!Security::Crypto::Internal::ComputeFileSHA256(it->path(), actual).ok || actual.size() != sizeof(expected))
            return TaskFileMatch::Error;
        if (std::memcmp(actual.data(), expected, sizeof(expected)) == 0)
            return TaskFileMatch::Match;
    }
    if (ec)
        return TaskFileMatch::Error;
    return TaskFileMatch::None;
}

bool IsUnderRoot(std::string_view relativePath, const std::vector<std::string>& roots)
{
    const auto normalise = [](std::string_view p) {
        auto s = std::filesystem::path(AsU8(p)).lexically_normal().generic_u8string();
        std::string out(reinterpret_cast<const char*>(s.data()), s.size());
        while (out.size() > 1 && out.back() == '/')
            out.pop_back();
        if (out == ".")
            out.clear();
        return out;
    };
    const std::string path = normalise(relativePath);
    // a path that leaves the folder ("../x") or is absolute is never "under" a root relative to it
    if ((!path.empty() && path.front() == '/') || path == ".." || path.starts_with("../"))
        return false;
    for (const auto& r : roots)
    {
        const std::string root = normalise(r);
        if (root == ".." || root.starts_with("../") || (!root.empty() && root.front() == '/'))
            continue;
        if (root.empty())
            return true; // the folder itself: everything in it
        if (path == root || (path.size() > root.size() && path.starts_with(root) && path[root.size()] == '/'))
            return true;
    }
    return false;
}

std::vector<std::filesystem::path> FindFoldersWithFile(const std::filesystem::path& home, std::string_view fileName)
{
    namespace fs = std::filesystem;
    std::vector<fs::path> folders;
    const fs::path wanted(AsU8(fileName));
    std::error_code ec;
    auto it      = fs::recursive_directory_iterator(home, fs::directory_options::skip_permission_denied, ec);
    uint32 count = 0;
    for (; !ec && it != fs::recursive_directory_iterator(); it.increment(ec))
    {
        if (++count > MAX_SCANNED_ENTRIES)
            break;
        const auto type = it->symlink_status(ec).type();
        if (ec)
            break;
        if (type == fs::file_type::directory)
        {
            if (it.depth() + 1 >= MAX_SCAN_DEPTH)
                it.disable_recursion_pending();
            continue;
        }
        if (type == fs::file_type::regular && it->path().filename().native() == wanted.native())
        {
            auto folder = it->path().parent_path().lexically_normal();
            if (std::find(folders.begin(), folders.end(), folder) == folders.end())
                folders.push_back(std::move(folder));
        }
    }
    return folders;
}

std::vector<std::string> ParseTaskHashes(std::string_view text)
{
    std::vector<std::string> hashes;
    while (!text.empty())
    {
        const auto end        = text.find('\n');
        const auto line       = text.substr(0, end);
        text                  = end == std::string_view::npos ? std::string_view() : text.substr(end + 1);
        const std::string sha = NormalizeSha256Hex(line);
        if (!sha.empty() && !ContainsTaskHash(hashes, sha))
            hashes.push_back(sha);
    }
    if (hashes.size() > MAX_TASK_HASHES)
        hashes.erase(hashes.begin(), hashes.end() - static_cast<std::ptrdiff_t>(MAX_TASK_HASHES)); // keep the newest
    return hashes;
}

std::string SerializeTaskHashes(const std::vector<std::string>& hashes)
{
    std::string text;
    text.reserve(hashes.size() * 65);
    for (const auto& h : hashes)
    {
        if (!text.empty())
            text.push_back('\n');
        text += h;
    }
    return text;
}

bool AddTaskHash(std::vector<std::string>& hashes, std::string_view sha256Hex)
{
    std::string sha = NormalizeSha256Hex(sha256Hex);
    if (sha.empty() || ContainsTaskHash(hashes, sha))
        return false;
    hashes.push_back(std::move(sha));
    while (hashes.size() > MAX_TASK_HASHES)
        hashes.erase(hashes.begin()); // the oldest first
    return true;
}

bool ContainsTaskHash(const std::vector<std::string>& hashes, std::string_view sha256Hex)
{
    const std::string sha = NormalizeSha256Hex(sha256Hex);
    return !sha.empty() && std::find(hashes.begin(), hashes.end(), sha) != hashes.end();
}
} // namespace GView::App::Browser::DownloadGate

#ifdef BUILD_FOR_WASM
namespace GView::App::Browser
{
namespace
{
    namespace Learning = GView::Security::Learning;

    std::string ConfiguredLearningDownloadFolder()
    {
        // the same setting as LoadLearningSettings (LearningModeWindow.cpp)
        auto ini = AppCUI::Application::GetAppSettings();
        if (!ini)
            return {};
        auto sect = ini->GetSection("GView");
        if (!sect.Exists())
            return {};
        auto folder = sect.GetValue("LearningDownloadFolder").AsStringView();
        return folder.has_value() ? std::string(*folder) : std::string();
    }

    std::vector<std::string> LoadTaskHashes()
    {
        auto text   = Secrets::Get(Secrets::LEARNING_TASK_HASHES);
        auto hashes = DownloadGate::ParseTaskHashes(text.value_or(std::string()));
        return hashes;
    }

    std::string Sha256Hex(BufferView data)
    {
        uint8 hash[32];
        if (!Security::Crypto::Internal::ComputeSHA256(data, hash).ok)
            return {};
        static constexpr char HEX[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(64);
        for (const auto b : hash)
        {
            hex.push_back(HEX[b >> 4]);
            hex.push_back(HEX[b & 0x0F]);
        }
        return hex;
    }
} // namespace

std::vector<std::filesystem::path> LearningTaskRoots()
{
    std::vector<std::filesystem::path> roots;
    // a folder that is (or is under) a root already listed is not scanned twice
    const auto add = [&roots](const std::filesystem::path& p) {
        auto n = p.lexically_normal();
        if (n.empty())
            return;
        for (const auto& r : roots)
        {
            const auto rel = n.lexically_relative(r).generic_string();
            if (!rel.empty() && rel != ".." && !rel.starts_with("../"))
                return;
        }
        roots.push_back(std::move(n));
    };
    add(HomeFolder() / "Documents" / "GView"); // the default: always, also for the files of earlier sessions
    auto& session = Learning::GetSession();
    if (session.HasSession())
        add(Learning::DownloadBaseFolder(session.GetSettings().downloadFolder)); // what the session writes into
    add(Learning::DownloadBaseFolder(ConfiguredLearningDownloadFolder()));       // what the next session would use
    // task folders of a download folder configured earlier (the setting can be changed by the student)
    for (const auto& folder : DownloadGate::FindFoldersWithFile(HomeFolder(), Learning::TASK_MANIFEST_FILE_NAME))
        add(folder);
    return roots;
}

std::vector<std::string> LearningTaskRootsRelativeToHome()
{
    std::vector<std::string> result;
    const auto home = HomeFolder().lexically_normal();
    for (const auto& root : LearningTaskRoots())
    {
        const auto rel = root.lexically_relative(home);
        if (rel.empty())
            continue; // not under the home folder: the store never holds it
        const auto s = rel.generic_string();
        if (s == ".." || s.starts_with("../"))
            continue;
        result.push_back(s);
    }
    return result;
}

void RecordDeliveredTaskHash(std::string_view sha256Hex)
{
    auto hashes = LoadTaskHashes();
    if (DownloadGate::AddTaskHash(hashes, sha256Hex))
        Secrets::Set(Secrets::LEARNING_TASK_HASHES, DownloadGate::SerializeTaskHashes(hashes));
}

bool IsBrowserDownloadAllowed(BufferView data, std::string& refusalReason)
{
    refusalReason.clear();
    if (Learning::GetSession().HasSession())
    {
        refusalReason = "downloads are disabled while Learning and Evaluation Mode is in use (End session first)";
        return false;
    }
    if (GView::App::IsFeatureRestricted(Security::RestrictedMode::Feature::Export))
    {
        refusalReason = "exports are restricted by the course policy";
        return false;
    }
    const std::string sha = Sha256Hex(data);
    if (sha.empty())
    {
        refusalReason = "the file could not be checked";
        return false;
    }
    if (DownloadGate::ContainsTaskHash(LoadTaskHashes(), sha))
    {
        refusalReason = "Learning task files can not be downloaded";
        return false;
    }
    for (const auto& root : LearningTaskRoots())
    {
        switch (DownloadGate::FindFileWithContent(root, data))
        {
        case DownloadGate::TaskFileMatch::None:
            break;
        case DownloadGate::TaskFileMatch::Match:
            refusalReason = "Learning task files can not be downloaded";
            return false;
        case DownloadGate::TaskFileMatch::Error:
            refusalReason = "the Learning task folder could not be checked";
            return false;
        }
    }
    return true;
}
} // namespace GView::App::Browser
#endif
