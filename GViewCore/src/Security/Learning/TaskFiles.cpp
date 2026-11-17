#include "TaskFiles.hpp"

#include <fstream>
#include <nlohmann/json.hpp>

#ifdef BUILD_FOR_WINDOWS
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#endif

namespace GView::Security::Learning
{
namespace
{
    constexpr size_t MAX_MANIFEST_BYTES  = 1024 * 1024;
    constexpr size_t MAX_MANIFEST_ITEMS  = 4096;
    constexpr size_t MAX_WEEK_NAME_BYTES = 48; // with the server (64) and file (128) names: stays near Windows' MAX_PATH

    std::string FileSha256Hex(const std::filesystem::path& path)
    {
        std::vector<uint8_t> hash;
        if (!Crypto::Internal::ComputeFileSHA256(path, hash).ok || hash.size() != 32)
            return {};
        return ToHex(BufferView(hash.data(), hash.size()));
    }

    bool IsSha256Hex(std::string_view s) noexcept
    {
        if (s.size() != 64)
            return false;
        for (char c : s)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        return true;
    }

    // file names are compared case-insensitively: Windows and macOS file systems usually are
    bool SameFileName(std::string_view a, std::string_view b) noexcept
    {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); i++)
        {
            char x = a[i], y = b[i];
            if (x >= 'A' && x <= 'Z')
                x = static_cast<char>(x - 'A' + 'a');
            if (y >= 'A' && y <= 'Z')
                y = static_cast<char>(y - 'A' + 'a');
            if (x != y)
                return false;
        }
        return true;
    }

    bool IsRegularFile(const std::filesystem::path& p)
    {
        std::error_code ec;
        return std::filesystem::is_regular_file(p, ec);
    }
} // namespace

std::filesystem::path TaskFolder(std::string_view configuredFolder, std::string_view serverUrl, std::string_view weekName)
{
    return DownloadBaseFolder(configuredFolder) / PathFromUtf8(ServerFolderName(serverUrl)) /
           PathFromUtf8(SanitizePathComponent(weekName, "Course", MAX_WEEK_NAME_BYTES));
}

TaskFileStore::TaskFileStore(std::filesystem::path taskFolder) : folder(std::move(taskFolder))
{
    Load();
}

void TaskFileStore::Load()
{
    entries.clear();
    try
    {
        const auto path = folder / PathFromUtf8(TASK_MANIFEST_FILE_NAME);
        std::error_code ec;
        const auto size = std::filesystem::file_size(path, ec);
        if (ec || size == 0 || size > MAX_MANIFEST_BYTES)
            return;
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open())
            return;
        std::string text(static_cast<size_t>(size), '\0');
        f.read(text.data(), static_cast<std::streamsize>(text.size()));
        text.resize(static_cast<size_t>(f.gcount()));
        const auto j = nlohmann::json::parse(text, nullptr, false);
        if (j.is_discarded() || !j.is_object())
            return;
        const auto items = j.find("items");
        if (items == j.end() || !items->is_object())
            return;
        // the manifest lives in a folder the student controls: every entry is validated like server data
        for (const auto& [name, value] : items->items())
        {
            if (entries.size() >= MAX_MANIFEST_ITEMS)
                break;
            if (!IsValidItemName(name) || !value.is_object())
                continue;
            const auto file = value.find("file");
            if (file == value.end() || !file->is_string())
                continue;
            Entry e;
            e.file = file->get<std::string>();
            if (e.file.empty() || SanitizePathComponent(e.file, "") != e.file || IsTakenByAnotherItem(e.file, name))
                continue; // also: two items can never share a file, whatever the manifest says
            if (const auto sha = value.find("sha256"); sha != value.end() && sha->is_string() && IsSha256Hex(sha->get_ref<const std::string&>()))
                e.sha256 = sha->get<std::string>();
            if (const auto v = value.find("itemVersion"); v != value.end() && v->is_number_unsigned() && v->get<uint64_t>() <= UINT32_MAX)
                e.itemVersion = static_cast<uint32>(v->get<uint64_t>());
            entries.emplace(name, std::move(e));
        }
    }
    catch (...)
    {
        entries.clear();
    }
}

bool TaskFileStore::Save() const
{
    std::filesystem::path tmp;
    try
    {
        nlohmann::json items = nlohmann::json::object();
        for (const auto& [name, e] : entries)
            items[name] = { { "file", e.file }, { "sha256", e.sha256 }, { "itemVersion", e.itemVersion } };
        const nlohmann::json j    = { { "format", 1 }, { "items", std::move(items) } };
        const std::string text    = j.dump(2);
        const auto finalPath      = folder / PathFromUtf8(TASK_MANIFEST_FILE_NAME);
        tmp                       = finalPath;
        tmp += ".tmp";
        std::error_code ec;
        std::filesystem::create_directories(folder, ec);
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f.is_open())
                return false;
            f.write(text.data(), static_cast<std::streamsize>(text.size()));
            f.flush();
            if (!f.good())
            {
                f.close();
                std::filesystem::remove(tmp, ec);
                return false;
            }
        }
#ifdef BUILD_FOR_WINDOWS
        // a hidden target can make the replace fail: clear its attributes first, hide the new one afterwards
        SetFileAttributesW(finalPath.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (!MoveFileExW(tmp.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            std::filesystem::remove(tmp, ec);
            return false;
        }
        SetFileAttributesW(finalPath.c_str(), FILE_ATTRIBUTE_HIDDEN);
#else
        std::filesystem::rename(tmp, finalPath, ec);
        if (ec)
        {
            std::filesystem::remove(tmp, ec);
            return false;
        }
#endif
        return true;
    }
    catch (...)
    {
        std::error_code ec;
        if (!tmp.empty())
            std::filesystem::remove(tmp, ec);
        return false;
    }
}

bool TaskFileStore::IsTakenByAnotherItem(std::string_view file, std::string_view itemName) const
{
    // WriteFileAtomic writes "<file>.part" first: "x" and "x.part" must not belong to two different items either
    const auto clash = [](std::string_view a, std::string_view b) {
        constexpr std::string_view PART = ".part";
        if (SameFileName(a, b))
            return true;
        if (a.size() == b.size() + PART.size() && SameFileName(a.substr(0, b.size()), b) && SameFileName(a.substr(b.size()), PART))
            return true;
        return b.size() == a.size() + PART.size() && SameFileName(b.substr(0, a.size()), a) && SameFileName(b.substr(a.size()), PART);
    };
    if (clash(file, TASK_MANIFEST_FILE_NAME))
        return true;
    for (const auto& [name, e] : entries)
    {
        if (name != itemName && clash(e.file, file))
            return true;
    }
    return false;
}

std::optional<std::filesystem::path> TaskFileStore::FindUpToDate(std::string_view itemName, std::string_view sha256) const
{
    if (!IsSha256Hex(sha256))
        return std::nullopt;
    const auto it = entries.find(itemName);
    if (it == entries.end())
        return std::nullopt;
    auto path = folder / PathFromUtf8(it->second.file);
    if (!IsRegularFile(path) || FileSha256Hex(path) != sha256)
        return std::nullopt;
    return path;
}

TaskFileStore::Plan TaskFileStore::PlanFor(std::string_view itemName, std::string_view deliveredFileName, std::string_view serverSha256) const
{
    Plan plan;
    const auto it = entries.find(itemName);
    if (it != entries.end())
    {
        plan.file = it->second.file; // the item keeps the file it already has
    }
    else
    {
        // first time in this folder: the delivered name, unless another item of the course already owns it
        const std::string preferred = SanitizeFileName(deliveredFileName.empty() ? itemName : deliveredFileName);
        plan.file                   = preferred;
        for (uint32 n = 1; IsTakenByAnotherItem(plan.file, itemName); n++)
        {
            std::string prefix(itemName);
            if (n > 1)
                prefix += "-" + std::to_string(n);
            plan.file = SanitizeFileName(prefix + "-" + preferred);
        }
    }
    plan.path = folder / PathFromUtf8(plan.file);

    if (!IsRegularFile(plan.path))
    {
        plan.state = LocalState::Missing;
        return plan;
    }
    const std::string local = FileSha256Hex(plan.path);
    if (!local.empty() && local == serverSha256)
        plan.state = LocalState::SameAsServer;
    else if (!local.empty() && it != entries.end() && local == it->second.sha256)
        plan.state = LocalState::Outdated;
    else
        plan.state = LocalState::Modified; // also: a file GView did not write (or cannot read) is in the way
    return plan;
}

Utils::GStatus TaskFileStore::Store(
      const Plan& plan, std::string_view itemName, BufferView data, std::string_view sha256, uint32 itemVersion, std::filesystem::path& outPath)
{
    auto st = WriteFileAtomic(folder, plan.file, data, sha256, outPath);
    if (!st.ok)
        return st;
    auto& e       = entries[std::string(itemName)];
    e.file        = PathToUtf8(outPath.filename());
    e.sha256      = std::string(sha256);
    e.itemVersion = itemVersion;
    Save();
    return Utils::GStatus::Ok();
}

void TaskFileStore::Keep(const Plan& plan, std::string_view itemName, std::string_view serverSha256, uint32 itemVersion)
{
    auto it = entries.find(itemName);
    if (plan.state == LocalState::SameAsServer || it == entries.end() || it->second.file != plan.file)
    {
        // the reference is the server version: a kept Modified file differs from it and stays Modified; its version
        // is unknown (0), since the bytes on disk are not the server's
        auto& e       = entries[std::string(itemName)];
        e.file        = plan.file;
        e.sha256      = IsSha256Hex(serverSha256) ? std::string(serverSha256) : std::string();
        e.itemVersion = plan.state == LocalState::SameAsServer ? itemVersion : 0;
    }
    // else: a Modified copy already recorded keeps the hash GView wrote, so it is still reported as Modified later
    Save();
}

uint32 TaskFileStore::RecordedVersion(std::string_view itemName) const
{
    const auto it = entries.find(itemName);
    return it == entries.end() ? 0 : it->second.itemVersion;
}

std::optional<std::filesystem::path> TaskFileStore::KnownFile(std::string_view itemName) const
{
    const auto it = entries.find(itemName);
    if (it == entries.end())
        return std::nullopt;
    auto path = folder / PathFromUtf8(it->second.file);
    if (!IsRegularFile(path))
        return std::nullopt;
    return path;
}
} // namespace GView::Security::Learning
