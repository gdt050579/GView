// Private, per-process temporary folder. Used for the APIs that need a real file (WinVerifyTrust, minizip-ng for archives
// larger than the cache): the content written here is usually hostile (malware extracted from a container), so
//  - the folder is created atomically with a random name and is accessible only to the current user (mkdtemp => 0700 on
//    POSIX; on Windows it inherits the ACL of the per-user %TEMP% folder or of the configured base folder),
//  - file names never come from object paths (no traversal): "<counter>-<sanitized object name>",
//  - a configured base folder that is unusable fails closed (nothing is silently written somewhere else),
//  - files are removed when their TemporaryFile handle is destroyed and the folder when GView exits.
// AppCUI does not destroy the desktop windows at exit, so a copy can still be open then (Windows refuses to delete it)
// and a crash leaves everything behind: each folder holds a lock file for the lifetime of its process, and the next
// GView instance removes the GView-* folders whose lock is free (older than STALE_FOLDER_AGE, to skip a folder that is
// being created).

#include "Internal.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <random>

#if defined(BUILD_FOR_WINDOWS)
#    define WIN32_LEAN_AND_MEAN
#    define NOMINMAX
#    include <Windows.h>
#else
#    include <fcntl.h>
#    include <stdlib.h> // mkdtemp
#    include <sys/file.h>
#    include <sys/stat.h> // lstat
#    include <unistd.h>
#endif

namespace GView::App
{
namespace fs = std::filesystem;

namespace
{
    constexpr std::string_view FOLDER_PREFIX  = "GView-";
    constexpr std::string_view LOCK_FILE_NAME = ".gview-folder.lock";
    constexpr auto STALE_FOLDER_AGE           = std::chrono::minutes(1);

    // lock held for the lifetime of the process: while it is held, no other GView instance removes the folder
    class FolderLock
    {
#if defined(BUILD_FOR_WINDOWS)
        HANDLE handle{ INVALID_HANDLE_VALUE };
#else
        int fd{ -1 };
#endif
      public:
        // creates the lock file (it must not exist) and takes the lock
        bool Create(const fs::path& lockFile)
        {
#if defined(BUILD_FOR_WINDOWS)
            // no sharing: other processes can neither open nor delete it while this handle is open (not inheritable)
            handle = CreateFileW(lockFile.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            return handle != INVALID_HANDLE_VALUE;
#else
            fd = open(lockFile.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
            return fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0;
#endif
        }
        // takes the lock of an existing lock file: fails while the process that created it is alive
        bool TryAcquire(const fs::path& lockFile)
        {
#if defined(BUILD_FOR_WINDOWS)
            handle = CreateFileW(lockFile.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            return handle != INVALID_HANDLE_VALUE;
#else
            fd = open(lockFile.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
            return fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0;
#endif
        }
        void Release() noexcept
        {
#if defined(BUILD_FOR_WINDOWS)
            if (handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
            handle = INVALID_HANDLE_VALUE;
#else
            if (fd >= 0)
                close(fd);
            fd = -1;
#endif
        }
        ~FolderLock()
        {
            Release();
        }
    };

    // removes the content of a folder, then the folder itself if nothing is left but its lock file (the lock is
    // released in between); a lock file that stays behind lets the next GView instance finish the job
    void RemoveLockedFolder(const fs::path& folder, FolderLock& lock) noexcept
    {
        try {
            std::vector<fs::path> entries;
            std::error_code ec;
            for (fs::directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec))
                if (it->path().filename() != LOCK_FILE_NAME)
                    entries.push_back(it->path());
            bool everythingRemoved = !ec;
            for (const auto& entry : entries) {
                std::error_code removeError;
                fs::remove_all(entry, removeError);
                everythingRemoved &= !removeError;
            }
            lock.Release();
            if (everythingRemoved)
                fs::remove_all(folder, ec);
        } catch (...) {
            lock.Release();
        }
    }

#if !defined(BUILD_FOR_WASM)
    // a real folder (not a symbolic link) owned by the current user. In a shared base folder (/tmp) another user can
    // create GView-* folders and swap them for a symbolic link at any time; folders of the current user can not be
    // renamed or replaced by others in a sticky folder, so only those are swept.
    bool IsOwnFolder(const fs::path& folder)
    {
#    if defined(BUILD_FOR_WINDOWS)
        (void) folder; // the default base folder (%TEMP%) is private to the user
        return true;
#    else
        struct stat st {};
        return lstat(folder.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid();
#    endif
    }
#endif

    // removes the GView-* folders left behind by GView instances that are no longer running
    void RemoveStaleFolders(const fs::path& base) noexcept
    {
#if !defined(BUILD_FOR_WASM) // single process and in-memory file system: nothing can be stale
        try {
            std::error_code ec;
            const auto now = fs::file_time_type::clock::now();
            for (fs::directory_iterator it(base, ec), end; !ec && it != end; it.increment(ec)) {
                try {
                    const auto name = it->path().filename().u8string();
                    std::error_code entryError;
                    if (!name.starts_with(u8"GView-") || it->is_symlink(entryError) || !it->is_directory(entryError) || !IsOwnFolder(it->path()))
                        continue;
                    const auto lockFile = it->path() / LOCK_FILE_NAME;
                    const auto created  = fs::last_write_time(lockFile, entryError); // fails when there is no lock file
                    if (entryError || now - created < STALE_FOLDER_AGE)
                        continue;
                    FolderLock lock;
                    // checked again right before the removal (the lock file was opened through the folder path)
                    if (lock.TryAcquire(lockFile) && IsOwnFolder(it->path()))
                        RemoveLockedFolder(it->path(), lock);
                } catch (...) {
                    // e.g. a name that can not be converted => not one of ours
                }
            }
        } catch (...) {
        }
#else
        (void) base;
#endif
    }

    struct FolderState {
        std::mutex lock;
        fs::path base;   // configured base folder (empty => system temporary directory)
        fs::path folder; // the folder of this process (empty => not created yet)
        FolderLock folderLock;
        bool staleFoldersRemoved{ false };
        std::atomic<uint64> counter{ 0 };

        void RemoveFolder() noexcept
        {
            if (!folder.empty())
                RemoveLockedFolder(folder, folderLock);
            folder.clear();
            staleFoldersRemoved = false; // a new folder (possibly under another base) sweeps its base again
        }
        ~FolderState()
        {
            RemoveFolder();
        }
    };

    FolderState& State()
    {
        static FolderState state;
        return state;
    }

    std::string PathToUTF8(const fs::path& p)
    {
        const auto u8 = p.u8string();
        return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
    }

    std::optional<fs::path> CreatePrivateFolder(const fs::path& base, std::string& error)
    {
#if defined(BUILD_FOR_WINDOWS)
        constexpr uint32 MAX_CREATE_ATTEMPTS = 16;
        std::random_device rd;
        for (uint32 i = 0; i < MAX_CREATE_ATTEMPTS; i++) {
            LocalString<32> name;
            name.SetFormat("%.*s%08X%08X", (int) FOLDER_PREFIX.size(), FOLDER_PREFIX.data(), static_cast<uint32>(rd()), static_cast<uint32>(rd()));
            const auto candidate = base / name.GetText();
            std::error_code ec;
            // false when it already exists: a folder that this process did not create is never reused
            if (fs::create_directory(candidate, ec))
                return candidate;
            if (ec) {
                error = "Unable to create a temporary folder in '" + PathToUTF8(base) + "': " + ec.message();
                return std::nullopt;
            }
        }
        error = "Unable to create a unique temporary folder in '" + PathToUTF8(base) + "'";
        return std::nullopt;
#else
        // mkdtemp creates the folder atomically with 0700 permissions
        auto pattern = (base / (std::string(FOLDER_PREFIX) + "XXXXXX")).string();
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back(0);
        if (mkdtemp(buffer.data()) == nullptr) {
            error = "Unable to create a temporary folder in '" + PathToUTF8(base) + "'";
            return std::nullopt;
        }
        return fs::path(buffer.data());
#endif
    }
} // namespace

//===============================[TemporaryFile]==================================
TemporaryFile::TemporaryFile(TemporaryFile&& other) noexcept : path(std::move(other.path))
{
    other.path.clear();
}
TemporaryFile& TemporaryFile::operator=(TemporaryFile&& other) noexcept
{
    if (this != &other) {
        Remove();
        path = std::move(other.path);
        other.path.clear();
    }
    return *this;
}
TemporaryFile::~TemporaryFile()
{
    Remove();
}
void TemporaryFile::Remove() noexcept
{
    if (path.empty())
        return;
    std::error_code ec;
    fs::remove(path, ec); // best effort: whatever is left is removed with the folder when GView exits
    path.clear();
}

//===============================[TemporaryFolderAccess]==================================
void TemporaryFolderAccess::SetBaseFolder(const std::filesystem::path& base)
{
    auto& s = State();
    std::lock_guard<std::mutex> guard(s.lock);
    s.base = base;
}

std::optional<std::filesystem::path> TemporaryFolderAccess::GetFolder(std::string& error)
{
    auto& s = State();
    std::lock_guard<std::mutex> guard(s.lock);
    if (!s.folder.empty())
        return s.folder;

    std::error_code ec;
    auto base = s.base;
    if (base.empty()) {
        base = fs::temp_directory_path(ec);
        if (ec) {
            error = "Unable to find the system temporary directory: " + ec.message();
            return std::nullopt;
        }
    }
    if (!fs::is_directory(base, ec)) {
        error = "The temporary folder '" + PathToUTF8(base) + "' does not exist";
        return std::nullopt;
    }
    if (!s.staleFoldersRemoved) {
        s.staleFoldersRemoved = true;
        RemoveStaleFolders(base);
    }
    auto folder = CreatePrivateFolder(base, error);
    if (!folder.has_value())
        return std::nullopt;
    // without its lock, another GView instance would remove the folder (and the copies in use) after a while
    if (!s.folderLock.Create(*folder / LOCK_FILE_NAME)) {
        s.folderLock.Release();
        fs::remove_all(*folder, ec);
        error = "Unable to lock the temporary folder '" + PathToUTF8(*folder) + "'";
        return std::nullopt;
    }
    s.folder = std::move(*folder);
    return s.folder;
}

std::string TemporaryFolderAccess::SanitizeFileName(std::u16string_view name)
{
    // archive entry names and object names may contain both separators
    const auto separator = name.find_last_of(u"/\\");
    if (separator != std::u16string_view::npos)
        name = name.substr(separator + 1);

    std::string result;
    result.reserve(std::min<size_t>(name.size(), MAX_NAME_LENGTH * 2));
    for (const auto ch : name) {
        if (result.size() >= MAX_NAME_LENGTH * 2) // only the tail (extension) of very long names matters
            result.erase(0, MAX_NAME_LENGTH);
        const bool allowed = (ch >= u'a' && ch <= u'z') || (ch >= u'A' && ch <= u'Z') || (ch >= u'0' && ch <= u'9') || ch == u'.' || ch == u'-' || ch == u'_';
        result.push_back(allowed ? static_cast<char>(ch) : '_');
    }

    // no leading dots (".", "..", hidden files) and no trailing dots (silently dropped by Windows)
    const auto first = result.find_first_not_of('.');
    result.erase(0, first == std::string::npos ? result.size() : first);
    while (!result.empty() && result.back() == '.')
        result.pop_back();

    if (result.size() > MAX_NAME_LENGTH) {
        // keep a short extension: WinVerifyTrust selects the SIP of scripts / installers by extension
        std::string extension;
        const auto dot = result.find_last_of('.');
        if (dot != std::string::npos && result.size() - dot <= 16)
            extension = result.substr(dot);
        result.resize(MAX_NAME_LENGTH - extension.size());
        result += extension;
    }
    if (result.empty())
        result = "object";
    return result;
}

Utils::GStatus TemporaryFolderAccess::Write(Utils::DataCache& cache, std::u16string_view nameHint, TemporaryFile& output)
{
    output.Remove();

    std::string error;
    const auto folder = GetFolder(error);
    if (!folder.has_value())
        return Utils::GStatus::Error(std::move(error));

    const uint64 size  = cache.GetSize();
    const uint32 chunk = cache.GetCacheSize();
    if (size > 0 && chunk == 0)
        return Utils::GStatus::Error("The object has no data cache");

    const auto id = State().counter.fetch_add(1) + 1;
    TemporaryFile result; // declared before the file object => the file is closed before a failed result is removed
    AppCUI::OS::File file;
    const auto filePath = *folder / (std::to_string(id) + "-" + SanitizeFileName(nameHint));
    if (!file.Create(filePath, false))
        return Utils::GStatus::Error("Unable to create the temporary file '" + PathToUTF8(filePath) + "'");
    result.path = filePath;

    for (uint64 offset = 0; offset < size;) {
        const uint32 toCopy = static_cast<uint32>(std::min<uint64>(chunk, size - offset));
        const auto buffer   = cache.Get(offset, toCopy, true);
        if (!buffer.IsValid() || buffer.GetLength() != toCopy) {
            file.Close();
            return Utils::GStatus::Error("Unable to read the content of the object");
        }
        if (!file.Write(buffer.GetData(), toCopy)) {
            file.Close();
            return Utils::GStatus::Error("Unable to write the temporary file '" + PathToUTF8(filePath) + "'");
        }
        offset += toCopy;
    }
    file.Close();

    output = std::move(result);
    return Utils::GStatus::Ok();
}

void TemporaryFolderAccess::RemoveFolder() noexcept
{
    auto& s = State();
    std::lock_guard<std::mutex> guard(s.lock);
    s.RemoveFolder();
}

//===============================[policy gated entry point]==================================
Utils::GStatus CORE_EXPORT DropToTemporaryFile(Reference<GView::Object> object, TemporaryFile& output)
{
    output.Remove();
    if (!object.IsValid())
        return Utils::GStatus::Error("Invalid object");
    // same rule as IsExportBlockedFor (a temporary file is a copy on disk that the user can reach), but silent: the
    // callers fall back to in-memory processing instead of failing the user's action
    if (Security::Learning::Hooks::IsMemoryOnlyObject(object) || IsFeatureRestricted(Security::RestrictedMode::Feature::Export))
        return Utils::GStatus::Error("Writing this content to disk is not allowed by the Learning and Evaluation Mode policy");
    return TemporaryFolderAccess::Write(object->GetData(), object->GetName(), output);
}
} // namespace GView::App
