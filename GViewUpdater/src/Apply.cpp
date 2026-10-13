#include "Apply.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <set>
#include <sstream>
#include <thread>

#ifdef _WIN32
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#else
#    include <cerrno>
#    include <cstring>
#    include <unistd.h>
#endif

namespace GViewUpdater
{
namespace fs = std::filesystem;

namespace
{
    fs::path FromUtf8(std::string_view s)
    {
        return fs::path(std::u8string(s.begin(), s.end()));
    }

    std::string ToUtf8(const fs::path& p)
    {
        const auto u8 = p.u8string();
        return std::string(u8.begin(), u8.end());
    }

    std::string Lower(std::string_view s)
    {
        std::string r(s);
        for (auto& c : r)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        return r;
    }

    class Logger
    {
        std::vector<std::string> pending; // lines logged before the log file could be opened
        std::ofstream file;
        const Options& options;

      public:
        explicit Logger(const Options& o) : options(o)
        {
        }
        void Open(const fs::path& path)
        {
            file.open(path, std::ios::app);
            if (file) {
                for (const auto& l : pending)
                    file << l << '\n';
                file.flush();
            }
            pending.clear();
        }
        void Write(std::string_view message)
        {
            char stamp[32] = {};
            const auto now = std::time(nullptr);
            std::tm tmv{};
#ifdef _WIN32
            localtime_s(&tmv, &now);
#else
            localtime_r(&now, &tmv);
#endif
            std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);
            std::string line = std::string(stamp) + " " + std::string(message);
            if (file.is_open()) {
                file << line << '\n';
                file.flush();
            } else {
                pending.push_back(line);
            }
            if (options.output)
                options.output(message);
            else
                std::printf("GViewUpdater: %.*s\n", static_cast<int>(message.size()), message.data());
        }
    };

    // ---------------------------------------------------------------- platform rename
    // Moves a file without ever replacing an existing destination. Retries transient Windows errors (antivirus scanners
    // and search indexers briefly open new files without FILE_SHARE_DELETE).
    bool MoveNoReplace(const fs::path& from, const fs::path& to, std::string& error)
    {
#ifdef _WIN32
        static constexpr int DELAYS_MS[] = { 0, 100, 200, 400, 800, 1600, 3000 };
        DWORD last = 0;
        for (const int delay : DELAYS_MS) {
            if (delay > 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            if (MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH))
                return true;
            last = GetLastError();
            if (last != ERROR_SHARING_VIOLATION && last != ERROR_ACCESS_DENIED && last != ERROR_LOCK_VIOLATION)
                break;
        }
        error = "MoveFileEx failed with error " + std::to_string(last);
        return false;
#else
        std::error_code ec;
        if (fs::exists(fs::symlink_status(to, ec))) {
            error = "destination already exists";
            return false;
        }
        if (::rename(from.c_str(), to.c_str()) == 0)
            return true;
        error = std::string("rename failed: ") + std::strerror(errno);
        return false;
#endif
    }

    struct JournalEntry {
        char kind; // 'D' = folder created in the target, 'M' = target file moved to old, 'P' = staged file placed
        std::string path;
    };

    class Journal
    {
        std::ofstream file;
        std::vector<JournalEntry> entries;

      public:
        bool Open(const fs::path& path)
        {
            file.open(path, std::ios::trunc);
            return static_cast<bool>(file);
        }
        bool Add(char kind, const std::string& path)
        {
            entries.push_back({ kind, path });
            file << kind << ' ' << path << '\n';
            file.flush();
            return static_cast<bool>(file);
        }
        const std::vector<JournalEntry>& Entries() const
        {
            return entries;
        }
    };

    bool CheckDirectory(const fs::path& p, std::string_view what, Logger& log)
    {
        std::error_code ec;
        const auto st = fs::symlink_status(p, ec);
        if (ec || !fs::is_directory(st)) {
            log.Write(std::string(what) + " is not a folder: " + ToUtf8(p));
            return false;
        }
        return true;
    }

    // a rename between staging and target must be a metadata-only operation on the same volume
    bool ProbeSameVolume(const fs::path& staging, const fs::path& target, Logger& log)
    {
#ifdef _WIN32
        const auto pid = std::to_string(GetCurrentProcessId());
#else
        const auto pid = std::to_string(::getpid());
#endif
        const auto a = staging / FromUtf8(".gvu-probe-" + pid);
        const auto b = target / FromUtf8(".gvu-probe-" + pid);
        std::error_code ec;
        {
            std::ofstream f(a, std::ios::trunc);
            if (!f) {
                log.Write("cannot write to the staging folder");
                return false;
            }
        }
        std::string error;
        if (!MoveNoReplace(a, b, error)) {
            fs::remove(a, ec);
            log.Write("the installation folder is not writable or not on the same volume as the staging folder (" + error + ")");
            return false;
        }
        fs::remove(b, ec);
        return true;
    }

    bool Rollback(const Journal& journal, const Options& o, Logger& log)
    {
        bool ok      = true;
        bool failOne = o.failRollback;
        const auto& entries = journal.Entries();
        for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
            std::string error;
            std::error_code ec;
            const auto rel = FromUtf8(it->path);
            bool stepOk    = true;
            if (failOne && it->kind != 'D') {
                failOne = false;
                stepOk  = false;
                error   = "simulated rollback failure";
            } else if (it->kind == 'P') {
                stepOk = MoveNoReplace(o.target / rel, o.staging / rel, error);
            } else if (it->kind == 'M') {
                stepOk = MoveNoReplace(o.old / rel, o.target / rel, error);
            } else if (it->kind == 'D') {
                fs::remove(o.target / rel, ec); // only removes it when empty
            }
            if (!stepOk) {
                ok = false;
                log.Write("ROLLBACK FAILED for " + it->path + ": " + error);
            }
        }
        return ok;
    }

    void WriteMarker(const fs::path& dir)
    {
        std::ofstream f(dir / FromUtf8(DONE_MARKER), std::ios::trunc);
        f << "ok\n";
    }
} // namespace

bool IsSafeRelativePath(std::string_view path)
{
    if (path.empty() || path.size() > 512 || path.front() == '/' || path.back() == '/')
        return false;
    for (char c : path) {
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F || c == ':' || c == '\\')
            return false;
    }
    std::string_view rest = path;
    while (true) {
        const auto slash = rest.find('/');
        const auto part  = rest.substr(0, slash);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ')
            return false;
        if (slash == std::string_view::npos)
            return true;
        rest = rest.substr(slash + 1);
    }
}

bool ParseManifest(std::string_view text, Manifest& manifest, std::string& error)
{
    manifest = {};
    std::set<std::string> seen;
    bool header = false, ended = false;
    while (!text.empty()) {
        const auto nl         = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text                  = (nl == std::string_view::npos) ? std::string_view{} : text.substr(nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (ended) {
            if (!line.empty()) {
                error = "data after the end marker";
                return false;
            }
            continue;
        }
        if (!header) {
            if (line != MANIFEST_HEADER) {
                error = "unknown manifest format";
                return false;
            }
            header = true;
            continue;
        }
        if (line == "end") {
            ended = true;
            continue;
        }
        if (line.starts_with("version ")) {
            manifest.version.assign(line.substr(8));
            continue;
        }
        if (line.starts_with("file ")) {
            const auto path = line.substr(5);
            if (!IsSafeRelativePath(path)) {
                error = "unsafe path in the manifest: " + std::string(path);
                return false;
            }
            if (!seen.insert(Lower(path)).second) {
                error = "duplicated path in the manifest: " + std::string(path);
                return false;
            }
            if (manifest.files.size() >= MAX_MANIFEST_FILES) {
                error = "too many files in the manifest";
                return false;
            }
            manifest.files.emplace_back(path);
            continue;
        }
        error = "unexpected manifest line";
        return false;
    }
    if (!header || !ended) {
        error = "the manifest is truncated";
        return false;
    }
    bool hasExecutable = false;
    for (const auto& f : manifest.files)
        hasExecutable |= Lower(f) == Lower(GVIEW_EXECUTABLE);
    if (!hasExecutable) {
        error = "the manifest does not contain " + std::string(GVIEW_EXECUTABLE);
        return false;
    }
    return true;
}

int Apply(const Options& o)
{
    Logger log(o);
    std::error_code ec;

    // ---------------------------------------------------------------- validation (nothing is modified)
    if (!CheckDirectory(o.staging, "the staging folder", log) || !CheckDirectory(o.target, "the installation folder", log))
        return EXIT_REFUSED;
    if (fs::exists(fs::symlink_status(o.old, ec))) {
        log.Write("the backup folder already exists: " + ToUtf8(o.old));
        return EXIT_REFUSED;
    }
    std::string manifestText;
    {
        std::ifstream m(o.staging / FromUtf8(MANIFEST_NAME), std::ios::binary);
        if (!m) {
            log.Write("the update manifest is missing");
            return EXIT_REFUSED;
        }
        std::ostringstream ss;
        ss << m.rdbuf();
        manifestText = ss.str();
    }
    Manifest manifest;
    std::string error;
    if (!ParseManifest(manifestText, manifest, error)) {
        log.Write("invalid update manifest: " + error);
        return EXIT_REFUSED;
    }
    for (const auto& f : manifest.files) {
        const auto rel = FromUtf8(f);
        if (!fs::is_regular_file(fs::symlink_status(o.staging / rel, ec))) {
            log.Write("staged file missing or not a regular file: " + f);
            return EXIT_REFUSED;
        }
        const auto targetStatus = fs::symlink_status(o.target / rel, ec);
        if (fs::exists(targetStatus) && !fs::is_regular_file(targetStatus)) {
            log.Write("cannot replace a non regular file: " + f);
            return EXIT_REFUSED;
        }
        // every parent of the destination must be a real folder (no symlink / file in the way)
        for (auto parent = rel.parent_path(); !parent.empty(); parent = parent.parent_path()) {
            const auto st = fs::symlink_status(o.target / parent, ec);
            if (fs::exists(st) && !fs::is_directory(st)) {
                log.Write("cannot create folder (a file or link is in the way): " + ToUtf8(parent));
                return EXIT_REFUSED;
            }
        }
    }
    if (!ProbeSameVolume(o.staging, o.target, log))
        return EXIT_REFUSED;
    fs::create_directories(o.old, ec);
    if (ec) {
        log.Write("unable to create the backup folder: " + ToUtf8(o.old));
        return EXIT_REFUSED;
    }
    log.Open(o.log.empty() ? o.old / FromUtf8(LOG_NAME) : o.log);
    Journal journal;
    if (!journal.Open(o.old / FromUtf8(JOURNAL_NAME))) {
        log.Write("unable to create the journal");
        fs::remove_all(o.old, ec);
        return EXIT_REFUSED;
    }
    log.Write("installing GView " + manifest.version + " (" + std::to_string(manifest.files.size()) + " files) into " + ToUtf8(o.target));

    // ---------------------------------------------------------------- swap
    int renames = 0;
    auto move   = [&](const fs::path& from, const fs::path& to) -> bool {
        if (renames++ == o.failAtRename) {
            error = "simulated failure";
            return false;
        }
        return MoveNoReplace(from, to, error);
    };
    bool failed = false;
    for (const auto& f : manifest.files) {
        const auto rel = FromUtf8(f);
        // folders that do not exist yet (journaled so that the rollback removes them again)
        std::vector<fs::path> missing;
        for (auto parent = rel.parent_path(); !parent.empty(); parent = parent.parent_path())
            if (!fs::exists(o.target / parent, ec))
                missing.push_back(parent);
        for (auto it = missing.rbegin(); it != missing.rend() && !failed; ++it) {
            if (!fs::create_directory(o.target / *it, ec) || ec) {
                error  = "unable to create folder " + ToUtf8(*it);
                failed = true;
            } else if (!journal.Add('D', ToUtf8(*it))) {
                error  = "unable to write the journal";
                failed = true;
            }
        }
        if (failed)
            break;
        if (fs::exists(fs::symlink_status(o.target / rel, ec))) {
            fs::create_directories((o.old / rel).parent_path(), ec);
            if (!move(o.target / rel, o.old / rel)) {
                error  = "unable to move " + f + " to the backup folder: " + error;
                failed = true;
                break;
            }
            if (!journal.Add('M', f)) {
                error  = "unable to write the journal";
                failed = true;
                break;
            }
        }
        if (!move(o.staging / rel, o.target / rel)) {
            error  = "unable to place " + f + ": " + error;
            failed = true;
            break;
        }
        if (!journal.Add('P', f)) {
            error  = "unable to write the journal";
            failed = true;
            break;
        }
    }

    if (failed) {
        log.Write("update failed: " + error + " - rolling back");
        if (!Rollback(journal, o, log)) {
            log.Write("the rollback is incomplete: the previous files are in " + ToUtf8(o.old) + " (see " + std::string(JOURNAL_NAME) + ")");
            return EXIT_ROLLBACK_INCOMPLETE;
        }
        WriteMarker(o.old); // nothing left to recover: GView may delete the folder
        log.Write("rollback completed, the installation is unchanged");
        return EXIT_ROLLED_BACK;
    }

    WriteMarker(o.old);
    fs::remove_all(o.staging, ec);
    log.Write("update installed");
    return EXIT_APPLIED;
}
} // namespace GViewUpdater
