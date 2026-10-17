// Persistent storage of the web build: everything under GView's home folder ($HOME = /home/web_user, where the files
// given to the page land in Files/, where Learning and Evaluation Mode saves task files and where the file dialogs
// start) is kept across visits; /tmp and the rest of the in-memory file system are not.
//
//   boot   RestoreStorage(): the newest stored files are copied back into the home folder (EAGER_RESTORE_BUDGET); the
//          others are listed by File > Stored files and copied on demand (a multi-GB sample is never loaded unasked)
//   frame  every SCAN_INTERVAL_FRAMES (~2 s; browsers slow hidden pages down to ~1 frame/s) the home folder is scanned
//          (size + mtime, symbolic links are not followed) and Storage::Diff decides what to send to the store / remove
//   hidden when the page is hidden (tab switched, minimized, closing) everything that changed is sent at once, without
//          waiting for it to be stable: it may be the last chance (a closing page may still lose the last file)
//
// The store itself (OPFS + IndexedDB, AES-GCM at rest) lives in a Worker of the page: GView/web/gview-storage.js and
// gview-storage-worker.js. Every call below is asynchronous on the JavaScript side (fire and forget), except the boot
// restore and the on-demand copy, which suspend GView with Asyncify until the data is in the in-memory file system.
// Learning content delivered in memory mode never reaches the file system, so it can never be stored.

#include "Internal.hpp"

#include <emscripten/emscripten.h>
#include <sys/stat.h>

#include <algorithm>
#include <set>

#include <nlohmann/json.hpp>

EM_JS_DEPS(gview_browser_storage, "$FS,$UTF8ToString,$stringToUTF8,$lengthBytesUTF8");

// 1 = the persistent storage of the page is usable (waits for nothing: 0 while it is still starting)
EM_JS(int32_t, gview_js_storage_available, (), {
    const s = globalThis.gviewStorage;
    return (s && s.available) ? 1 : 0;
});

// boot: waits for the store, then copies the newest stored files into the home folder; returns the number copied
EM_ASYNC_JS(int32_t, gview_js_storage_restore, (const char* home, double budgetBytes), {
    const s = globalThis.gviewStorage;
    if (!s) return 0;
    try {
        return await s.restore(FS, UTF8ToString(home), budgetBytes);
    } catch (e) {
        return 0;
    }
});

// copies one stored file into the home folder (Stored files > Open); 1 = done
EM_ASYNC_JS(int32_t, gview_js_storage_materialize, (const char* home, const char* path), {
    const s = globalThis.gviewStorage;
    if (!s) return 0;
    try {
        return (await s.materialize(FS, UTF8ToString(home), UTF8ToString(path))) ? 1 : 0;
    } catch (e) {
        return 0;
    }
});

// JSON array of the stored files [{ path, size, mtime, storedAt, origin, materialized }] (UTF-8 size / copy)
EM_JS(int32_t, gview_js_storage_entries_size, (), {
    const s = globalThis.gviewStorage;
    const list = (s && s.available) ? [...s.entries.values()] : [];
    s && (s.entriesText = JSON.stringify(list));
    return s ? lengthBytesUTF8(s.entriesText) : 0;
});

EM_JS(int32_t, gview_js_storage_entries_copy, (char* buffer, uint32_t capacity), {
    const s = globalThis.gviewStorage;
    if (!s || typeof s.entriesText !== "string") return -1;
    return stringToUTF8(s.entriesText, buffer, capacity);
});

// keeps the file: the bytes are read from the in-memory file system now, written by the storage worker later
EM_JS(int32_t, gview_js_storage_put, (const char* absPath, const char* relPath, double mtimeMs), {
    const s = globalThis.gviewStorage;
    if (!s || !s.available || s.full) return 0;
    try {
        const data = FS.readFile(UTF8ToString(absPath)); // a copy (transferred to the worker)
        return s.put(UTF8ToString(relPath), data, mtimeMs, "output") ? 1 : 0;
    } catch (e) {
        return 0;
    }
});

EM_JS(int32_t, gview_js_storage_has, (const char* relPath), {
    const s = globalThis.gviewStorage;
    return (s && s.entries.has(UTF8ToString(relPath))) ? 1 : 0;
});

EM_JS(void, gview_js_storage_remove, (const char* relPath), {
    const s = globalThis.gviewStorage;
    if (s) s.remove(UTF8ToString(relPath));
});

EM_JS(void, gview_js_storage_clear, (), {
    const s = globalThis.gviewStorage;
    if (s) s.clear();
});

// status line of the Stored files window (UTF-8 size / copy)
EM_JS(int32_t, gview_js_storage_status_size, (), {
    const s = globalThis.gviewStorage;
    let text;
    if (!s) text = "The page has no persistent storage: files last as long as the tab.";
    else if (!s.available) text = "Files last as long as the tab: " + (s.error || "the storage is still starting");
    else {
        let total = 0;
        for (const e of s.entries.values()) total += e.size;
        const mb = (n) => (n / (1024 * 1024)).toFixed(1) + " MiB";
        text = s.entries.size + " file(s), " + mb(total) + " kept in this browser" +
               (s.quota ? " (site storage: " + mb(s.usage || 0) + " used of " + mb(s.quota) + ")" : "") +
               (s.persisted ? ", persistent" : ", may be evicted under storage pressure") +
               (s.full ? " - STORAGE FULL" : "");
    }
    s && (s.statusText = text);
    globalThis.gviewStorageStatusText = text;
    return lengthBytesUTF8(text);
});

EM_JS(int32_t, gview_js_storage_status_copy, (char* buffer, uint32_t capacity), {
    return stringToUTF8(globalThis.gviewStorageStatusText || "", buffer, capacity);
});

EM_JS(int32_t, gview_js_secret_size, (const char* name), {
    const s = globalThis.gviewStorage;
    const v = s ? s.secrets.get(UTF8ToString(name)) : undefined;
    return (typeof v === "string") ? lengthBytesUTF8(v) : -1;
});

EM_JS(int32_t, gview_js_secret_copy, (const char* name, char* buffer, uint32_t capacity), {
    const s = globalThis.gviewStorage;
    const v = s ? s.secrets.get(UTF8ToString(name)) : undefined;
    return (typeof v === "string") ? stringToUTF8(v, buffer, capacity) : -1;
});

EM_JS(void, gview_js_secret_set, (const char* name, const char* value, uint32_t size), {
    const s = globalThis.gviewStorage;
    if (s) s.setSecret(UTF8ToString(name), UTF8ToString(value, size));
});

EM_JS(void, gview_js_secret_remove, (const char* name), {
    const s = globalThis.gviewStorage;
    if (s) s.removeSecret(UTF8ToString(name));
});

namespace GView::App::Browser
{
namespace
{
    constexpr double EAGER_RESTORE_BUDGET      = 64.0 * 1024 * 1024; // bytes copied back at boot (newest files first)
    constexpr uint32 SCAN_INTERVAL_FRAMES      = 60;                 // ~2 s (OnFrameUpdate runs at ~30 Hz)
    constexpr uint32 MAX_SCANNED_ENTRIES       = 20000;
    constexpr int MAX_SCAN_DEPTH               = 16;
    constexpr uint64 MAX_SCANNER_FILE_SIZE     = 512ull * 1024 * 1024; // larger outputs are not copied through the page
    constexpr uint32 MAX_STATUS_LENGTH         = 4096;
    constexpr uint32 MAX_ENTRIES_JSON_LENGTH   = 64 * 1024 * 1024;

    Storage::Snapshot previousScan;
    Storage::Snapshot stored; // what the store holds for the files present in the home folder
    uint32 framesUntilScan = SCAN_INTERVAL_FRAMES;
    bool restored          = false;

    std::optional<Storage::Stamp> StampOf(const std::filesystem::path& file)
    {
        struct stat st{};
        if (::lstat(file.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
            return std::nullopt;
        return Storage::Stamp{ static_cast<uint64>(st.st_size),
                               static_cast<int64>(st.st_mtim.tv_sec) * 1000 + static_cast<int64>(st.st_mtim.tv_nsec / 1000000) };
    }

    // tooLarge: files present but not scanned; complete: false when the scan stopped early (entry limit, error)
    Storage::Snapshot Scan(const std::filesystem::path& home, std::set<std::string>& tooLarge, bool& complete)
    {
        Storage::Snapshot snapshot;
        std::error_code ec;
        complete = true;
        // symbolic links are never followed (/files points back into the home folder)
        auto it = std::filesystem::recursive_directory_iterator(home, std::filesystem::directory_options::skip_permission_denied, ec);
        uint32 count = 0;
        for (; !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
        {
            if (++count > MAX_SCANNED_ENTRIES)
            {
                complete = false;
                break;
            }
            if (it.depth() >= MAX_SCAN_DEPTH)
                it.disable_recursion_pending();
            if (it->is_symlink(ec) || !it->is_regular_file(ec))
                continue;
            const auto stamp = StampOf(it->path());
            if (!stamp.has_value())
                continue;
            auto relative = it->path().lexically_relative(home).generic_string();
            if (stamp->size > MAX_SCANNER_FILE_SIZE)
            {
                tooLarge.insert(std::move(relative));
                continue;
            }
            if (Storage::IsStorablePath(relative))
                snapshot.emplace(std::move(relative), *stamp);
        }
        if (ec)
            complete = false;
        return snapshot;
    }

    // files deeper than MAX_SCAN_DEPTH are never listed by Scan (a relative path with N '/' is at depth N)
    bool IsBeyondScanDepth(const std::string& relativePath)
    {
        return std::count(relativePath.begin(), relativePath.end(), '/') > MAX_SCAN_DEPTH;
    }

    std::string ReadJsText(int32 size, int32 (*copy)(char*, uint32_t), uint32 maxSize)
    {
        if (size <= 0 || static_cast<uint32>(size) > maxSize)
            return {};
        std::string text(static_cast<size_t>(size) + 1, '\0'); // + the 0 written by stringToUTF8
        const int32 copied = copy(text.data(), static_cast<uint32_t>(text.size()));
        if (copied <= 0)
            return {};
        text.resize(static_cast<size_t>(copied));
        return text;
    }
} // namespace

void StorageMarkStored(const std::string& relativePath, const Storage::Stamp& stamp)
{
    stored[relativePath] = stamp;
    previousScan[relativePath] = stamp; // not reported as "new" by the next scan
}

std::vector<StoredFile> StoredFiles()
{
    std::vector<StoredFile> files;
    const auto text = ReadJsText(gview_js_storage_entries_size(), gview_js_storage_entries_copy, MAX_ENTRIES_JSON_LENGTH);
    if (text.empty())
        return files;
    auto j = nlohmann::json::parse(text, nullptr, false);
    if (!j.is_array())
        return files;
    for (const auto& e : j)
    {
        if (!e.is_object() || !e.contains("path") || !e["path"].is_string())
            continue;
        StoredFile f;
        f.path         = e["path"].get<std::string>();
        f.size         = e.value("size", 0.0) > 0 ? static_cast<uint64>(e.value("size", 0.0)) : 0;
        f.storedAtMs   = static_cast<int64>(e.value("storedAt", 0.0));
        f.materialized = e.value("materialized", false);
        if (Storage::IsStorablePath(f.path))
            files.push_back(std::move(f));
    }
    std::sort(files.begin(), files.end(), [](const StoredFile& a, const StoredFile& b) { return a.path < b.path; });
    return files;
}

bool IsStoredPath(const std::string& relativePath)
{
    return gview_js_storage_has(relativePath.c_str()) == 1;
}

std::string StorageStatus()
{
    return ReadJsText(gview_js_storage_status_size(), gview_js_storage_status_copy, MAX_STATUS_LENGTH);
}

bool StorageAvailable()
{
    return gview_js_storage_available() == 1;
}

void RestoreStorage()
{
    const auto home = HomeFolder();
    const int32 count = gview_js_storage_restore(home.c_str(), EAGER_RESTORE_BUDGET);
    restored          = true;
    if (count <= 0)
        return;
    // what was copied back is what the store holds: nothing to send again
    for (const auto& f : StoredFiles())
    {
        if (!f.materialized)
            continue;
        if (const auto stamp = StampOf(home / f.path); stamp.has_value())
            StorageMarkStored(f.path, *stamp);
    }
}

bool MaterializeStoredFile(const std::string& relativePath, std::filesystem::path& outPath)
{
    CHECK(Storage::IsStorablePath(relativePath), false, "Invalid stored path");
    const auto home = HomeFolder();
    outPath         = home / std::filesystem::path(relativePath);
    if (StampOf(outPath).has_value())
        return true; // already in memory
    CHECK(gview_js_storage_materialize(home.c_str(), relativePath.c_str()) == 1, false, "Unable to load %s", relativePath.c_str());
    const auto stamp = StampOf(outPath);
    CHECK(stamp.has_value(), false, "Unable to load %s", relativePath.c_str());
    StorageMarkStored(relativePath, *stamp);
    return true;
}

void ForgetStoredFile(const std::string& relativePath)
{
    if (!Storage::IsStorablePath(relativePath))
        return;
    std::error_code ec;
    std::filesystem::remove(HomeFolder() / std::filesystem::path(relativePath), ec);
    stored.erase(relativePath);
    previousScan.erase(relativePath);
    gview_js_storage_remove(relativePath.c_str());
}

void ForgetAllStoredFiles()
{
    stored.clear();
    gview_js_storage_clear();
    // the files that are in memory stay open; they are kept again (as new) by the next scans
    previousScan.clear();
}

bool StorageOnFrame(bool pageHidden)
{
    if (!restored)
        return false;
    if (framesUntilScan > 0 && !pageHidden)
    {
        framesUntilScan--;
        return false;
    }
    framesUntilScan = SCAN_INTERVAL_FRAMES;
    if (gview_js_storage_available() == 0)
        return false;

    const auto home    = HomeFolder();
    std::set<std::string> tooLarge;
    bool complete      = true;
    auto current       = Scan(home, tooLarge, complete);
    // hidden page: no time to wait for a second scan - every changed file counts as stable
    const auto changes = Storage::Diff(pageHidden ? current : previousScan, current, stored);
    for (const auto& path : changes.persist)
    {
        const auto& stamp = current.at(path);
        const auto abs    = (home / std::filesystem::path(path)).string();
        // a failure (storage full / unavailable) is reported by the page and not retried until the file changes
        gview_js_storage_put(abs.c_str(), path.c_str(), static_cast<double>(stamp.mtimeMs));
        stored[path] = stamp;
    }
    for (const auto& path : changes.remove)
    {
        // not seen because the scan skipped it (too large, too deep, scan cut short): that is not a deletion
        if (!complete || tooLarge.contains(path) || IsBeyondScanDepth(path))
            continue;
        gview_js_storage_remove(path.c_str());
        stored.erase(path);
    }
    previousScan = std::move(current);
    return false;
}

std::optional<std::string> Secrets::Get(std::string_view name)
{
    const std::string key(name);
    const int32 size = gview_js_secret_size(key.c_str());
    if (size < 0 || size > 64 * 1024)
        return std::nullopt;
    std::string value(static_cast<size_t>(size) + 1, '\0');
    const int32 copied = gview_js_secret_copy(key.c_str(), value.data(), static_cast<uint32_t>(value.size()));
    if (copied != size)
        return std::nullopt;
    value.resize(static_cast<size_t>(size));
    return value;
}

void Secrets::Set(std::string_view name, std::string_view value)
{
    const std::string key(name);
    const std::string text(value); // 0-terminated for UTF8ToString
    gview_js_secret_set(key.c_str(), text.c_str(), static_cast<uint32_t>(text.size()));
}

void Secrets::Remove(std::string_view name)
{
    const std::string key(name);
    gview_js_secret_remove(key.c_str());
}
} // namespace GView::App::Browser
