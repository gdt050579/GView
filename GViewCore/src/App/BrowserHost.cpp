// GView inside a web page (wasm32-emscripten). The page (GView/web/GView.html.in) gives files to GView through the
// exports below: the bytes are copied into the in-memory file system ($HOME/Files, also reachable as /files) and the
// file is opened from the desktop's OnFrameUpdate - never from the export itself, which may run while a modal window
// is suspended.
//
// ABI (numbers only, like AppCUI's BrowserExports.cpp - JS never writes into wasm memory outside a buffer it was given):
//   ptr = _gview_browser_alloc(size)                                  0 = out of memory
//   ... JS copies the bytes into HEAPU8[ptr, ptr + size) ...
//   _gview_browser_add_file(namePtr, nameSize, dataPtr, dataSize)    1 = queued, 0 = rejected; frees both buffers
//   _gview_browser_last_stored()                                     "<path relative to $HOME>\n<mtime ms>" (UTF-8,
//                                                                    0-terminated) of the last accepted file: the page
//                                                                    keeps that file in the persistent storage itself
//
// The settings file (AppCUI names it after the virtual executable: /app.ini) also lives in the in-memory file system and
// would be lost on every reload. It is kept in the localStorage of the page (SETTINGS_KEY): restored before AppCUI
// loads it, stored back from OnFrame when its size or modification time changes - whoever wrote it (the first-run
// defaults, a settings dialog, the keyboard shortcuts window, the theme editor, ...).

#include "Internal.hpp"
#include "Learning/BackgroundWorker.hpp"

#include <emscripten/emscripten.h>
#include <sys/stat.h>

#include <deque>
#include <utility>
#include <fstream>
#include <new>
#include <optional>

// localStorage may be unavailable (private mode, blocked site data, sandboxed frame) or full: every access is guarded and
// the settings then simply stay in memory, as before
EM_JS_DEPS(gview_browser_settings, "$UTF8ToString,$stringToUTF8,$lengthBytesUTF8");

// size in bytes of the stored settings (UTF-8), -1 = nothing stored or no localStorage
EM_JS(int32_t, gview_js_settings_size, (const char* key), {
    try {
        const text = globalThis.localStorage.getItem(UTF8ToString(key));
        return text === null ? -1 : lengthBytesUTF8(text);
    } catch (e) {
        return -1;
    }
});

// copies the stored settings and a terminating 0 into buffer; returns the bytes written (without the 0), -1 = failed
EM_JS(int32_t, gview_js_settings_read, (const char* key, char* buffer, uint32_t capacity), {
    try {
        const text = globalThis.localStorage.getItem(UTF8ToString(key));
        return text === null ? -1 : stringToUTF8(text, buffer, capacity);
    } catch (e) {
        return -1;
    }
});

// 1 = stored, 0 = failed (quota exceeded or no localStorage)
EM_JS(int32_t, gview_js_settings_write, (const char* key, const char* data, uint32_t size), {
    try {
        globalThis.localStorage.setItem(UTF8ToString(key), UTF8ToString(data, size));
        return 1;
    } catch (e) {
        return 0;
    }
});

namespace GView::App::Browser
{
namespace
{
    constexpr std::string_view FILES_SUBFOLDER = "Files";  // under $HOME: kept across visits (BrowserStorage.cpp)
    constexpr std::string_view FILES_LINK      = "/files"; // where the files were before the persistent storage
    constexpr size_t MAX_FILE_NAME             = 255;

    std::filesystem::path filesFolder;
    std::string lastStored; // see _gview_browser_last_stored
    bool pageHidden = false; // set by _gview_browser_page_hidden, handled by the next frame

    // the origin (e.g. <user>.github.io) can be shared with other pages: the key carries the application name
    constexpr const char* SETTINGS_KEY          = "GView/GView.ini";
    constexpr uint32 MAX_SETTINGS_SIZE          = 1024 * 1024; // a generated GView.ini is a few tens of KB
    constexpr uint32 SETTINGS_CHECK_FRAME_COUNT = 15;          // ~0.5 s (OnFrameUpdate runs at ~30 Hz in FPS mode)

    std::deque<std::filesystem::path> pendingFiles;

    struct SettingsStamp
    {
        off_t size;
        time_t seconds;
        long nanoseconds;
        bool operator==(const SettingsStamp&) const = default;
    };
    std::string settingsPath; // cached: the check runs from OnFrame
    std::optional<SettingsStamp> storedSettingsStamp;
    uint32 framesUntilSettingsCheck = 0;

    std::optional<SettingsStamp> GetSettingsStamp()
    {
        struct stat st{};
        if (settingsPath.empty() || (::stat(settingsPath.c_str(), &st) != 0) || !S_ISREG(st.st_mode))
            return std::nullopt;
        return SettingsStamp{ st.st_size, st.st_mtim.tv_sec, st.st_mtim.tv_nsec };
    }

    void StoreSettingsIfChanged()
    {
        if (framesUntilSettingsCheck > 0) {
            framesUntilSettingsCheck--;
            return;
        }
        framesUntilSettingsCheck = SETTINGS_CHECK_FRAME_COUNT;

        const auto stamp = GetSettingsStamp();
        if (!stamp.has_value() || (stamp == storedSettingsStamp))
            return;
        // remembered even when it can not be stored: a failing localStorage is not retried twice a second
        storedSettingsStamp = stamp;
        CHECKRET((stamp->size > 0) && (static_cast<uint64>(stamp->size) <= MAX_SETTINGS_SIZE), "Settings file too large to be kept");

        std::string content(static_cast<size_t>(stamp->size), '\0');
        std::ifstream in(settingsPath, std::ios::binary);
        CHECKRET(in.read(content.data(), static_cast<std::streamsize>(content.size())), "Unable to read: %s", settingsPath.c_str());
        CHECKRET(gview_js_settings_write(SETTINGS_KEY, content.data(), static_cast<uint32_t>(content.size())) == 1,
                 "Unable to keep the settings in the localStorage of the page");
    }

    // keeps only the name of the file (no folders, no control characters); empty when nothing usable is left
    std::string SanitizeFileName(std::string_view name)
    {
        const auto slash = name.find_last_of("/\\");
        if (slash != std::string_view::npos)
            name = name.substr(slash + 1);
        std::string result;
        for (const auto ch : name)
        {
            if (static_cast<unsigned char>(ch) >= 0x20 && ch != 0x7F && ch != ':')
                result.push_back(ch);
        }
        if (result == "." || result == "..")
            result.clear();
        if (result.size() > MAX_FILE_NAME)
            result.resize(MAX_FILE_NAME);
        return result;
    }

    // "name.ext", "name (1).ext", "name (2).ext", ... - a file given twice does not replace the opened one
    std::filesystem::path UniquePath(const std::string& fileName)
    {
        const std::filesystem::path& folder = filesFolder;
        auto path = folder / fileName;
        std::error_code ec;
        const auto stem      = path.stem().string();
        const auto extension = path.extension().string();
        // a stored file that is not loaded into memory yet keeps its name too (it would be replaced in the store)
        const auto taken = [&](const std::filesystem::path& p) {
            return std::filesystem::exists(p, ec) || IsStoredPath(p.lexically_relative(HomeFolder()).generic_string());
        };
        for (uint32 index = 1; taken(path) && index < 10000; index++)
            path = folder / (stem + " (" + std::to_string(index) + ")" + extension);
        return path;
    }

    bool StoreFile(std::string_view name, const uint8* data, uint32 size)
    {
        const auto fileName = SanitizeFileName(name);
        CHECK(!fileName.empty(), false, "Invalid file name");
        const auto path = UniquePath(fileName);
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            CHECK(out.good(), false, "Unable to create: %s", path.string().c_str());
            out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
            CHECK(out.good(), false, "Unable to write: %s", path.string().c_str());
        }
        NoteFileStoredByPage(path);
        pendingFiles.push_back(path);
        return true;
    }
} // namespace

const char* LastStoredDescription()
{
    return lastStored.c_str();
}

void ClearLastStored()
{
    lastStored.clear();
}

void NotePageHidden()
{
    pageHidden = true;
}

std::filesystem::path HomeFolder()
{
    const char* home = std::getenv("HOME"); // /home/web_user (Emscripten)
    return std::filesystem::path((home != nullptr && home[0] == '/') ? home : "/home/web_user");
}

void PrepareFilesFolder()
{
    std::error_code ec;
    filesFolder = HomeFolder() / FILES_SUBFOLDER;
    std::filesystem::create_directories(filesFolder, ec);
    if (!std::filesystem::exists(FILES_LINK, ec))
        std::filesystem::create_directory_symlink(filesFolder, FILES_LINK, ec);
    std::filesystem::current_path(filesFolder, ec);
}

void NoteFileStoredByPage(const std::filesystem::path& file)
{
    lastStored.clear();
    struct stat st{};
    if (::stat(file.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
        return;
    const auto relative = file.lexically_relative(HomeFolder()).generic_string();
    if (!Storage::IsStorablePath(relative))
        return;
    const int64 mtimeMs = static_cast<int64>(st.st_mtim.tv_sec) * 1000 + static_cast<int64>(st.st_mtim.tv_nsec / 1000000);
    lastStored          = relative + "\n" + std::to_string(mtimeMs);
    StorageMarkStored(relative, Storage::Stamp{ static_cast<uint64>(st.st_size), mtimeMs });
}

void RestoreSettings()
{
    settingsPath = AppCUI::Application::GetAppSettingsFile().string();
    CHECKRET(!settingsPath.empty(), "Unknown settings file");

    // nothing stored (first run, or no localStorage): GView creates the default settings, stored by the next check.
    // The stored text is parsed like any GView.ini (an invalid one is renamed to .ini.bak and replaced).
    const int32 size = gview_js_settings_size(SETTINGS_KEY);
    if ((size <= 0) || (static_cast<uint32>(size) > MAX_SETTINGS_SIZE))
        return;
    std::string content(static_cast<size_t>(size) + 1, '\0'); // + the 0 written by stringToUTF8
    const int32 copied = gview_js_settings_read(SETTINGS_KEY, content.data(), static_cast<uint32_t>(content.size()));
    CHECKRET(copied == size, "The stored settings changed while they were read"); // e.g. saved by another tab
    content.resize(static_cast<size_t>(size));
    {
        std::ofstream out(settingsPath, std::ios::binary | std::ios::trunc);
        CHECKRET(out.write(content.data(), static_cast<std::streamsize>(content.size())), "Unable to write: %s", settingsPath.c_str());
    }
    storedSettingsStamp = GetSettingsStamp(); // already stored: no need to store it back
}

bool OnFrame(bool desktopHasFocus)
{
    // runs under modal windows too: settings are often saved from a dialog
    StoreSettingsIfChanged();
    const bool hidden = std::exchange(pageHidden, false);
    StorageOnFrame(hidden);
    // the jobs of Learning and Evaluation Mode that wait for the network (no threads in a page, BackgroundWorker.hpp)
    GView::Security::Learning::Cooperative::Pump();
    GView::Security::Learning::Hooks::OnBrowserFrame(hidden);

    // a file window is not opened under a modal window (it would get the focus while the modal one waits for input)
    if (pendingFiles.empty() || !desktopHasFocus)
        return false;
    while (!pendingFiles.empty())
    {
        const auto path = std::move(pendingFiles.front());
        pendingFiles.pop_front();
        GView::App::OpenFile(path, OpenMethod::FirstMatch, "", nullptr, "browser upload");
    }
    return true;
}
} // namespace GView::App::Browser

extern "C"
{
EMSCRIPTEN_KEEPALIVE uint8* gview_browser_alloc(uint32 size)
{
    if (size == 0)
        return nullptr;
    return new (std::nothrow) uint8[size];
}

// the page became hidden (visibilitychange): only records it - this export may run while GView is suspended
EMSCRIPTEN_KEEPALIVE void gview_browser_page_hidden()
{
    GView::App::Browser::NotePageHidden();
}

EMSCRIPTEN_KEEPALIVE const char* gview_browser_last_stored()
{
    return GView::App::Browser::LastStoredDescription();
}

EMSCRIPTEN_KEEPALIVE int32 gview_browser_add_file(uint8* name, uint32 nameSize, uint8* data, uint32 dataSize)
{
    // both buffers come from gview_browser_alloc (or are null for an empty name / file)
    std::unique_ptr<uint8[]> nameBuffer(name);
    std::unique_ptr<uint8[]> dataBuffer(data);
    if ((name == nullptr) || (nameSize == 0) || ((data == nullptr) && (dataSize != 0)))
        return 0;
    static const uint8 emptyFile = 0;
    const std::string_view fileName(reinterpret_cast<const char*>(name), nameSize);
    GView::App::Browser::ClearLastStored();
    return GView::App::Browser::StoreFile(fileName, data ? data : &emptyFile, dataSize) ? 1 : 0;
}
}
