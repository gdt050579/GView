// GView inside a web page (wasm32-emscripten). The page (GView/web/GView.html.in) gives files to GView through the
// exports below: the bytes are copied into the in-memory file system (FILES_FOLDER) and the file is opened from the
// desktop's OnFrameUpdate - never from the export itself, which may run while a modal window is suspended.
//
// ABI (numbers only, like AppCUI's BrowserExports.cpp - JS never writes into wasm memory outside a buffer it was given):
//   ptr = _gview_browser_alloc(size)                                  0 = out of memory
//   ... JS copies the bytes into HEAPU8[ptr, ptr + size) ...
//   _gview_browser_add_file(namePtr, nameSize, dataPtr, dataSize)    1 = queued, 0 = rejected; frees both buffers

#include "Internal.hpp"

#include <emscripten/emscripten.h>

#include <deque>
#include <fstream>
#include <new>

namespace GView::App::Browser
{
namespace
{
    constexpr std::string_view FILES_FOLDER = "/files";
    constexpr size_t MAX_FILE_NAME          = 255;

    std::deque<std::filesystem::path> pendingFiles;

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
        const std::filesystem::path folder(FILES_FOLDER);
        auto path = folder / fileName;
        std::error_code ec;
        const auto stem      = path.stem().string();
        const auto extension = path.extension().string();
        for (uint32 index = 1; std::filesystem::exists(path, ec) && index < 10000; index++)
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
        pendingFiles.push_back(path);
        return true;
    }
} // namespace

void PrepareFilesFolder()
{
    std::error_code ec;
    std::filesystem::create_directories(FILES_FOLDER, ec);
    std::filesystem::current_path(FILES_FOLDER, ec);
}

bool OnFrame(bool desktopHasFocus)
{
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

EMSCRIPTEN_KEEPALIVE int32 gview_browser_add_file(uint8* name, uint32 nameSize, uint8* data, uint32 dataSize)
{
    // both buffers come from gview_browser_alloc (or are null for an empty name / file)
    std::unique_ptr<uint8[]> nameBuffer(name);
    std::unique_ptr<uint8[]> dataBuffer(data);
    if ((name == nullptr) || (nameSize == 0) || ((data == nullptr) && (dataSize != 0)))
        return 0;
    static const uint8 emptyFile = 0;
    const std::string_view fileName(reinterpret_cast<const char*>(name), nameSize);
    return GView::App::Browser::StoreFile(fileName, data ? data : &emptyFile, dataSize) ? 1 : 0;
}
}
