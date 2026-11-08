// One-click launch of Learning and Evaluation Mode in the web build: the course page sends the student to
// <page>#launch=<one-time code>&server=<course server URL>.
//
// GView/web/gview-page.js reads and strips the fragment before GView starts, redeems the code at
// POST <server>/GView/WebLaunch while GView.wasm downloads, and publishes the outcome in globalThis.gviewLaunch. This
// file polls that object from the frames of the desktop (it never waits for it), takes the outcome once - the page then
// drops its copy of the connection string - and hands it to Learning and Evaluation Mode (RunLearningLaunch in
// LearningModeWindow.cpp: validation, trust prompt, replacement of the current connection, connect, store).
//
// ABI (numbers only; JavaScript writes only into the buffer given by C++):
//   gview_js_launch_state()                         0 = nothing to do, 1 = pending, 2 = connection string, 3 = error
//   gview_js_launch_field_size(field)               UTF-8 size of 0 = serverOrigin, 1 = error, 2 = connectionString
//   gview_js_launch_field_copy(field, buf, cap)     copies it (0-terminated)
//   gview_js_launch_taken()                         the module has the outcome: the page forgets the connection string

#include "Internal.hpp"
#include "Learning/SecureMemory.hpp"

#include <emscripten/emscripten.h>

EM_JS_DEPS(gview_browser_launch, "$stringToUTF8,$lengthBytesUTF8");

EM_JS(int32_t, gview_js_launch_state, (), {
    const l = globalThis.gviewLaunch;
    if (!l) return 0;
    if (l.state === "pending") return 1;
    if (l.state === "ok") return 2;
    if (l.state === "error") return 3;
    return 0; // "none" (no launch link) or "taken"
});

EM_JS(int32_t, gview_js_launch_field_size, (int32_t field), {
    const l = globalThis.gviewLaunch;
    const v = l ? [l.serverOrigin, l.error, l.connectionString][field] : undefined;
    return (typeof v === "string") ? lengthBytesUTF8(v) : -1;
});

EM_JS(int32_t, gview_js_launch_field_copy, (int32_t field, char* buffer, uint32_t capacity), {
    const l = globalThis.gviewLaunch;
    const v = l ? [l.serverOrigin, l.error, l.connectionString][field] : undefined;
    return (typeof v === "string") ? stringToUTF8(v, buffer, capacity) : -1;
});

EM_JS(void, gview_js_launch_taken, (), {
    const l = globalThis.gviewLaunch;
    if (l) {
        l.connectionString = "";
        l.state = "taken";
    }
});

namespace GView::App::Browser
{
namespace
{
    constexpr int32 FIELD_SERVER_ORIGIN      = 0;
    constexpr int32 FIELD_ERROR              = 1;
    constexpr int32 FIELD_CONNECTION_STRING  = 2;
    constexpr uint32 MAX_ORIGIN_SIZE         = 512;
    constexpr uint32 MAX_ERROR_SIZE          = 1024;
    constexpr uint32 MAX_CONNECTION_STRING   = 16 * 1024; // MAX_CONNECTION_STRING_LENGTH of LearningProtocol.cpp
    bool launchHandled                       = false;

    std::string ReadField(int32 field, uint32 maxSize)
    {
        const int32 size = gview_js_launch_field_size(field);
        if (size <= 0 || static_cast<uint32>(size) > maxSize)
            return {};
        std::string text(static_cast<size_t>(size) + 1, '\0'); // + the 0 written by stringToUTF8
        const int32 copied = gview_js_launch_field_copy(field, text.data(), static_cast<uint32_t>(text.size()));
        if (copied != size)
        {
            GView::Security::Learning::WipeString(text);
            return {};
        }
        text.resize(static_cast<size_t>(size));
        return text;
    }
} // namespace

bool LaunchOnFrame(bool desktopHasFocus)
{
    // a modal window (first-run tutorial, error, ...) is on top: the launch waits for the desktop
    if (launchHandled || !desktopHasFocus)
        return false;
    const int32 state = gview_js_launch_state();
    if (state == 1)
        return false; // the course server has not answered yet
    launchHandled = true; // once per page load, whatever the outcome
    if (state != 2 && state != 3)
        return false;

    LearningLaunch launch;
    launch.serverOrigin = ReadField(FIELD_SERVER_ORIGIN, MAX_ORIGIN_SIZE);
    if (state == 2)
        launch.connectionString = ReadField(FIELD_CONNECTION_STRING, MAX_CONNECTION_STRING);
    else
        launch.error = ReadField(FIELD_ERROR, MAX_ERROR_SIZE);
    gview_js_launch_taken();
    if (state == 2 && launch.connectionString.empty())
        launch.error = "The course server sent an invalid answer. Open GView again from the course page.";
    else if (state == 3 && launch.error.empty())
        launch.error = "The launch link could not be opened. Open GView again from the course page.";

    GView::App::RunLearningLaunch(launch);
    GView::Security::Learning::WipeString(launch.connectionString);
    return true;
}
} // namespace GView::App::Browser
