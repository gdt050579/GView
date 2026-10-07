#pragma once

// UI-thread orchestration of the auto-updater.
//   - OnFrame()          : called by the GView desktop every frame (FPS mode). The first frame starts the daily background
//                          check; completed checks are applied here and the update dialog is shown when no modal is open.
//   - CheckInteractive() : Help > Check for updates (modal progress, works on every frontend).
//   - Shutdown()         : after AppCUI::Application::Run() returned; stops the worker (cancels a running request).
// Updates are never offered while Learning and Evaluation Mode (restricted mode or a learning session) is active.

#include "UpdateCore.hpp"

namespace GView::Update
{
enum class DialogChoice : uint8 { Install, RemindLater, Skip };
// implemented in App/UpdateDialog.cpp. "Remind me later" is the default (focused) choice; an unsolicited prompt (the
// automatic check) ignores its buttons for a moment so that keystrokes meant for a viewer cannot answer it.
DialogChoice ShowUpdateDialog(const ReleaseInfo& release, bool canInstall, bool unsolicited);

namespace Service
{
    void Enable() noexcept;
    bool OnFrame(bool desktopHasFocus);
    void CheckInteractive();
    void Shutdown() noexcept;
} // namespace Service
} // namespace GView::Update
