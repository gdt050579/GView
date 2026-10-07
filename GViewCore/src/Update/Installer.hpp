#pragma once

// Post-UI supervisor: runs after AppCUI::Application::Run() returned (terminal restored).
// It copies GViewUpdater to a private temp folder, runs it to swap the staged files into the installation folder,
// waits for it, then starts the new GView with the original command line and waits for it as well. Keeping this process
// alive as the parent keeps the user's terminal session continuous on every OS.

#include "UpdateCore.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace GView::Update::Installer
{
using NativeString = std::filesystem::path::string_type; // std::wstring on Windows, std::string elsewhere

struct PendingInstall {
    Version version;
    std::filesystem::path installDir;
    std::filesystem::path stagingDir;
    std::filesystem::path gviewExecutable; // captured before the files are moved
};

// command line arguments of the running GView, without argv[0]
void SetRelaunchArguments(std::vector<NativeString> args);
void SetPending(PendingInstall pending);
bool HasPending() noexcept;
// runs the pending install (if any) and returns the process exit code to use
int Execute();

// GViewUpdater exit codes (keep in sync with GViewUpdater/src/Apply.hpp)
constexpr int UPDATER_OK                  = 0;
constexpr int UPDATER_REFUSED             = 10;
constexpr int UPDATER_ROLLED_BACK         = 20;
constexpr int UPDATER_ROLLBACK_INCOMPLETE = 30;

// Spawns 'executable' with 'args' (argv[1..]), inheriting the console/terminal, and waits for it.
// Returns the exit code, or -1 when the process could not be started.
int RunAndWait(const std::filesystem::path& executable, const std::vector<NativeString>& args);
} // namespace GView::Update::Installer
