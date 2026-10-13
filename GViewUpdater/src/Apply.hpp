#pragma once

// GViewUpdater: applies an update staged by GView (GViewCore/src/Update/Stager.cpp).
//
// The helper is deliberately small and self-contained (C++ standard library + OS APIs only, static CRT on Windows) so
// that it keeps working while the GView binaries and their DLLs are being replaced. It never deletes anything from the
// installation folder: every replaced file is renamed into the --old folder and every move is journaled, so a failure at
// any point is rolled back by replaying the journal backwards.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace GViewUpdater
{
// exit codes (keep in sync with GViewCore/src/Update/Installer.hpp)
constexpr int EXIT_APPLIED             = 0;
constexpr int EXIT_USAGE               = 2;
constexpr int EXIT_REFUSED             = 10; // validation failed, the installation folder was not touched
constexpr int EXIT_ROLLED_BACK         = 20; // a move failed, every change was reverted
constexpr int EXIT_ROLLBACK_INCOMPLETE = 30; // a move failed and the rollback failed too: manual recovery needed

constexpr std::string_view MANIFEST_NAME   = "apply.manifest";
constexpr std::string_view MANIFEST_HEADER = "GViewUpdate 1";
constexpr std::string_view DONE_MARKER     = "DONE";
constexpr std::string_view JOURNAL_NAME    = "journal.txt";
constexpr std::string_view LOG_NAME        = "updater.log";
constexpr size_t MAX_MANIFEST_FILES        = 10000;

#ifdef _WIN32
constexpr std::string_view GVIEW_EXECUTABLE = "GView.exe";
#else
constexpr std::string_view GVIEW_EXECUTABLE = "GView";
#endif

struct Manifest {
    std::string version;
    std::vector<std::string> files; // relative, '/' separated, validated
};

struct Options {
    std::filesystem::path staging;
    std::filesystem::path target;
    std::filesystem::path old;
    std::filesystem::path log; // default: <old>/updater.log
    // tests only: make the N-th rename (0 based) fail to exercise the rollback; -1 = disabled
    int failAtRename{ -1 };
    // tests only: make the first rollback rename fail
    bool failRollback{ false };
    // receives every log line (in addition to the log file); default writes to stdout
    std::function<void(std::string_view)> output;
};

// "file" entries must be safe relative paths: no absolute path, drive, '..', '.', empty component, ':', '\\' or control char
bool IsSafeRelativePath(std::string_view path);
bool ParseManifest(std::string_view text, Manifest& manifest, std::string& error);

int Apply(const Options& options);
} // namespace GViewUpdater
