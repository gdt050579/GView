#include "Installer.hpp"
#include "Stager.hpp"

#include <cstdio>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>

#ifdef BUILD_FOR_WINDOWS
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#    include <windows.h>
#    ifdef MessageBox
#        undef MessageBox
#    endif
#else
#    include <cerrno>
#    include <csignal>
#    include <spawn.h>
#    include <sys/stat.h>
#    include <sys/wait.h>
#    include <unistd.h>
extern char** environ;
#endif

namespace GView::Update::Installer
{
namespace fs = std::filesystem;

namespace
{
    std::mutex g_mutex;
    std::vector<NativeString> g_relaunchArgs;
    std::optional<PendingInstall> g_pending;

    // path::string() throws on Windows for characters outside the ANSI code page: print UTF-8 instead
    std::string Printable(const fs::path& p)
    {
        const auto u8 = p.u8string();
        return std::string(u8.begin(), u8.end());
    }

    NativeString Arg(std::string_view ascii)
    {
        return NativeString(ascii.begin(), ascii.end());
    }

    std::string RandomSuffix()
    {
        std::random_device rd;
        std::uniform_int_distribution<uint32> dist;
        char buf[17];
        snprintf(buf, sizeof(buf), "%08x%08x", dist(rd), dist(rd));
        return buf;
    }

    // private folder for the helper copy: created fresh (never reused), owner-only on Unix
    std::optional<fs::path> CreatePrivateTempDir()
    {
        std::error_code ec;
        const auto base = fs::temp_directory_path(ec);
        if (ec)
            return std::nullopt;
        for (int attempt = 0; attempt < 8; attempt++) {
            const auto dir = base / ("GView-update-" + RandomSuffix());
#ifdef BUILD_FOR_WINDOWS
            if (fs::create_directory(dir, ec) && !ec)
                return dir;
#else
            if (::mkdir(dir.c_str(), 0700) == 0)
                return dir;
#endif
        }
        return std::nullopt;
    }

    fs::path ChooseOldDir(const fs::path& installDir, const Version& v)
    {
        const auto work = UpdateWorkDir(installDir);
        std::error_code ec;
        auto candidate = work / ("old-" + v.ToString());
        for (int i = 2; fs::exists(candidate, ec) && i < 1000; i++)
            candidate = work / ("old-" + v.ToString() + "-" + std::to_string(i));
        return candidate;
    }

#ifdef BUILD_FOR_WINDOWS
    // CommandLineToArgvW compatible quoting
    std::wstring QuoteArgument(const std::wstring& arg)
    {
        if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos)
            return arg;
        std::wstring out = L"\"";
        for (size_t i = 0;; i++) {
            size_t backslashes = 0;
            while (i < arg.size() && arg[i] == L'\\') {
                backslashes++;
                i++;
            }
            if (i == arg.size()) {
                out.append(backslashes * 2, L'\\');
                break;
            }
            if (arg[i] == L'"') {
                out.append(backslashes * 2 + 1, L'\\');
                out.push_back(L'"');
            } else {
                out.append(backslashes, L'\\');
                out.push_back(arg[i]);
            }
        }
        out.push_back(L'"');
        return out;
    }
#endif
} // namespace

int RunAndWait(const fs::path& executable, const std::vector<NativeString>& args)
{
#ifdef BUILD_FOR_WINDOWS
    std::wstring commandLine = QuoteArgument(executable.native());
    for (const auto& a : args) {
        commandLine.push_back(L' ');
        commandLine += QuoteArgument(a);
    }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // no CREATE_NEW_CONSOLE: the child attaches to this console, so the terminal session stays the same
    if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return -1;
    CloseHandle(pi.hThread);
    // Ctrl+C reaches every process of the console: let the child decide, the supervisor must outlive it
    SetConsoleCtrlHandler(nullptr, TRUE);
    WaitForSingleObject(pi.hProcess, INFINITE);
    SetConsoleCtrlHandler(nullptr, FALSE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
#else
    std::vector<std::string> storage;
    storage.reserve(args.size() + 1);
    storage.push_back(executable.native());
    for (const auto& a : args)
        storage.push_back(a);
    std::vector<char*> argv;
    for (auto& s : storage)
        argv.push_back(s.data());
    argv.push_back(nullptr);

    // the supervisor ignores SIGINT/SIGQUIT while waiting (like system()); the child gets the default handlers back
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t defaults;
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGINT);
    sigaddset(&defaults, SIGQUIT);
    posix_spawnattr_setsigdefault(&attr, &defaults);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF);

    struct sigaction ignore{}, oldInt{}, oldQuit{};
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGINT, &ignore, &oldInt);
    sigaction(SIGQUIT, &ignore, &oldQuit);

    pid_t pid    = 0;
    const int rc = posix_spawn(&pid, executable.c_str(), nullptr, &attr, argv.data(), environ);
    posix_spawnattr_destroy(&attr);
    int result = -1;
    if (rc == 0) {
        int status = 0;
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) {
                status = -1;
                break;
            }
        }
        if (status >= 0 && WIFEXITED(status))
            result = WEXITSTATUS(status);
        else if (status >= 0 && WIFSIGNALED(status))
            result = 128 + WTERMSIG(status);
    }
    sigaction(SIGINT, &oldInt, nullptr);
    sigaction(SIGQUIT, &oldQuit, nullptr);
    return result;
#endif
}

void SetRelaunchArguments(std::vector<NativeString> args)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    g_relaunchArgs = std::move(args);
}

void SetPending(PendingInstall pending)
{
    std::lock_guard<std::mutex> lk(g_mutex);
    g_pending = std::move(pending);
}

bool HasPending() noexcept
{
    std::lock_guard<std::mutex> lk(g_mutex);
    return g_pending.has_value();
}

int Execute()
{
    PendingInstall p;
    std::vector<NativeString> relaunchArgs;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if (!g_pending.has_value())
            return 0;
        p = *g_pending;
        g_pending.reset();
        relaunchArgs = g_relaunchArgs;
    }
    const auto versionText = p.version.ToString();
    std::cout << "\nInstalling GView " << versionText << " ..." << std::endl;

    // 1. a private copy of the helper: the one in the installation folder is replaced while it runs
    std::error_code ec;
    auto helperSource = p.installDir / UPDATER_EXECUTABLE_NAME;
    if (!fs::is_regular_file(helperSource, ec))
        helperSource = p.stagingDir / UPDATER_EXECUTABLE_NAME;
    if (!fs::is_regular_file(helperSource, ec)) {
        std::cout << "Update not installed: " << UPDATER_EXECUTABLE_NAME << " was not found. GView " GVIEW_VERSION " is unchanged." << std::endl;
        fs::remove_all(p.stagingDir, ec);
        return 1;
    }
    const auto tempDir = CreatePrivateTempDir();
    if (!tempDir.has_value()) {
        std::cout << "Update not installed: unable to create a temporary folder. GView " GVIEW_VERSION " is unchanged." << std::endl;
        fs::remove_all(p.stagingDir, ec);
        return 1;
    }
    const auto helper = *tempDir / UPDATER_EXECUTABLE_NAME;
    fs::copy_file(helperSource, helper, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        std::cout << "Update not installed: unable to copy " << UPDATER_EXECUTABLE_NAME << ". GView " GVIEW_VERSION " is unchanged." << std::endl;
        fs::remove_all(*tempDir, ec);
        fs::remove_all(p.stagingDir, ec);
        return 1;
    }
#ifndef BUILD_FOR_WINDOWS
    fs::permissions(helper, fs::perms::owner_all, fs::perm_options::replace, ec);
#endif

    // 2. swap the files
    const auto oldDir = ChooseOldDir(p.installDir, p.version);
    const int code =
          RunAndWait(helper, { Arg("apply"), Arg("--staging"), p.stagingDir.native(), Arg("--target"), p.installDir.native(), Arg("--old"), oldDir.native() });
    fs::remove_all(*tempDir, ec);

    switch (code) {
    case UPDATER_OK:
        break;
    case UPDATER_REFUSED:
    case UPDATER_ROLLED_BACK:
        std::cout << "Update not installed (see " << Printable(oldDir / "updater.log") << "). GView " GVIEW_VERSION " is unchanged." << std::endl;
        fs::remove_all(p.stagingDir, ec);
        return 1;
    case UPDATER_ROLLBACK_INCOMPLETE:
        std::cout << "The update failed and could not be fully rolled back.\n"
                  << "The previous files are in: " << Printable(oldDir) << "\n"
                  << "The journal of the moved files is: " << Printable(oldDir / "journal.txt") << "\n"
                  << "Reinstall GView from https://github.com/gdt050579/GView/releases if it does not start." << std::endl;
        return 2;
    default:
        std::cout << "Update not installed: " << UPDATER_EXECUTABLE_NAME << " failed (exit code " << code << "). GView " GVIEW_VERSION " is unchanged."
                  << std::endl;
        fs::remove_all(p.stagingDir, ec);
        return 1;
    }

    // 3. restart with the same command line
    std::cout << "GView " << versionText << " installed. Restarting ..." << std::endl;
    const int rc = RunAndWait(p.gviewExecutable, relaunchArgs);
    if (rc < 0) {
        std::cout << "GView " << versionText << " was installed but could not be started: " << Printable(p.gviewExecutable) << std::endl;
        return 1;
    }
    return rc;
}
} // namespace GView::Update::Installer
