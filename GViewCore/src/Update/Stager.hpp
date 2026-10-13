#pragma once

// Download -> verify -> extract a release into <install>/.update/staging-<version>/ (worker thread).
// Nothing in the installation folder itself is modified here: GViewUpdater applies the staged files after GView exits.

#include "UpdateCore.hpp"

#include <atomic>
#include <filesystem>
#include <string>
#include <vector>

namespace GView::Update
{
enum class StagePhase : uint32 { Preparing, Downloading, Verifying, Extracting, Done };

struct StageProgress {
    std::atomic<StagePhase> phase{ StagePhase::Preparing };
    std::atomic<uint64> done{ 0 };
    std::atomic<uint64> total{ 0 };
};

struct StageResult {
    bool ok{ false };
    bool cancelled{ false };
    std::filesystem::path stagingDir;
    std::vector<std::string> files; // relative paths ('/' separators) listed in the manifest
    std::string error;
};

// <install>/.update
std::filesystem::path UpdateWorkDir(const std::filesystem::path& installDir);
// true when the update work folder can be created and written (the installation folder is writable)
bool CanWriteInstallDir(const std::filesystem::path& installDir);

StageResult StageRelease(
      const ReleaseInfo& release,
      const std::filesystem::path& installDir,
      const UpdateSettings& settings,
      StageProgress& progress,
      const std::atomic<bool>& cancel);

// Exposed for unit tests: validates and extracts 'zipPath' into 'stagingDir' (must not exist) and writes the manifest.
StageResult ExtractRelease(
      const std::filesystem::path& zipPath,
      const std::filesystem::path& stagingDir,
      const Version& version,
      StageProgress& progress,
      const std::atomic<bool>& cancel);

// lowercase hex SHA-256 of a file (empty on I/O error or cancellation)
std::string Sha256File(const std::filesystem::path& file, const std::atomic<bool>& cancel);

// Startup housekeeping: removes stale staging folders / partial downloads and old-* folders the updater marked as DONE.
void CleanupWorkDir(const std::filesystem::path& installDir) noexcept;
} // namespace GView::Update
