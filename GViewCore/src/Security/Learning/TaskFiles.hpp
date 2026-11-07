#pragma once

// Local copies of file-mode task content (no Save dialog):
//
//     <base>/<server host>/<week>/<file>          base = [GView] LearningDownloadFolder or <Documents>/GView
//
// Every path component comes from untrusted server data and goes through SanitizePathComponent. A small manifest
// (TASK_MANIFEST_FILE_NAME, hidden on Windows) in each week folder records which catalogue item owns which file and the
// SHA-256 of the version GView wrote there, so that:
//   - two items never share a file (a file name already owned by another item is prefixed with the item name; item
//     names are unique on a server, so two weeks whose names sanitize to the same folder still cannot collide);
//   - opening an item again reuses the local copy while it still matches the server;
//   - a copy that was changed on disk is detected and never replaced without asking.

#include "ContentDelivery.hpp"

#include <map>
#include <optional>

namespace GView::Security::Learning
{
constexpr std::string_view TASK_MANIFEST_FILE_NAME = ".gview-items.json";

// <base>/<server>/<week>
std::filesystem::path TaskFolder(std::string_view configuredFolder, std::string_view serverUrl, std::string_view weekName);

class TaskFileStore
{
  public:
    enum class LocalState : uint8 {
        Missing,      // nothing on disk yet: write the server version
        SameAsServer, // the local file already holds the server version: open it as it is
        Outdated,     // unchanged since GView wrote it, but the server now has another version: replace it
        Modified,     // differs from what GView wrote (changed on disk): ask before replacing it
    };
    struct Plan {
        std::filesystem::path path;
        std::string file; // file name inside the folder (UTF-8, already sanitized)
        LocalState state{ LocalState::Missing };
    };

    // Reads the manifest of the folder; a missing or damaged manifest is treated as empty.
    explicit TaskFileStore(std::filesystem::path folder);

    const std::filesystem::path& Folder() const noexcept
    {
        return folder;
    }

    // The local copy of the item when it exists and its content hashes to sha256 (the checksum from the catalogue).
    std::optional<std::filesystem::path> FindUpToDate(std::string_view itemName, std::string_view sha256) const;

    // Where the delivered content of the item goes and what is there now (hashes the existing file, if any).
    Plan PlanFor(std::string_view itemName, std::string_view deliveredFileName, std::string_view serverSha256) const;

    // Writes the content to plan.path (atomic, verified against sha256) and records it in the manifest.
    Utils::GStatus Store(
          const Plan& plan, std::string_view itemName, BufferView data, std::string_view sha256, uint32 itemVersion, std::filesystem::path& outPath);

    // Records that plan.path is the item's file and stays as it is: a SameAsServer copy, or a Modified copy the student
    // chose to keep (it is reported as Modified again on the next open).
    void Keep(const Plan& plan, std::string_view itemName, std::string_view serverSha256, uint32 itemVersion);

    // Version of the server content GView last recorded for the item (0 = unknown).
    uint32 RecordedVersion(std::string_view itemName) const;

    // The item's file in this folder, when GView recorded one and it still exists (no hashing).
    std::optional<std::filesystem::path> KnownFile(std::string_view itemName) const;

  private:
    struct Entry {
        std::string file;
        std::string sha256;
        uint32 itemVersion{ 0 };
    };
    std::filesystem::path folder;
    std::map<std::string, Entry, std::less<>> entries;

    bool IsTakenByAnotherItem(std::string_view file, std::string_view itemName) const;
    void Load();
    bool Save() const; // best effort: a lost manifest only costs a hash comparison (or a question) on the next open
};
} // namespace GView::Security::Learning
