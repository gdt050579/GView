#include "Stager.hpp"
#include "HttpClient.hpp"

#include <mz.h>
#include <mz_strm.h>
#include <mz_zip.h>
#include <mz_zip_rw.h>
#include <openssl/evp.h>

#include <fstream>
#include <memory>
#include <set>

namespace GView::Update
{
namespace fs = std::filesystem;

namespace
{
    constexpr std::string_view STAGING_PREFIX = "staging-";
    constexpr std::string_view OLD_PREFIX     = "old-";
    constexpr std::string_view DONE_MARKER    = "DONE";

    fs::path FromUtf8(std::string_view s)
    {
        return fs::path(std::u8string(s.begin(), s.end()));
    }

    std::string LowerAscii(std::string_view s)
    {
        std::string r(s);
        for (auto& c : r)
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
        return r;
    }

    struct ZipReader {
        void* handle{ nullptr };
        ZipReader() : handle(mz_zip_reader_create())
        {
        }
        ~ZipReader()
        {
            if (handle) {
                mz_zip_reader_close(handle);
                mz_zip_reader_delete(&handle);
            }
        }
        ZipReader(const ZipReader&)            = delete;
        ZipReader& operator=(const ZipReader&) = delete;
    };

    struct EntryInfo {
        std::string path; // normalised, '/' separators
        bool isDir{ false };
        uint64 size{ 0 };
        uint32 unixMode{ 0 }; // permission bits when the archive was made on Unix
    };

    StageResult Fail(std::string error)
    {
        StageResult r;
        r.error = std::move(error);
        return r;
    }

    // Pass 1: read the central directory, validate every entry and collect the list (nothing is written)
    bool ScanArchive(void* reader, std::vector<EntryInfo>& entries, std::string& error)
    {
        std::set<std::string> seen;
        uint64 totalSize = 0;
        int32 err        = mz_zip_reader_goto_first_entry(reader);
        while (err == MZ_OK) {
            if (entries.size() >= MAX_ZIP_ENTRIES) {
                error = "the archive has too many entries";
                return false;
            }
            mz_zip_file* info = nullptr;
            if (mz_zip_reader_entry_get_info(reader, &info) != MZ_OK || info == nullptr || info->filename == nullptr) {
                error = "the archive is corrupted";
                return false;
            }
            const auto normalized = NormalizeZipEntryPath(std::string_view(info->filename, info->filename_size));
            if (!normalized.has_value()) {
                error = "the archive contains an unsafe path";
                return false;
            }
            if ((info->flag & MZ_ZIP_FLAG_ENCRYPTED) != 0) {
                error = "the archive contains encrypted entries";
                return false;
            }
            if (mz_zip_attrib_is_symlink(info->external_fa, info->version_madeby) == MZ_OK) {
                error = "the archive contains symbolic links";
                return false;
            }
            EntryInfo e;
            e.isDir = normalized->back() == '/' || mz_zip_reader_entry_is_dir(reader) == MZ_OK;
            e.path  = *normalized;
            if (!e.isDir) {
                if (info->uncompressed_size < 0 || static_cast<uint64>(info->uncompressed_size) > MAX_EXTRACTED_BYTES - totalSize) {
                    error = "the archive is too large once extracted";
                    return false;
                }
                e.size = static_cast<uint64>(info->uncompressed_size);
                totalSize += e.size;
                // case-insensitive file systems would merge "A" and "a": refuse duplicates on every platform
                if (!seen.insert(LowerAscii(e.path)).second) {
                    error = "the archive contains duplicated entries";
                    return false;
                }
            }
            if (MZ_HOST_SYSTEM(info->version_madeby) == MZ_HOST_SYSTEM_UNIX || MZ_HOST_SYSTEM(info->version_madeby) == MZ_HOST_SYSTEM_OSX_DARWIN)
                e.unixMode = (info->external_fa >> 16) & 0777u;
            entries.push_back(std::move(e));
            err = mz_zip_reader_goto_next_entry(reader);
        }
        if (err != MZ_END_OF_LIST) {
            error = "the archive is corrupted";
            return false;
        }
        return true;
    }

    bool ExtractEntry(void* reader, const EntryInfo& entry, const fs::path& dest, const std::atomic<bool>& cancel, StageProgress& progress, std::string& error)
    {
        std::error_code ec;
        fs::create_directories(dest.parent_path(), ec);
        if (ec) {
            error = "unable to create a folder in the staging area";
            return false;
        }
        // the reader is positioned on this entry by the caller (same order as ScanArchive); double check the name
        mz_zip_file* info = nullptr;
        if (mz_zip_reader_entry_get_info(reader, &info) != MZ_OK || info == nullptr || info->filename == nullptr ||
            NormalizeZipEntryPath(std::string_view(info->filename, info->filename_size)) != entry.path) {
            error = "the archive is corrupted";
            return false;
        }
        if (mz_zip_reader_entry_open(reader) != MZ_OK) {
            error = "unable to read an archive entry";
            return false;
        }
        std::ofstream out(dest, std::ios::binary | std::ios::trunc);
        if (!out) {
            mz_zip_reader_entry_close(reader);
            error = "unable to write to the staging area";
            return false;
        }
        std::unique_ptr<char[]> buffer(new char[64 * 1024]);
        uint64 written = 0;
        while (true) {
            if (cancel.load(std::memory_order_acquire)) {
                mz_zip_reader_entry_close(reader);
                error = "cancelled";
                return false;
            }
            const int32 n = mz_zip_reader_entry_read(reader, buffer.get(), 64 * 1024);
            if (n < 0) {
                mz_zip_reader_entry_close(reader);
                error = "the archive is corrupted";
                return false;
            }
            if (n == 0)
                break;
            // never write more than the size declared in the central directory (decompression bombs, lying headers)
            if (static_cast<uint64>(n) > entry.size - written) {
                mz_zip_reader_entry_close(reader);
                error = "an archive entry is larger than declared";
                return false;
            }
            out.write(buffer.get(), n);
            if (!out) {
                mz_zip_reader_entry_close(reader);
                error = "unable to write to the staging area (disk full?)";
                return false;
            }
            written += static_cast<uint64>(n);
            progress.done.fetch_add(static_cast<uint64>(n), std::memory_order_relaxed);
        }
        out.close();
        // closing the entry verifies the CRC-32
        if (mz_zip_reader_entry_close(reader) != MZ_OK || written != entry.size || !out) {
            error = "an archive entry failed its integrity check";
            return false;
        }
#ifndef BUILD_FOR_WINDOWS
        auto perms          = fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read;
        const auto fileName = dest.filename().string();
        if ((entry.unixMode & 0111u) != 0 || fileName == GVIEW_EXECUTABLE_NAME || fileName == UPDATER_EXECUTABLE_NAME)
            perms |= fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec;
        fs::permissions(dest, perms, fs::perm_options::replace, ec);
#endif
        return true;
    }

    // removes every child except 'keep'; returns true when only 'keep' (or nothing) is left
    bool RemoveChildrenExcept(const fs::path& dir, std::string_view keep) noexcept
    {
        std::error_code ec;
        bool clean = true;
        for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
            if (it->path().filename() == FromUtf8(keep))
                continue;
            std::error_code rec;
            fs::remove_all(it->path(), rec);
            if (rec)
                clean = false;
        }
        return clean && !ec;
    }
} // namespace

fs::path UpdateWorkDir(const fs::path& installDir)
{
    return installDir / ".update";
}

bool CanWriteInstallDir(const fs::path& installDir)
{
    std::error_code ec;
    const auto work = UpdateWorkDir(installDir);
    fs::create_directories(work, ec);
    if (ec)
        return false;
    const auto probe = work / ".probe";
    {
        std::ofstream f(probe, std::ios::binary | std::ios::trunc);
        if (!f)
            return false;
        f << "probe";
        if (!f)
            return false;
    }
    // the updater replaces files by renaming them: probe that too
    const auto probe2 = work / ".probe2";
    fs::rename(probe, probe2, ec);
    const bool ok = !ec;
    fs::remove(probe, ec);
    fs::remove(probe2, ec);
    return ok;
}

std::string Sha256File(const fs::path& file, const std::atomic<bool>& cancel)
{
    std::ifstream in(file, std::ios::binary);
    if (!in)
        return {};
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return {};
    std::unique_ptr<char[]> buffer(new char[1024 * 1024]);
    while (in) {
        if (cancel.load(std::memory_order_acquire))
            return {};
        in.read(buffer.get(), 1024 * 1024);
        const auto n = in.gcount();
        if (n > 0 && EVP_DigestUpdate(ctx.get(), buffer.get(), static_cast<size_t>(n)) != 1)
            return {};
    }
    if (in.bad())
        return {};
    uint8 digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &len) != 1 || len != 32)
        return {};
    static constexpr char HEX[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (unsigned int i = 0; i < len; i++) {
        hex.push_back(HEX[digest[i] >> 4]);
        hex.push_back(HEX[digest[i] & 0x0F]);
    }
    return hex;
}

StageResult ExtractRelease(
      const fs::path& zipPath, const fs::path& stagingDir, const Version& version, StageProgress& progress, const std::atomic<bool>& cancel)
{
    progress.phase.store(StagePhase::Extracting);
    ZipReader zip;
    if (zip.handle == nullptr)
        return Fail("out of memory");
    const auto zipUtf8 = zipPath.u8string();
    if (mz_zip_reader_open_file(zip.handle, reinterpret_cast<const char*>(zipUtf8.c_str())) != MZ_OK)
        return Fail("the downloaded file is not a valid zip archive");

    std::vector<EntryInfo> entries;
    std::string error;
    if (!ScanArchive(zip.handle, entries, error))
        return Fail(error);

    std::vector<std::string> names;
    names.reserve(entries.size());
    for (const auto& e : entries)
        if (!e.isDir)
            names.push_back(e.path);
    const auto prefix = FindPayloadPrefix(names, GVIEW_EXECUTABLE_NAME);
    if (!prefix.has_value())
        return Fail("the archive does not contain exactly one " + std::string(GVIEW_EXECUTABLE_NAME));

    std::error_code ec;
    if (fs::exists(stagingDir, ec))
        return Fail("the staging folder already exists");
    fs::create_directories(stagingDir, ec);
    if (ec)
        return Fail("unable to create the staging folder");

    uint64 total = 0;
    for (const auto& e : entries)
        if (!e.isDir && e.path.starts_with(*prefix))
            total += e.size;
    progress.done.store(0);
    progress.total.store(total);

    StageResult result;
    result.stagingDir = stagingDir;
    // Pass 2: walk the central directory again in the same order as ScanArchive
    int32 err = mz_zip_reader_goto_first_entry(zip.handle);
    for (size_t index = 0; index < entries.size(); index++) {
        if (index > 0)
            err = mz_zip_reader_goto_next_entry(zip.handle);
        if (err != MZ_OK) {
            fs::remove_all(stagingDir, ec);
            return Fail("the archive is corrupted");
        }
        const auto& e = entries[index];
        if (e.isDir || !e.path.starts_with(*prefix))
            continue;
        const auto relative = e.path.substr(prefix->size());
        if (relative.empty() || IsProtectedPayloadPath(relative))
            continue;
        if (!ExtractEntry(zip.handle, e, stagingDir / FromUtf8(relative), cancel, progress, error)) {
            fs::remove_all(stagingDir, ec);
            result.cancelled = error == "cancelled";
            result.error     = std::move(error);
            return result;
        }
        result.files.push_back(relative);
    }

    // manifest consumed by GViewUpdater (plain text, one entry per line; names never contain control characters)
    {
        std::ofstream m(stagingDir / FromUtf8(MANIFEST_NAME), std::ios::binary | std::ios::trunc);
        m << MANIFEST_HEADER << '\n' << "version " << version.ToString() << '\n';
        for (const auto& f : result.files)
            m << "file " << f << '\n';
        m << "end\n";
        if (!m) {
            fs::remove_all(stagingDir, ec);
            return Fail("unable to write the update manifest");
        }
    }
    result.ok = true;
    progress.phase.store(StagePhase::Done);
    return result;
}

StageResult StageRelease(
      const ReleaseInfo& release, const fs::path& installDir, const UpdateSettings& settings, StageProgress& progress, const std::atomic<bool>& cancel)
{
    progress.phase.store(StagePhase::Preparing);
    const auto work = UpdateWorkDir(installDir);
    std::error_code ec;
    fs::create_directories(work, ec);
    if (ec)
        return Fail("unable to create the update work folder");

    const auto space = fs::space(work, ec);
    if (!ec && space.available < release.assetSize * 4 + 64ull * 1024ull * 1024ull)
        return Fail("not enough free disk space in the installation folder");

    const auto versionText = release.version.ToString();
    const auto stagingDir  = work / FromUtf8(std::string(STAGING_PREFIX) + versionText);
    const auto zipPath     = work / FromUtf8("download-" + versionText + ".zip");
    fs::remove_all(stagingDir, ec);
    fs::remove(zipPath, ec);

    // 1. checksum manifest (small, fetched first so a release without one fails fast)
    std::string expectedDigest;
    if (!release.checksumsUrl.empty()) {
        HttpGetRequest req;
        req.url                 = release.checksumsUrl;
        req.maxBytes            = MAX_MANIFEST_BYTES;
        req.followRedirects     = true;
        req.proxy               = settings.proxy;
        req.cancel              = &cancel;
        req.totalTimeoutSeconds = 60;
        const auto resp         = HttpGetToMemory(req);
        if (!resp.IsSuccess()) {
            StageResult r = Fail("unable to download the checksum list: " + resp.Describe());
            r.cancelled   = resp.cancelled;
            return r;
        }
        const auto digest = FindChecksum(resp.body, release.assetName);
        if (!digest.has_value())
            return Fail("the checksum list does not contain " + release.assetName);
        expectedDigest = *digest;
    } else {
#ifdef DISSASM_DEV
        // development builds may install releases published before checksums existed
#else
        return Fail("the release does not publish a SHA256SUMS checksum list; download it manually from the release page");
#endif
    }

    // 2. the release archive
    progress.phase.store(StagePhase::Downloading);
    progress.done.store(0);
    progress.total.store(release.assetSize);
    {
        HttpGetRequest req;
        req.url                 = release.assetUrl;
        req.headers             = { "Accept: application/octet-stream" };
        req.maxBytes            = release.assetSize; // GitHub reports the exact size
        req.followRedirects     = true;
        req.proxy               = settings.proxy;
        req.cancel              = &cancel;
        req.totalTimeoutSeconds = 0;
        req.lowSpeedSeconds     = 30;
        req.progress            = [&progress](uint64 received, uint64) { progress.done.store(received, std::memory_order_relaxed); };
        const auto resp         = HttpGetToFile(req, zipPath);
        if (!resp.IsSuccess()) {
            StageResult r = Fail("download failed: " + resp.Describe());
            r.cancelled   = resp.cancelled;
            return r;
        }
        if (fs::file_size(zipPath, ec) != release.assetSize || ec) {
            fs::remove(zipPath, ec);
            return Fail("the downloaded file has an unexpected size");
        }
    }

    // 3. integrity
    progress.phase.store(StagePhase::Verifying);
    if (!expectedDigest.empty()) {
        const auto digest = Sha256File(zipPath, cancel);
        if (digest != expectedDigest) {
            fs::remove(zipPath, ec);
            StageResult r = Fail(cancel.load() ? "cancelled" : "checksum mismatch: the downloaded file is corrupted or was tampered with");
            r.cancelled   = cancel.load();
            return r;
        }
    }

    // 4. extraction
    auto result = ExtractRelease(zipPath, stagingDir, release.version, progress, cancel);
    fs::remove(zipPath, ec);
    return result;
}

void CleanupWorkDir(const fs::path& installDir) noexcept
{
    try {
        const auto work = UpdateWorkDir(installDir);
        std::error_code ec;
        if (!fs::is_directory(work, ec))
            return;
        for (fs::directory_iterator it(work, ec), end; !ec && it != end; it.increment(ec)) {
            const auto name = it->path().filename().u8string();
            const std::string_view n(reinterpret_cast<const char*>(name.data()), name.size());
            std::error_code rec;
            if (n.starts_with(STAGING_PREFIX) || n.starts_with("download-") || n.starts_with(".probe")) {
                fs::remove_all(it->path(), rec);
            } else if (n.starts_with(OLD_PREFIX) && it->is_directory(rec)) {
                // old-* without the DONE marker holds the files of an interrupted update: keep it for manual recovery
                if (!fs::exists(it->path() / FromUtf8(DONE_MARKER), rec))
                    continue;
                if (RemoveChildrenExcept(it->path(), DONE_MARKER))
                    fs::remove_all(it->path(), rec);
            }
        }
        fs::remove(work, ec); // only succeeds when empty
    } catch (...) {
    }
}
} // namespace GView::Update
