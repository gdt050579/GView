#include "../include/GView.hpp"

#include <mz.h>
#include <mz_os.h>
#include <mz_strm.h>
#include <mz_strm_buf.h>
#include <mz_strm_split.h>
#include <mz_zip.h>
#include <mz_zip_rw.h>

#include <locale>
#include <codecvt>

namespace GView::ZIP
{
using mz_zip_reader_create_ptr = struct Reader
{
    void* value{ nullptr };

    void Reset()
    {
        if (value != nullptr)
        {
            mz_zip_reader_delete(&value);
            value = nullptr;
        }
    };

    ~Reader()
    {
        Reset();
    }
};

struct _Entry
{
    uint16_t version_madeby;     /* version made by */
    uint16_t version_needed;     /* version needed to extract */
    uint16_t flag;               /* general purpose bit flag */
    uint16_t compression_method; /* compression method */
    time_t modified_date;        /* last modified date in unix time */
    time_t accessed_date;        /* last accessed date in unix time */
    time_t creation_date;        /* creation date in unix time */
    uint32_t crc;                /* crc-32 */
    int64_t compressed_size;     /* compressed size */
    int64_t uncompressed_size;   /* uncompressed size */
    uint16_t filename_size;      /* filename length */
    uint16_t extrafield_size;    /* extra field length */
    uint16_t comment_size;       /* file comment length */
    uint32_t disk_number;        /* disk number start */
    int64_t disk_offset;         /* relative offset of local header */
    uint16_t internal_fa;        /* internal file attributes */
    uint32_t external_fa;        /* external file attributes */

    std::u8string filename;              /* filename utf8 null-terminated string */
    std::unique_ptr<uint8_t> extrafield; /* extrafield data */
    std::u8string comment;               /* comment utf8 null-terminated string */
    std::u8string linkname;              /* sym-link filename utf8 null-terminated string */

    uint16_t zip64;              /* zip64 extension mode */
    uint16_t aes_version;        /* winzip aes extension if not 0 */
    uint8_t aes_encryption_mode; /* winzip aes encryption mode */
    uint16_t pk_verify;          /* pkware encryption verifier */

    EntryType type;
};

void ConvertZipFileInfoToEntry(const mz_zip_file* zipFile, _Entry& entry)
{
    entry.version_madeby     = zipFile->version_madeby;
    entry.version_needed     = zipFile->version_needed;
    entry.flag               = zipFile->flag;
    entry.compression_method = zipFile->compression_method;
    entry.modified_date      = zipFile->modified_date;
    entry.accessed_date      = zipFile->accessed_date;
    entry.creation_date      = zipFile->creation_date;
    entry.crc                = zipFile->crc;
    entry.compressed_size    = zipFile->compressed_size;
    entry.uncompressed_size  = zipFile->uncompressed_size;
    entry.filename_size      = zipFile->filename_size;
    entry.extrafield_size    = zipFile->extrafield_size;
    entry.comment_size       = zipFile->comment_size;
    entry.disk_number        = zipFile->disk_number;
    entry.disk_offset        = zipFile->disk_offset;
    entry.internal_fa        = zipFile->internal_fa;
    entry.external_fa        = zipFile->external_fa;

    entry.filename.resize(zipFile->filename_size);
    memcpy(entry.filename.data(), zipFile->filename, zipFile->filename_size);

    entry.extrafield.reset(new uint8_t[zipFile->extrafield_size]);
    memcpy(entry.extrafield.get(), zipFile->extrafield, zipFile->extrafield_size);

    entry.comment.resize(zipFile->comment_size);
    memcpy(entry.comment.data(), zipFile->comment, zipFile->comment_size);

    const auto linknameSize = strlen(zipFile->linkname);
    entry.linkname.resize(linknameSize);
    memcpy(entry.linkname.data(), zipFile->linkname, linknameSize);

    entry.zip64               = zipFile->zip64;
    entry.aes_version         = zipFile->aes_version;
    entry.aes_encryption_mode = zipFile->aes_encryption_mode;
    entry.pk_verify           = zipFile->pk_verify;

    entry.type = EntryType::Unknown;

    const bool isDir     = (mz_zip_entry_is_dir((void*) zipFile) == MZ_OK);
    const bool isSymlink = (mz_zip_entry_is_symlink((void*) zipFile) == MZ_OK);
    if (isDir)
    {
        entry.type = EntryType::Directory;
    }
    else
    {
        if (isSymlink)
        {
            entry.type = EntryType::Symlink;
        }
        else
        {
            entry.type = EntryType::File;
        }
    }
}

struct _Info
{
    std::string path;
    mz_zip_reader_create_ptr reader{};
    std::vector<_Entry> entries;
};

uint32 Info::GetCount() const
{
    return (uint32) reinterpret_cast<_Info*>(context)->entries.size();
}

bool Info::GetEntry(uint32 index, Entry& entry) const
{
    auto info = reinterpret_cast<_Info*>(context);
    CHECK(index < info->entries.size(), false, "");

    entry.context = &info->entries.at(index);

    return true;
}

Info::Info()
{
    this->context = new _Info();
}

Info::~Info()
{
    delete reinterpret_cast<_Info*>(this->context);
}

std::u8string_view Entry::GetFilename() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->filename;
}

uint16 Entry::GetFlags() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->flag;
}

static inline std::string_view GetSignatureFlagName(uint32 flag)
{
    switch (flag)
    {
    case MZ_ZIP_FLAG_ENCRYPTED:
        return "ENCRYPTED";
    // case MZ_ZIP_FLAG_LZMA_EOS_MARKER:
    //     return "LZMA_EOS_MARKER";
    case MZ_ZIP_FLAG_DEFLATE_MAX:
        return "DEFLATE_MAX";
    case MZ_ZIP_FLAG_DEFLATE_NORMAL:
        return "DEFLATE_NORMAL";
    case MZ_ZIP_FLAG_DEFLATE_FAST:
        return "DEFLATE_FAST";
    case MZ_ZIP_FLAG_DEFLATE_SUPER_FAST:
        return "DEFLATE_SUPER_FAST";
    case MZ_ZIP_FLAG_DATA_DESCRIPTOR:
        return "DATA_DESCRIPTOR";
    default:
        return "UNKNOWN";
    }
}

std::string Entry::GetFlagNames() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);

    static std::initializer_list<uint32> flags{ MZ_ZIP_FLAG_ENCRYPTED,    MZ_ZIP_FLAG_DEFLATE_MAX,        MZ_ZIP_FLAG_DEFLATE_NORMAL,
                                                MZ_ZIP_FLAG_DEFLATE_FAST, MZ_ZIP_FLAG_DEFLATE_SUPER_FAST, MZ_ZIP_FLAG_DATA_DESCRIPTOR };

    std::string output;

    for (const auto& iFlag : flags)
    {
        const auto flag = static_cast<uint32>(iFlag & entry->flag);
        if (flag != iFlag)
        {
            continue;
        }

        if ((flag & MZ_ZIP_FLAG_DEFLATE_SUPER_FAST) == MZ_ZIP_FLAG_DEFLATE_SUPER_FAST &&
            (flag == MZ_ZIP_FLAG_DEFLATE_MAX || flag == MZ_ZIP_FLAG_DEFLATE_FAST))
        {
            continue; // write only super fast flag
        }

        if (!output.empty())
        {
            output += " | ";
        }
        output += GetSignatureFlagName(iFlag);
    }

    return output;
}

int64 Entry::GetCompressedSize() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->compressed_size;
}

int64 Entry::GetUncompressedSize() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->uncompressed_size;
}

int64 Entry::GetCompressionMethod() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->compression_method;
}

std::string Entry::GetCompressionMethodName() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return std::string(mz_zip_get_compression_method_string(entry->compression_method));
}

uint32 Entry::GetDiskNumber() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->disk_number;
}

int64 Entry::GetDiskOffset() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->disk_offset;
}

EntryType Entry::GetType() const
{
    CHECK(context != nullptr, EntryType::Unknown, "");
    auto entry = reinterpret_cast<_Entry*>(context);

    return entry->type;
}

std::string_view Entry::GetTypeName() const
{
    CHECK(context != nullptr, "Unknown", "");
    auto entry = reinterpret_cast<_Entry*>(context);

    switch (entry->type)
    {
    case EntryType::Directory:
        return "Directory";
    case EntryType::Symlink:
        return "Symlink";
    case EntryType::File:
        return "File";
    case EntryType::Unknown:
    default:
        return "Unknown";
    }
}

bool Info::Decompress(Buffer& output, uint32 index, const std::string& password) const
{
    CHECK(context != nullptr, false, "");
    auto info = reinterpret_cast<_Info*>(context);

    CHECK(index < info->entries.size(), false, "");
    auto& entry = info->entries.at(index);
    CHECK(entry.type == EntryType::File, false, "");

    mz_zip_reader_create_ptr reader{ nullptr };
    mz_zip_reader_create(&reader.value);
    mz_zip_reader_set_password(reader.value, password.c_str());
    mz_zip_reader_set_pattern(reader.value, (char*) entry.filename.data(), 0);

    CHECK(mz_zip_reader_open_file(reader.value, info->path.c_str()) == MZ_OK, false, "");

    output.Reserve(entry.uncompressed_size);

    CHECK(mz_zip_reader_entry_save_buffer(reader.value, output.GetData(), entry.uncompressed_size) == MZ_OK, false, "");

    output.Resize(entry.uncompressed_size);

    return true;
}

bool Info::Decompress(const BufferView& input, Buffer& output, uint32 index, const std::string& password) const
{
    CHECK(context != nullptr, false, "");
    auto info = reinterpret_cast<_Info*>(context);

    CHECK(index < info->entries.size(), false, "");
    auto& entry = info->entries.at(index);
    CHECK(entry.type == EntryType::File, false, "");

    mz_zip_reader_create_ptr reader{ nullptr };
    mz_zip_reader_create(&reader.value);
    mz_zip_reader_set_password(reader.value, password.c_str());
    mz_zip_reader_set_pattern(reader.value, (char*) entry.filename.data(), 0);

    CHECK(mz_zip_reader_open_buffer(
                reader.value,
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(input.GetData())),
                input.GetLength(),
                /* don't copy */ 0) == MZ_OK,
          false,
          "");

    output.Reserve(entry.uncompressed_size);

    CHECK(mz_zip_reader_entry_save_buffer(reader.value, output.GetData(), entry.uncompressed_size) == MZ_OK, false, "");

    output.Resize(entry.uncompressed_size);

    return true;
}

bool GetInfo(std::u16string_view path, Info& info)
{
    auto internalInfo = reinterpret_cast<_Info*>(info.context);
    CHECK(internalInfo, false, "");

    internalInfo->reader.Reset();
    mz_zip_reader_create(&internalInfo->reader.value);

    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    std::u16string p(path);
    internalInfo->entries.clear();
    internalInfo->path = convert.to_bytes(p);

    CHECK(mz_zip_reader_open_file(internalInfo->reader.value, internalInfo->path.c_str()) == MZ_OK, false, "");
    CHECK(mz_zip_reader_goto_first_entry(internalInfo->reader.value) == MZ_OK, false, "");

    do
    {
        mz_zip_file* zipFile{ nullptr };
        CHECKBK(mz_zip_reader_entry_get_info(internalInfo->reader.value, &zipFile) == MZ_OK, "");
        mz_zip_reader_set_pattern(internalInfo->reader.value, nullptr, 1); // do we need a pattern?

        auto& entry = internalInfo->entries.emplace_back();
        ConvertZipFileInfoToEntry(zipFile, entry);

        CHECKBK(mz_zip_reader_goto_next_entry(internalInfo->reader.value) == MZ_OK, "");
    } while (true);

    return true;
}

bool GetInfo(Utils::DataCache& cache, Info& info)
{
    auto internalInfo = reinterpret_cast<_Info*>(info.context);
    CHECK(internalInfo, false, "");

    internalInfo->reader.Reset();
    mz_zip_reader_create(&internalInfo->reader.value);

    // mz_zip_reader_set_password(reader, password.c_str()); // do we want to try a password?
    // mz_zip_reader_set_encoding(reader.get(), 0);

    // not the best option.. you might want to stream this or drop it on the disk as a temp file
    // every option has its downsides
    auto buffer = cache.GetEntireFile();
    CHECK(buffer.IsValid(), false, "");

    CHECK(mz_zip_reader_open_buffer(
                internalInfo->reader.value,
                const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(buffer.GetData())),
                buffer.GetLength(),
                /* don't copy */ 0) == MZ_OK,
          false,
          "");
    CHECK(mz_zip_reader_goto_first_entry(internalInfo->reader.value) == MZ_OK, false, "");

    do
    {
        mz_zip_file* zipFile{ nullptr };
        CHECKBK(mz_zip_reader_entry_get_info(internalInfo->reader.value, &zipFile) == MZ_OK, "");
        mz_zip_reader_set_pattern(internalInfo->reader.value, nullptr, 1); // do we need a pattern?

        auto& entry = internalInfo->entries.emplace_back();
        ConvertZipFileInfoToEntry(zipFile, entry);

        CHECKBK(mz_zip_reader_goto_next_entry(internalInfo->reader.value) == MZ_OK, "");
    } while (true);

    return true;
}

} // namespace GView::ZIP
