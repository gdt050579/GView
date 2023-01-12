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
    ~Reader()
    {
        if (value != nullptr)
        {
            mz_zip_reader_delete(&value);
        }
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

    std::unique_ptr<char> filename;      /* filename utf8 null-terminated string */
    std::unique_ptr<uint8_t> extrafield; /* extrafield data */
    std::unique_ptr<char> comment;       /* comment utf8 null-terminated string */
    std::unique_ptr<char> linkname;      /* sym-link filename utf8 null-terminated string */

    uint16_t zip64;              /* zip64 extension mode */
    uint16_t aes_version;        /* winzip aes extension if not 0 */
    uint8_t aes_encryption_mode; /* winzip aes encryption mode */
    uint16_t pk_verify;          /* pkware encryption verifier */
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

    entry.filename.reset(new char[zipFile->filename_size + 1]);
    memcpy(entry.filename.get(), zipFile->filename, zipFile->filename_size + 1);
    entry.filename.get()[zipFile->filename_size] = 0;

    entry.extrafield.reset(new uint8_t[zipFile->extrafield_size]);
    memcpy(entry.extrafield.get(), zipFile->extrafield, zipFile->extrafield_size + 1);
    entry.extrafield.get()[zipFile->extrafield_size] = 0;

    entry.comment.reset(new char[zipFile->comment_size]);
    memcpy(entry.comment.get(), zipFile->comment, zipFile->comment_size + 1);
    entry.comment.get()[zipFile->comment_size] = 0;

    const auto linknameSize = strlen(zipFile->linkname) + 1;
    entry.linkname.reset(new char[linknameSize]);
    memcpy(entry.linkname.get(), zipFile->linkname, linknameSize);
    entry.linkname.get()[linknameSize - 1] = 0;

    entry.zip64               = zipFile->zip64;
    entry.aes_version         = zipFile->aes_version;
    entry.aes_encryption_mode = zipFile->aes_encryption_mode;
    entry.pk_verify           = zipFile->pk_verify;
}

struct _Info
{
    std::vector<_Entry> entries;
};

uint32 Info::GetCount() const
{
    return reinterpret_cast<_Info*>(context)->entries.size();
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

std::string_view Entry::GetFilename() const
{
    CHECK(context != nullptr, 0, "");
    auto entry = reinterpret_cast<_Entry*>(context);
    return entry->filename.get();
}

bool GetInfo(std::u16string_view path, Info& info)
{
    mz_zip_reader_create_ptr reader{};
    mz_zip_reader_create(&reader.value);

    // mz_zip_reader_set_password(reader, password.c_str()); // do we want to try a password?
    // mz_zip_reader_set_encoding(reader.get(), 0);

    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    std::u16string p(path);
    std::string source = convert.to_bytes(p);

    CHECK(mz_zip_reader_open_file(reader.value, source.c_str()) == MZ_OK, false, "");
    CHECK(mz_zip_reader_goto_first_entry(reader.value) == MZ_OK, false, "");

    auto internalInfo = reinterpret_cast<_Info*>(info.context);
    CHECK(internalInfo, false, "");
    internalInfo->entries.clear();
    do
    {
        mz_zip_file* zipFile{ nullptr };
        CHECKBK(mz_zip_reader_entry_get_info(reader.value, &zipFile) == MZ_OK, "");
        mz_zip_reader_set_pattern(reader.value, nullptr, 1); // do we need a pattern?

        auto& entry = internalInfo->entries.emplace_back();
        ConvertZipFileInfoToEntry(zipFile, entry);

        CHECKBK(mz_zip_reader_goto_next_entry(reader.value) == MZ_OK, "");
    } while (true);

    return true;
}
} // namespace GView::ZIP
