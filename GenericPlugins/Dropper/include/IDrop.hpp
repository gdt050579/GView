#pragma once

#include "GView.hpp"

using namespace GView::Utils;

namespace GView::GenericPlugins::Droppper
{
static const uint8 MAX_PRECACHED_BUFFER_SIZE = 8;

enum class Result : uint32 {
    NotFound = 0, // -> nothing found
    Buffer,       // -> artefact found -> drop it as a buffer
    Ascii,        // -> artefact found -> drop it as ascii
    Unicode,      // -> artefact found -> drop it as unicode (skip 0)
};

enum class Priority : uint32 { Binary = 0, Text = 1, Count = 2 };

enum class ObjectCategory : uint32 {
    Archive        = 0,
    AVStrings      = 1,
    Cryptographic  = 2,
    Executables    = 3,
    HtmlObjects    = 4,
    Image          = 5,
    Multimedia     = 6,
    SpecialStrings = 7,
};

class IDrop
{
  public:
    // virtual methods
    virtual const char* GetName()            = 0; // specific dropper mini-plugin name
    virtual ObjectCategory GetGroup()        = 0; // archive type recognizer, executables type, etc
    virtual const char* GetOutputExtension() = 0; // dropped file extension
    virtual Priority GetPriority()           = 0; // get plugin priority
    virtual bool ShouldGroupInOneFile()      = 0; // URLs, IPs, etc

    // prechachedBufferSize -> max 8
    virtual Result Check(uint64 offset, DataCache& file, BufferView precachedBuffer, uint64& start, uint64& end) = 0;

    // functii deja existente
    inline bool IsMagicU16(BufferView precachedBuffer, uint16 magic)
    {
        if (precachedBuffer.GetLength() >= 2) {
            return *reinterpret_cast<const uint16*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline bool IsMagicU32(BufferView precachedBuffer, uint32 magic)
    {
        if (precachedBuffer.GetLength() >= 4) {
            return *reinterpret_cast<const uint32*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline bool IsMagicU64(BufferView precachedBuffer, uint64 magic)
    {
        if (precachedBuffer.GetLength() >= 8) {
            return *reinterpret_cast<const uint64*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    // TODO: isn't this a memcmp..?
    inline bool IsBuffer(uint64 offset, DataCache& file, BufferView bv)
    {
        CHECK(bv.IsValid(), false, "");

        auto bufferSize = bv.GetLength();
        auto buffer     = bv.GetData();

        while (bufferSize) {
            if (file.GetFromCache(offset) != *buffer) {
                return false;
            }
            buffer++;
            offset++;
            bufferSize--;
        }

        return true;
    }

    // TODO: is this a valid/required callback?
    inline uint64 ParseAscii(uint64 offset, DataCache& file, bool (*isValidChar)(char ch))
    {
        // dummy body
        const auto a = file.Get(offset, 1, true);
        return isValidChar(*(char*) a.GetData());
    }

    // TODO: is this a valid/required callback?
    inline uint64 ParseUnicode(uint64 offset, DataCache& file, bool (*isValidChar)(uint16 ch))
    {
        // dummy body
        const auto a = file.Get(offset, 2, true);
        return isValidChar(*(uint16*) a.GetData());
    }
};
} // namespace GView::GenericPlugins::Droppper
