#pragma once

#include "GView.hpp"

using namespace GView::Utils;

namespace GView::GenericPlugins::Droppper
{
enum class Result : uint32 {
    NotFound = 0, // -> nothing found
    Buffer,       // -> artefact found -> drop it as a buffer
    Unicode,      // -> artefact found -> drop it as unicode (skip 0)
    Ascii,        // -> artefact found -> drop it as ascii
};

enum class Priority : uint32 { Binary = 0, Text = 1 };

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
    virtual Result Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end) = 0;

    // functii deja existente
    inline bool IsMagicU16(unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint16 magic)
    {
        if (prechachedBufferSize >= 2) {
            return *(uint16*) prechachedBuffer == magic;
        }
        return false;
    }

    inline bool IsMagicU32(unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint32 magic)
    {
        if (prechachedBufferSize >= 4) {
            return *(uint32*) prechachedBuffer == magic;
        }
        return false;
    }

    inline bool IsBuffer(uint64 offset, DataCache& file, unsigned char* buffer, uint32 bufferSize)
    {
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

    inline uint64 ParseAscii(uint64 offset, DataCache& file, bool (*isValidChar)(char ch))
    {
        // dummy body
        const auto a = file.Get(offset, 1, true);
        return isValidChar(*(char*) a.GetData());
    }

    inline uint64 ParseUnicode(uint64 offset, DataCache& file, bool (*isValidChar)(uint16 ch))
    {
        // dummy body
        const auto a = file.Get(offset, 2, true);
        return isValidChar(*(uint16*) a.GetData());
    }
};
} // namespace GView::GenericPlugins::Droppper
