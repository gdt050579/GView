#pragma once

#include "GView.hpp"

namespace GView::GenericPlugins::Droppper
{
enum Result {
    NotFound, // -> nothing found
    Buffer,   // -> artefact found -> drop it as a buffer
    Unicode,  // -> artefact found -> drop it as unicode (skip 0)
    Ascii,    // -> artefact found -> drop it as ascii
};

class IDrop
{
  public:
    // virtual methods
    virtual const char* GetName()            = 0; // specific dropper mini-plugin name
    virtual const char* GetGroup()           = 0; // Archive type recognizer, Archive type recognizer, etc
    virtual const char* GetOutputExtension() = 0; // dropped file extension
    virtual bool ShouldGroupInOneFile()      = 0; // URLs, IPs, etc

    // prechachedBufferSize, // max 8
    virtual Result Check(uint64 offset, DataCache& file, unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint64& start, uint64& end) = 0;

    virtual uint32 GetPriority() = 0;

    // functii deja existente
    inline bool is_magic_u16(unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint16 magic)
    {
        if (prechachedBufferSize >= 2) {
            return *(uint16*) prechachedBuffer == magic;
        }
        return false;
    }

    inline bool is_magic_u32(unsigned char* prechachedBuffer, uint32 prechachedBufferSize, uint32 magic)
    {
        if (prechachedBufferSize >= 4) {
            return *(uint32*) prechachedBuffer == magic;
        }
        return false;
    }

    inline bool is_buffer(uint64 offset, DataCache& file, unsigned char* buffer, uint32 bufferSize)
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

    inline uint64 parse_ascii(uint64 offset, DataCache& file, bool (*isValidChar)(char ch))
    {
        return 0;
    }

    inline uint64 parse_unicode(uint64 offset, DataCache& file, bool (*isValidChar)(char ch))
    {
        return 0;
    }
};
} // namespace GView::GenericPlugins::Droppper
