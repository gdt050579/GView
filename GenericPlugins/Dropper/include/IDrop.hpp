#pragma once

#include "Constants.hpp"

using namespace GView::Utils;

namespace GView::GenericPlugins::Droppper
{
class IDrop
{
  public:
    // virtual methods
    virtual const std::string_view GetName() const            = 0; // specific dropper mini-plugin name
    virtual Category GetCategory() const                      = 0; // archive type recognizer, executables type, etc
    virtual Subcategory GetSubcategory() const                = 0; // specific subgroup from each category
    virtual const std::string_view GetOutputExtension() const = 0; // dropped file extension
    virtual Priority GetPriority() const                      = 0; // get plugin priority
    virtual bool ShouldGroupInOneFile() const                 = 0; // URLs, IPs, etc

    // prechachedBufferSize -> max 8
    virtual bool Check(uint64 offset, DataCache& file, BufferView precachedBuffer, Finding& finding) = 0;

    // helpers
    inline bool IsMagicU16(BufferView precachedBuffer, uint16 magic) const
    {
        if (precachedBuffer.GetLength() >= 2) {
            return *reinterpret_cast<const uint16*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline bool IsMagicU32(BufferView precachedBuffer, uint32 magic) const
    {
        if (precachedBuffer.GetLength() >= 4) {
            return *reinterpret_cast<const uint32*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline bool IsMagicU64(BufferView precachedBuffer, uint64 magic) const
    {
        if (precachedBuffer.GetLength() >= 8) {
            return *reinterpret_cast<const uint64*>(precachedBuffer.GetData()) == magic;
        }
        return false;
    }

    inline static bool IsAsciiPrintable(char c)
    {
        return 0x20 <= c && c <= 0x7e;
    }
};
} // namespace GView::GenericPlugins::Droppper
