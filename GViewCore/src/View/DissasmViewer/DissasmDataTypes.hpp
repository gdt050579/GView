#pragma once

#include "Internal.hpp"

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        struct LinePosition
        {
            uint32 line;
            uint32 offset;

            bool operator==(const LinePosition& other) const
            {
                return line == other.line && offset == other.offset;
            }

            bool operator>(const LinePosition& other) const
            {
                return line > other.line || line == other.line && offset > other.offset;
            }

            bool operator>=(const LinePosition& other) const
            {
                return line > other.line || line == other.line && offset >= other.offset;
            }

            bool operator<(const LinePosition& other) const
            {
                return line < other.line || line == other.line && offset < other.offset;
            }

            bool operator<=(const LinePosition& other) const
            {
                return line < other.line || line == other.line && offset <= other.offset;
            }
        };
    } // namespace DissasmViewer
} // namespace View
} // namespace GView