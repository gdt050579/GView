#include "pe.hpp"

using namespace GView::Type::PE;

bool X86_X64_ColorBuffer::GetColorForBuffer(uint64_t offset, BufferView buf, GView::View::BufferViewer::BufferColor& result)
{
    auto* p = buf.begin();
    switch (*p)
    {
    case 0xFF:
        if (buf.GetLength() >= 6)
        {
            if (p[1] == 0x15)
            {
                // possible call to API
                auto addr = *(uint32_t*) (p + 2);
                if ((addr >= this->memStartOffset) && (addr <= this->memEndOffset))
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = ColorPair{ Color::White, Color::Silver };
                    return true;
                }
            }
            else if (p[1] == 0x25)
            {
                // possible jump to API
                auto addr = *(uint32_t*) (p + 2);
                if ((addr >= this->memStartOffset) && (addr <= this->memEndOffset))
                {
                    result.start = offset;
                    result.end   = offset + 5;
                    result.color = ColorPair{ Color::Yellow, Color::DarkRed };
                    return true;
                }
            }
            return false;
        }
        return false;
    case 0xCC:
        // INT 3
        result.start = result.end = offset;
        result.color              = ColorPair{ Color::Gray, Color::DarkBlue };
        return true;
    case 0x55:
        if (buf.GetLength() >= 3)
        {
            // possible `push EBP` followed by MOV ebp, sep
            if ((*(uint16_t*) (p + 1)) == 0xEC8B)
            {
                result.start = offset;
                result.end   = offset + 2;
                result.color = ColorPair{ Color::Yellow, Color::Olive };
                return true;
            }
        }
        return false;
    case 0x8B:
        if (buf.GetLength() >= 4)
        {
            // possible `MOV esp, EBP` followed by `POP ebp` and `RET`
            if (((*(uint16_t*) (p + 1)) == 0x5DE5) && (p[3] == 0xC3))
            {
                result.start = offset;
                result.end   = offset + 3;
                result.color = ColorPair{ Color::Black, Color::Olive };
                return true;
            }
        }
        return false;
    }

    // unknwon
    return false;
}