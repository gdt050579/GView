#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{
const uint8 string_lowercase_table[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,
    26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91,  92,  93,  94,  95,  96,  97,  98,  99,  100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
    182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
    234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

#define GROW_TO(newSize)                                                                                                                   \
    if (((newSize) > allocated) && (this->Grow(newSize) == false))                                                                         \
        return false;

#define COPY_ASCII(offset, source, len)                                                                                                    \
    {                                                                                                                                      \
        const auto* start = (source);                                                                                                      \
        const auto* end   = start + (len);                                                                                                 \
        auto* p           = this->text + (offset);                                                                                         \
        for (; start < end; start++, p++)                                                                                                  \
        {                                                                                                                                  \
            (*p) = (*start);                                                                                                               \
        }                                                                                                                                  \
    }

#define COPY_UNICODE16(offset, source, len)                                                                                                \
    {                                                                                                                                      \
        memcpy(this->text + offset, (source), (len) * sizeof(char16));                                                                     \
    }
// max 1G char15 chars = 2G memory
constexpr uint32 MAX_MEMORY_TO_ALLOCATE = 0x40000000;
char16 indexOperatorTempChar            = 0;
TextEditor::TextEditor()
{
    this->text      = nullptr;
    this->size      = 0;
    this->allocated = 0;
}
bool TextEditor::Grow(size_t newSize)
{
    if (newSize <= allocated)
        return true;
    newSize = (newSize | 0xFF) + 1; // 256 bytes blocks
    if (newSize > MAX_MEMORY_TO_ALLOCATE)
        return false;
    try
    {
        auto* temp = new char16[newSize];
        if (this->text)
        {
            memcpy(temp, this->text, this->size * sizeof(char16));
            delete[] this->text;
        }
        this->text      = temp;
        this->allocated = static_cast<uint32>(newSize);
        return true;
    }
    catch (...)
    {
        return false;
    }
}
char16& TextEditor::operator[](uint32 index)
{
    if (index < size)
        return text[size];
    else
    {
        indexOperatorTempChar = 0;
        return indexOperatorTempChar;
    };
}

std::optional<uint32> TextEditor::Find(uint32 startOffset, std::string_view textToSearch, bool ignoreCase)
{
    if ((textToSearch.empty()) || (this->size == 0))
        return std::nullopt;
    if ((startOffset + textToSearch.size()) > this->size)
        return std::nullopt;

    const auto* p      = this->text + startOffset;
    const auto* e      = this->text + size + 1 - textToSearch.size();
    const uint8* txt   = reinterpret_cast<const uint8*>(textToSearch.data());
    const uint8* txt_e = txt + textToSearch.size();
    auto firstChar     = *txt;
    if (ignoreCase)
    {
        firstChar = string_lowercase_table[firstChar];
        while (p < e)
        {
            if (string_lowercase_table[*p] == firstChar)
            {
                const auto* s = p;
                const auto* t = txt;
                for (; (t < txt_e); t++, s++)
                {
                    if (string_lowercase_table[*t] != string_lowercase_table[*s])
                        break;
                }
                if (t == txt_e)
                    return static_cast<uint32>(p - this->text);
            }
            p++;
        }
    }
    else
    {
        while (p < e)
        {
            if ((*p) == firstChar)
            {
                const auto* s = p;
                const auto* t = txt;
                for (; (t < txt_e); t++, s++)
                {
                    if ((*t) != (*s))
                        break;
                }
                if (t == txt_e)
                    return static_cast<uint32>(p - this->text);
            }
            p++;
        }
    }
    // nothing found
    return std::nullopt;
}
bool TextEditor::Insert(uint32 offset, std::string_view newText)
{
    if (newText.empty())
        return true;
    if (offset > size)
        return false;
    if (offset == size)
        return Add(newText);
    GROW_TO(size + newText.size());
    memmove(this->text + offset + newText.size(), this->text + offset, (this->size - offset) * sizeof(char16));
    COPY_ASCII(offset, newText.data(), newText.size());
    size += static_cast<uint32>(newText.size());
    return true;
}
bool TextEditor::Insert(uint32 offset, std::u16string_view newText)
{
    if (newText.empty())
        return true;
    if (offset > size)
        return false;
    if (offset == size)
        return Add(newText);
    GROW_TO(size + newText.size());
    memmove(this->text + offset + newText.size(), this->text + offset, (this->size - offset) * sizeof(char16));
    COPY_UNICODE16(offset, newText.data(), newText.size());
    size += static_cast<uint32>(newText.size());
    return true;
}
bool TextEditor::InsertChar(uint32 offset, char16 ch)
{
    GROW_TO(size + 1);
    if (offset > size)
        return false;
    if (offset < size)
    {
        memmove(this->text + offset + 1, this->text + offset, (size - offset) * sizeof(char16));
    }
    text[offset] = ch;
    size++;
    return true;
}
bool TextEditor::Replace(uint32 offset, uint32 count, std::string_view newText)
{
    if (offset > size)
        return false;
    if (offset + count >= size)
    {
        this->size = offset;
        return Add(newText);
    }
    if (newText.size() > (size_t) count)
    {
        GROW_TO((size_t) size + newText.size() - (size_t) count);
        memmove(this->text + offset + newText.size(), this->text + offset + count, (this->size - (offset + count)) * sizeof(char16));
        this->size += (uint32) (newText.size() - (size_t) count);
    }
    else if (newText.size() < (size_t) count)
    {
        memmove(this->text + offset + newText.size(), this->text + offset + count, (this->size - (offset + count)) * sizeof(char16));
        this->size -= (uint32) ((size_t) count - newText.size());
    }
    COPY_ASCII(offset, newText.data(), newText.size());
    return true;
}
bool TextEditor::Replace(uint32 offset, uint32 count, std::u16string_view newText)
{
    if (offset > size)
        return false;
    if (offset + count >= size)
    {
        this->size = offset;
        return Add(newText);
    }
    if (newText.size() > (size_t) count)
    {
        GROW_TO((size_t) size + newText.size() - (size_t) count);
        memmove(this->text + offset + newText.size(), this->text + offset + count, (this->size - (offset + count)) * sizeof(char16));
        this->size += (uint32) (newText.size() - (size_t) count);
    }
    else if (newText.size() < (size_t) count)
    {
        memmove(this->text + offset + newText.size(), this->text + offset + count, (this->size - (offset + count)) * sizeof(char16));
        this->size -= (uint32) ((size_t) count - newText.size());
    }
    COPY_UNICODE16(offset, newText.data(), newText.size());
    return true;
}
bool TextEditor::ReplaceAll(std::string_view textToSearch, std::string_view textToReplaceWith, bool ignoreCase)
{
    if ((textToSearch.empty()) || (this->size == 0))
        return false;

    auto pos = 0;
    auto len = static_cast<uint32>(textToSearch.size());

    do
    {
        auto res = Find(pos, textToSearch, ignoreCase);
        if (!res.has_value())
            break;
        if (Replace(res.value(), len, textToReplaceWith) == false)
            return false;
        pos += len;
    } while (true);
    return true;
}
bool TextEditor::DeleteChar(uint32 offset)
{
    if (offset >= size)
        return false;
    if (offset + 1 < size)
    {
        memmove(this->text + offset, this->text + offset + 1, (this->size - (offset + 1)) * sizeof(char16));
    }
    size--;
    return true;
}
bool TextEditor::Delete(uint32 offset, uint32 charactersCount)
{
    if (offset > size)
        return false;
    if ((offset + charactersCount) >= size)
    {
        // last characters to delete
        size = offset;
        return true;
    }
    memmove(this->text + offset, this->text + offset + charactersCount, (this->size - (offset + charactersCount)) * sizeof(char16));
    size -= charactersCount;
    return true;
}
bool TextEditor::Add(std::string_view newText)
{
    GROW_TO(newText.size() + size);
    COPY_ASCII(size, newText.data(), newText.size());
    size += static_cast<uint32>(newText.size());
    return true;
}
bool TextEditor::Add(std::u16string_view newText)
{
    GROW_TO(newText.size() + size);
    COPY_UNICODE16(size, newText.data(), newText.size());
    size += static_cast<uint32>(newText.size());
    return true;
}
bool TextEditor::Set(std::string_view newText)
{
    GROW_TO(newText.size());
    COPY_ASCII(0, newText.data(), newText.size());
    this->size = static_cast<uint32>(newText.size());
    return true;
}
bool TextEditor::Set(std::u16string_view newText)
{
    GROW_TO(newText.size());
    COPY_UNICODE16(0, newText.data(), newText.size());
    this->size = static_cast<uint32>(newText.size());
    return true;
}
bool TextEditor::Resize(uint32 newSize, char16 fillChar)
{
    if (newSize == size)
        return true;
    if (newSize < size)
    {
        size = newSize;
        return true;
    }
    GROW_TO(newSize);
    auto* p = this->text + size;
    auto* e = this->text + newSize;
    for (; p < e; p++)
        (*p) = fillChar;
    size = newSize;
    return true;
}
bool TextEditor::Reserve(uint32 newSize)
{
    GROW_TO(newSize);
    return true;
}
} // namespace GView::View::LexicalViewer