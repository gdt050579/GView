#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

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