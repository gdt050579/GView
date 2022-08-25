#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{
// max 1G char15 chars = 2G memory
constexpr uint32 MAX_MEMORY_TO_ALLOCATE = 0x40000000;
char16 indexOperatorTempChar            = 0;
TextEditor::TextEditor()
{
    this->text      = nullptr;
    this->size      = 0;
    this->allocated = 0;
}
bool TextEditor::Grow(uint32 newSize)
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
        this->allocated = newSize;
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
} // namespace GView::View::LexicalViewer