#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer::StringOperationsPlugins
{
void Reverse(TextEditor& editor)
{
    if (editor.Len() == 0)
        return;
    auto e = editor.Len() - 1;
    auto s = 0U;
    while (s < e)
    {
        std::swap(editor[s], editor[e]);
        s++;
        e--;
    }
}
void UpperCase(TextEditor& editor)
{
    for (auto index = 0U; index < editor.Len(); index++)
        if ((editor[index] >= 'a') && (editor[index] <= 'z'))
            editor[index] -= 32;
}
void LowerCase(TextEditor& editor)
{
    for (auto index = 0U; index < editor.Len(); index++)
        if ((editor[index] >= 'A') && (editor[index] <= 'Z'))
            editor[index] |= 0x20;
}
} // namespace GView::View::LexicalViewer::StringOperationsPlugins