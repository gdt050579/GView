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
void RemoveUnnecesaryWhiteSpaces(TextEditor& editor)
{
    auto len = editor.Len();
    auto pos = 0;
    while (pos < len)
    {
        if ((editor[pos] == ' ') || (editor[pos] == '\t'))
        {
            // check to see if there are multiple ones
            auto next = pos;
            while ((next < len) && ((editor[next] == ' ') || (editor[next] == '\t')))
                next++;
            if (next-pos>=2)
            {
                editor.Replace(pos, next - pos, " ");
                len = editor.Len();                
            }
        }
        if ((editor[pos] == '\n') || (editor[pos] == '\r'))
        {
            // check to see if there are multiple ones
            auto next = pos;
            while ((next < len) && ((editor[next] == '\n') || (editor[next] == '\r')))
                next++;
            if (next - pos >= 2)
            {
                editor.Replace(pos, next - pos, "\n");
                len = editor.Len();
            }
        }
        pos++;
    }
}
} // namespace GView::View::LexicalViewer::StringOperationsPlugins