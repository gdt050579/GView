#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer::StringOperationsPlugins
{
void Reverse(TextEditor& editor, uint32 start, uint32 end)
{
    if (end == 0)
        return;
    end--;
    while (start < end)
    {
        std::swap(editor[start], editor[end]);
        start++;
        end--;
    }
}

void UpperCase(TextEditor& editor, uint32 start, uint32 end)
{
    for (auto index = start; index < end; index++)
        if ((editor[index] >= 'a') && (editor[index] <= 'z'))
            editor[index] -= 32;
}

void LowerCase(TextEditor& editor, uint32 start, uint32 end)
{
    for (auto index = start; index < end; index++)
        if ((editor[index] >= 'A') && (editor[index] <= 'Z'))
            editor[index] |= 0x20;
}

void RemoveUnnecesaryWhiteSpaces(TextEditor& editor, uint32 start, uint32 end)
{
    auto len = editor.Len();
    auto pos = 0u;
    while (pos < len)
    {
        if ((editor[pos] == ' ') || (editor[pos] == '\t'))
        {
            // check to see if there are multiple ones
            auto next = pos;
            while ((next < len) && ((editor[next] == ' ') || (editor[next] == '\t')))
                next++;
            if (next - pos >= 2)
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

bool IsHex(char16 ch)
{
    return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
}

char16 HexCharToValue(char16 ch)
{
    if (ch >= '0' && ch <= '9')
        return (ch - '0');
    if (ch >= 'A' && ch <= 'F')
        return (ch + 10 - 'A');
    if (ch >= 'a' && ch <= 'f')
        return (ch + 10 - 'a');
    return 0;
}

void UnescapedCharacters(TextEditor& editor, uint32 start, uint32 end)
{
    editor.ReplaceAll("\\n", "\n");
    editor.ReplaceAll("\\r", "\r");
    editor.ReplaceAll("\\t", "\t");
    editor.ReplaceAll("\\'", "\'");
    editor.ReplaceAll("\\\"", "\"");
    editor.ReplaceAll("\\a", "\a");
    editor.ReplaceAll("\\b", "\b");
    editor.ReplaceAll("\\f", "\f");
    editor.ReplaceAll("\\v", "\v");
    editor.ReplaceAll("\\?", "\?");
    editor.ReplaceAll("\\\\", "\\");

    for (auto i = 0u; i < editor.Len(); i++)
    {
        if (editor[i] != '\\')
            continue;
        if (editor[i + 1] == 'x' && IsHex(editor[i + 2]) && IsHex(editor[i + 3]))
        {
            editor[i] = HexCharToValue(editor[i + 2]) * 0x10 + HexCharToValue(editor[i + 3]);
            editor.Delete(i + 1, 3);
            continue;
        }
        if (editor[i + 1] == 'u' && IsHex(editor[i + 2]) && IsHex(editor[i + 3]) && IsHex(editor[i + 4]) && IsHex(editor[i + 5]))
        {
            editor[i] = HexCharToValue(editor[i + 2]) * 0x1000 + HexCharToValue(editor[i + 3]) * 0x100 + HexCharToValue(editor[i + 4]) * 0x10 +
                        HexCharToValue(editor[i + 5]);
            editor.Delete(i + 1, 5);
            continue;
        }
    }
}

void EscapeNonAsciiCharacters(TextEditor& editor, uint32 start, uint32 end)
{
    AppCUI::Utils::NumericFormatter fmt;

    for (auto i = 0u; i < editor.Len(); i++) {
        if ((int) editor[i] <= 127)
            continue;

        auto code = fmt.ToHex(editor[i]);

        editor.Replace(i, 1, u"\\u");
        editor.Insert(i + 2, code);
    }
}
} // namespace GView::View::LexicalViewer::StringOperationsPlugins