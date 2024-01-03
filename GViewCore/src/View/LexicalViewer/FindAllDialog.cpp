#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK             = 1;
constexpr int32 BTN_ID_CANCEL         = 2;
constexpr uint32 INVALID_TOKEN_NUMBER = 0xFFFFFFFF;

FindAllDialog::FindAllDialog(const TokenObject& currentToken, const std::vector<TokenObject>& tokens, const char16* txt)
    : Window("All apearences", "d:c,w:80,h:20", WindowFlags::ProcessReturn)
{
    LocalString<128> tmp;
    LocalUnicodeStringBuilder<512> content;
    this->selectedTokenIndex = INVALID_TOKEN_NUMBER;

    lst = Factory::ListView::Create(this, "l:1,t:0,r:1,b:3", { "n:Line,a:l,w:6", "n:Content,a:l,w:200" }, ListViewFlags::HideSearchBar);
    // add all lines
    auto len      = static_cast<uint32>(tokens.size());
    auto lastLine = 0xFFFFFFFFU;
    auto ctokSize = static_cast<uint32>(currentToken.GetText(txt).size());
    uint32 indexes[64];
    uint32 indexesCount;

    for (auto idx = 0U; idx < len; idx++)
    {
        const auto& tok = tokens[idx];
        if (tok.hash != currentToken.hash)
            continue;
        if (tok.lineNo == lastLine)
            continue;
        auto item = lst->AddItem(tmp.Format("%d", tok.lineNo));
        item.SetData(idx);
        auto start = idx;
        while ((start > 0) && (tokens[start].lineNo == tok.lineNo))
            start--;
        if (tokens[start].lineNo != tok.lineNo)
            start++;
        auto end = idx;
        while ((end > 0) && (tokens[end].lineNo == tok.lineNo))
            end++;
        end--;
        // between start and end a new line is found
        content.Clear();
        auto lastX   = 0U;
        indexesCount = 0;
        while (start < end)
        {
            if ((tokens[start].start > lastX) && (lastX > 0))
            {
                auto st = tokens[start].start;
                while (lastX < st)
                {
                    content.AddChar(' ');
                    lastX++;
                }
            }
            if ((tokens[start].hash == currentToken.hash) && (indexesCount < 64))
            {
                indexes[indexesCount++] = content.Len();
            }

            content.Add(tokens[start].GetText(txt));
            lastX = tokens[start].end;
            start++;
        }
        item.SetText(1, content);
        for (auto idx = 0u; idx < indexesCount; idx++)
        {
            item.HighlightText(1, indexes[idx], ctokSize);
        }
        lastLine = tok.lineNo;
    }

    Factory::Button::Create(this, "&OK", "l:25,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:40,b:0,w:13", BTN_ID_CANCEL);
}

void FindAllDialog::Validate()
{
    selectedTokenIndex = static_cast<uint32>(lst->GetCurrentItem().GetData(INVALID_TOKEN_NUMBER));
    if (selectedTokenIndex == INVALID_TOKEN_NUMBER)
        return;
    Exit(Dialogs::Result::Ok);
}

bool FindAllDialog::OnEvent(Reference<Control>, Event eventType, int ID)
{
    switch (eventType)
    {
    case Event::ButtonClicked:
        switch (ID)
        {
        case BTN_ID_CANCEL:
            Exit(Dialogs::Result::Cancel);
            return true;
        case BTN_ID_OK:
            Validate();
            return true;
        }
        break;
    case Event::ListViewItemPressed:
        Validate();
        return true;
    case Event::WindowAccept:
        Validate();
        return true;
    case Event::WindowClose:
        Exit(Dialogs::Result::Cancel);
        return true;
    }

    return false;
}
} // namespace GView::View::LexicalViewer
