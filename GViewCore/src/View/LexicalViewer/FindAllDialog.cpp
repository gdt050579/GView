#include "LexicalViewer.hpp"

namespace GView::View::LexicalViewer
{

using namespace AppCUI::Input;

constexpr int32 BTN_ID_OK     = 1;
constexpr int32 BTN_ID_CANCEL = 2;

FindAllDialog::FindAllDialog(uint64 hash, const std::vector<TokenObject>& tokens, const char16* txt)
    : Window("All apearences", "d:c,w:80,h:20", WindowFlags::ProcessReturn)
{
    LocalString<128> tmp;
    LocalUnicodeStringBuilder<512> content;
    this->selectedLineNo = 0;

    auto lst = Factory::ListView::Create(this, "l:1,t:0,r:1,b:3", { "n:Line,a:l,w:6", "n:Content,a:l,w:200" });
    // add all lines
    auto len      = static_cast<uint32>(tokens.size());
    auto lastLine = 0xFFFFFFFFU;
    for (auto idx = 0U; idx < len; idx++)
    {
        const auto& tok = tokens[idx];
        if (tok.hash != hash)
            continue;
        if (tok.lineNo == lastLine)
            continue;
        auto item = lst->AddItem(tmp.Format("%d", tok.lineNo));
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
        auto lastX = 0U;
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
            content.Add(tokens[start].GetText(txt));
            lastX = tokens[start].end;
            start++;
        }
        item.SetText(1, content);
        lastLine = tok.lineNo;
    }

    Factory::Button::Create(this, "&OK", "l:25,b:0,w:13", BTN_ID_OK);
    Factory::Button::Create(this, "&Cancel", "l:40,b:0,w:13", BTN_ID_CANCEL);
}

void FindAllDialog::Validate()
{
    selectedLineNo = 0;
    Exit(Dialogs::Result::Ok);
}

bool FindAllDialog::OnEvent(Reference<Control> control, Event eventType, int ID)
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