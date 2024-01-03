#include "js.hpp"

namespace GView::Type::JS::Plugins
{
    using namespace GView::View::LexicalViewer;

    std::string_view AddStrings::GetName()
    {
        return "Add Strings";
    }
    std::string_view AddStrings::GetDescription()
    {
        return "Concatenate multiple strings that are beeing added.";
    }
    bool AddStrings::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
    {
        for (auto index = data.startIndex; index < data.endIndex; index++)
        {
            if ((data.tokens[index].GetTypeID(TokenType::None) == TokenType::String) &&
                (data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_Plus) &&
                (data.tokens[index + 2].GetTypeID(TokenType::None) == TokenType::String))
            {
                return true;
            }
        }
        return false;
    }
    GView::View::LexicalViewer::PluginAfterActionRequest AddStrings::Execute(GView::View::LexicalViewer::PluginData& data)
    {
        int32 index = (int32) data.endIndex - 1;
        LocalUnicodeStringBuilder<256> temp; 
        while (index >= (int32) data.startIndex)
        {
            Token endToken = data.tokens[index];
            if (endToken.GetTypeID(TokenType::None) == TokenType::String &&
                endToken.Precedent().GetTypeID(TokenType::None) == TokenType::Operator_Plus &&
                endToken.Precedent().Precedent().GetTypeID(TokenType::None) == TokenType::String)
            {
                Token start = endToken.Precedent().Precedent();
                while (start.Precedent().GetTypeID(TokenType::None) == TokenType::Operator_Plus &&
                       start.Precedent().Precedent().GetTypeID(TokenType::None) == TokenType::String)
                {
                    start = start.Precedent().Precedent();
                }
                temp.Clear();
                temp.AddChar('"');
                index = start.GetIndex();
                auto startOffset = start.GetTokenStartOffset();
                auto endOffset   = endToken.GetTokenEndOffset();
                if (!startOffset.has_value() || !endOffset.has_value())
                    return GView::View::LexicalViewer::PluginAfterActionRequest::None;
                auto size = endOffset.value() - startOffset.value();
                while (start.GetIndex() <= endToken.GetIndex())
                {
                    auto txt = start.GetText();
                    auto value = txt.substr(1, txt.length() - 2);
                    if(value.find_first_of('"') == std::u16string_view::npos)
                    {
                        temp.Add(value);
                    }
                    else
                    {
                        for (auto ch : value)
                        {
                            if (ch == '"')
                                temp.AddChar('\\');
                            temp.AddChar(ch);
                        }
                    }
                    //temp.Add(txt.substr(1, txt.length() - 2));
                    start = start.Next().Next();
                }
                temp.AddChar('"');
                data.editor.Replace(startOffset.value(), size, temp.ToStringView());
            }
            index--;
        }

        return GView::View::LexicalViewer::PluginAfterActionRequest::Rescan;
    }
} // namespace GView::Type::JS::Plugins