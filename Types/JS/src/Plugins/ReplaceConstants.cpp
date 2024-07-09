#include "js.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view ReplaceConstants::GetName()
{
    return "Replace constants";
}
std::string_view ReplaceConstants::GetDescription()
{
    return "Replace variables with their string value";
}
bool ReplaceConstants::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{

    std::map < std::u16string_view, std::map<uint32, uint32> /* Key - last initializaton / modification, value->ValueTokenPosition*/> variables;
    for (auto index = data.startIndex; index < data.endIndex; index++)
    {
        if ((data.tokens[index].GetTypeID(TokenType::None) == TokenType::Word) &&
            (data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_Assignment ||
             data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_PlusAssignment) &&
            (data.tokens[index + 2].GetTypeID(TokenType::None) == TokenType::String))
        {
            const auto key = data.tokens[index].GetText();
            if (variables.contains(key))
            {
                variables[key][index] = index + 2;
            }
            else
            {
                variables[key] = { { index, index + 2 } };
            }
        }

		if (((data.tokens[index].GetTypeID(TokenType::None) == TokenType::Word) &&
            (data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_Plus)) ||
            ((data.tokens[index].GetTypeID(TokenType::None) == TokenType::Word) &&
             (data.tokens[index - 1].GetTypeID(TokenType::None) == TokenType::Operator_Plus)))
        {
            const auto key = data.tokens[index].GetText();
            if (variables.contains(key))
            {
                return true;
            }
		}
    }
    return false;
}

uint32 LookForClosestValue(uint32 index, std::map<uint32, uint32>& spaceForSearch)
{
    uint32 lastInitialization = spaceForSearch.begin()->first;
    for (const auto& [initialization, value] : spaceForSearch)
    {
        if (index > initialization)
        {
            lastInitialization = initialization;
		}
        else
        {
            break;
		}
	}
    return spaceForSearch[lastInitialization];
}

GView::View::LexicalViewer::PluginAfterActionRequest ReplaceConstants::Execute(GView::View::LexicalViewer::PluginData& data)
{

    std::map<std::u16string_view, std::map<uint32, uint32> /* Key - last initializaton / modification, value->ValueTokenPosition*/> variables;
	for (auto index = data.startIndex; index < data.endIndex; index++)
    {
        if ((data.tokens[index].GetTypeID(TokenType::None) == TokenType::Word) &&
            (data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_Assignment ||
             data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_PlusAssignment) &&
            (data.tokens[index + 2].GetTypeID(TokenType::None) == TokenType::String))
        {
            const auto key = data.tokens[index].GetText();
            if (variables.contains(key))
            {
                variables[key][index] = index + 2;
            }
            else
            {
                variables[key] = { {index, index + 2} };
            }
        }
    }

	int32 index = (int32) data.endIndex - 1;
	while (index >= (int32) data.startIndex)
    {
        if (((data.tokens[index].GetTypeID(TokenType::None) == TokenType::Word) &&
             (data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_Plus)) ||
            ((data.tokens[index].GetTypeID(TokenType::None) == TokenType::Word) &&
             (data.tokens[index - 1].GetTypeID(TokenType::None) == TokenType::Operator_Plus)))
        {
            const auto key = data.tokens[index].GetText();
            if (variables.contains(key))
            {
                auto startOffset = data.tokens[index].GetTokenStartOffset();
                auto endOffset   = data.tokens[index].GetTokenEndOffset();
                if (!startOffset.has_value() || !endOffset.has_value())
                    return GView::View::LexicalViewer::PluginAfterActionRequest::None;
                auto size          = endOffset.value() - startOffset.value();
                auto valueTokenId  = LookForClosestValue(index, variables[key]);
                auto variableValue = data.tokens[valueTokenId].GetText();
                data.editor.Replace(startOffset.value(), size, variableValue);
            }
        }
        index--;
    }

    return GView::View::LexicalViewer::PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins