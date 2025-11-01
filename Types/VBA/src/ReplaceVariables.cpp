#include "vba.hpp"

namespace GView::Type::VBA::Plugins
{

using namespace GView::View::LexicalViewer;

std::string_view ReplaceVariables::GetName()
{
    return "Replace Variables";
}

std::string_view ReplaceVariables::GetDescription()
{
    return "Replace variables with their values";
}

bool ReplaceVariables::CanBeAppliedOn(const PluginData& data)
{
    for (uint32 i = data.startIndex; i < data.endIndex; i++) {
        auto token = data.tokens[i];
        if (token.GetTypeID(TokenType::None) == TokenType::VariableRef)
            return true;
    }
    return false;
}

struct VariableData {
    uint32 tokenIndex;
    std::u16string value;
};

uint32 LookForClosestValue(uint32 index, std::map<uint32, uint32>& spaceForSearch)
{
    uint32 lastInitialization = spaceForSearch.begin()->first;
    for (const auto& [initialization, value] : spaceForSearch) {
        if (index > initialization) {
            lastInitialization = initialization;
        } else {
            break;
        }
    }
    return spaceForSearch[lastInitialization];
}

PluginAfterActionRequest ReplaceVariables::Execute(PluginData& data, Reference<Window> parent)
{
    std::unordered_map<std::u16string, VariableData> variablesToReplace;
    std::map<uint32, std::pair<uint32, std::u16string>> changes;

    for (uint32 i = data.startIndex; i <= data.endIndex; i++) {
        auto token = data.tokens[i];
        if (!token.IsValid())
            continue;
        if (token.GetTypeID(TokenType::None) != TokenType::VariableRef)
            continue;
        variablesToReplace[std::u16string(token.GetText())] = { i, {} };
    }

    for (auto token : data.tokens) {
        if (!token.IsValid())
            continue;
        if (token.GetTypeID(TokenType::None) != TokenType::Variable)
            continue;
        auto valueToken = token.Next().Next();
        if (!valueToken.IsValid())
            continue;

        const std::u16string variableName = std::u16string(token.GetText());

        auto variableIterator = variablesToReplace.find(variableName);
        if (variableIterator != variablesToReplace.end()) {
            const std::u16string variableValue           = std::u16string(valueToken.GetText());
            variableIterator->second.value               = variableValue;
            auto toReplaceToken                           = data.tokens[variableIterator->second.tokenIndex];
            changes[toReplaceToken.GetTokenStartOffset().value()] = { variableIterator->second.tokenIndex, variableValue };
        }

        if (variablesToReplace.empty())
            break;
    }

    int32 difference = 0;
    for (const auto& change : changes) {
        auto tokenToReplace = data.tokens[change.second.first];
        auto startOffset    = tokenToReplace.GetTokenStartOffset();
        auto endOffset      = tokenToReplace.GetTokenEndOffset();
        if (!startOffset.has_value() || !endOffset.has_value())
            return GView::View::LexicalViewer::PluginAfterActionRequest::None;
        const auto size          = endOffset.value() - startOffset.value();
        const uint32 offsetToUse = startOffset.value() + difference;
        difference += (int32) change.second.second.size() - (int32) tokenToReplace.GetText().size();
        data.editor.Replace(offsetToUse, size, change.second.second);
    }

    return PluginAfterActionRequest::Rescan;
}

} // namespace GView::Type::VBA::Plugins