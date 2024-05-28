#include <stack>
#include <vector>
#include <unordered_map>

#include "js.hpp"

namespace GView::Type::JS::Plugins
{
    using namespace GView::View::LexicalViewer;

    std::string_view ConstPropagation::GetName()
    {
        return "Constant Propagation";
    }
    std::string_view ConstPropagation::GetDescription()
    {
        return "Propagate string constants.";
    }
    bool ConstPropagation::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
    {
        for (auto index = data.startIndex; index < data.endIndex; index++)
        {
            
            // var word = "string";
            if (index + 4 < data.endIndex &&
                (data.tokens[index].GetTypeID(TokenType::None) == TokenType::DataType_Var) &&
                (data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Word) &&
                (data.tokens[index + 2].GetTypeID(TokenType::None) == TokenType::Operator_Assignment) &&
                (data.tokens[index + 3].GetTypeID(TokenType::None) == TokenType::String) &&
                (data.tokens[index + 4].GetTypeID(TokenType::None) == TokenType::Semicolumn))
            {
                return true;
            }
        }
        return false;
    }
    GView::View::LexicalViewer::PluginAfterActionRequest ConstPropagation::Execute(GView::View::LexicalViewer::PluginData& data)
    {
        struct VarInfo
        {
            std::u16string_view value{};
            bool modifiedInIf = false; // Whether or not this variable was modified in an 'if' block
        };

        // TODO: ustring_view on Unix?
        std::vector<std::unordered_map<std::u16string_view, VarInfo>> env;

        #define CONSUME(type)                                                                                      \
                if (index + 1 >= endIndex || data.tokens[index + 1].GetTypeID(TokenType::None) != TokenType::type) \
                {                                                                                                  \
                    continue;                                                                                      \
                }                                                                                                  \
                else                                                                                               \
                {                                                                                                  \
                    ++index;                                                                                       \
                }

        env.emplace_back(); // Global scope

        auto startIndex = (int32) data.startIndex;
        auto endIndex   = (int32) data.endIndex;

        // Since we are replacing tokens, the token offsets will very likely change,
        // so keep track of that by using an offset
        int32 tokenOffset = 0;

        std::stack<bool> blocks; // true -> this is an 'if' block, false otherwise

        // If a variable is modified in an 'if' block, we can't know
        // the true value because we don't know if the brach will be executed.
        // Therefore, the variable will be removed from the env in this case.
        uint32 ifDepth = 0;

        // Will the next block be an if block?
        bool ifComingUp = false;

        for (auto index = startIndex; index < endIndex; ++index)
        {
            auto token = data.tokens[index];
            auto type  = token.GetTypeID(TokenType::None);

            switch (type)
            {
            case TokenType::DataType_Var:
            {
                // var word = "string";
                CONSUME(Word);

                auto var = data.tokens[index].GetText();

                CONSUME(Operator_Assignment);
                CONSUME(String);

                auto str = data.tokens[index].GetText();

                CONSUME(Semicolumn);

                env[env.size() - 1][var].value = str;
                break;
            }
            case TokenType::Keyword_If:
            case TokenType::Keyword_Else:
            {
                ++ifDepth;
                ifComingUp = true;
                break;
            }
            case TokenType::BlockOpen:
            {
                blocks.push(ifComingUp);
                ifComingUp = false;
                env.emplace_back(); // New scope
                break;
            }
            case TokenType::BlockClose:
            {
                if (blocks.top())
                {
                    // This was an 'if' block
                    --ifDepth;

                    for (auto& block : env)
                    {
                        for (auto& var : block)
                        {
                            if (var.second.modifiedInIf)
                            {
                                var.second.value = {};
                            }
                        }
                    }
                }
                blocks.pop();

                env.pop_back();
                break;
            }
            case TokenType::Word:
            {
                auto str = token.GetText();

                // Variable resolution: from inner blocks to outer blocks
                auto envIndex = (int32) (env.size() - 1);

                while (envIndex >= 0)
                {
                    auto& block = env[envIndex];

                    // Resolved
                    if (block.find(str) != block.end())
                    {
                        if (index + 2 < endIndex && data.tokens[index + 1].GetTypeID(TokenType::None) == TokenType::Operator_Assignment)
                        {
                            // word = "string"; -> the variable was modified, so change the value in the env
                            if (data.tokens[index + 2].GetTypeID(TokenType::None) == TokenType::String &&
                                data.tokens[index + 3].GetTypeID(TokenType::None) == TokenType::Semicolumn)
                            {
                                block[str].value = data.tokens[index + 2].GetText();

                                // If we are in an 'if' block, we can't rely on the value of the variable,
                                // so we change it to the empty string view after we exit the 'if' block
                                block[str].modifiedInIf = (ifDepth > 0);
                            }
                            else
                            {
                                // word = something -> the variable was modified with an unknown value,
                                // so we can't propagate further
                                block[str].value = {};
                            }
                        }
                        else
                        {
                            auto replacement = block[str]; // The value of the variable

                            if (replacement.value.size() == 0)
                            {
                                // Empty string view -> the variable was last modified inside an 'if'
                                // block -> we can't rely on the value -> no propagation
                                break;
                            }

                            // Just word -> the variable is being read, so propagate the value from the env
                            auto start = token.GetTokenStartOffset().value() + tokenOffset;
                            auto end   = token.GetTokenEndOffset().value() + tokenOffset;

                            // Adjust the token offset
                            // If we replace this token with a longer one, the offset will grow accordingly
                            // If we replace it with a shorter one, the offset will shrink
                            tokenOffset += ((int32) replacement.value.size()) - (end - start);

                            data.editor.Replace(start, end - start, replacement.value);
                        }
                        break;
                    }

                    --envIndex;
                }
            }
            }
        }

        #undef CONSUME

        return GView::View::LexicalViewer::PluginAfterActionRequest::Rescan;
    }
} // namespace GView::Type::JS::Plugins