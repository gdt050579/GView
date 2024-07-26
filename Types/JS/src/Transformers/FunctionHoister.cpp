#include "Transformers/FunctionHoister.hpp"

namespace GView::Type::JS::Transformer
{
    AST::Action FunctionHoister::OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        funStack.push(node);
        funs[node] = {};

        return AST::Action::None;
    }

    AST::Action FunctionHoister::OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
    {
        vars[vars.size() - 1][node->name] = node;
        return AST::Action::None;
    }

    AST::Action FunctionHoister::OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
    {
        auto info = GetVar(node->name);

        if (info.first == nullptr || funStack.empty()) {
            return AST::Action::None;
        }

        auto& fun = funs[funStack.top()];

        if (fun.anchor == nullptr || info.second < fun.anchorLevel || blocks[info.second]->sourceStart < fun.anchor->sourceStart) {
            fun.anchor      = blocks[info.second];
            fun.anchorLevel = info.second;
        }

        return AST::Action::None;
    }

    AST::Action FunctionHoister::OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        funStack.pop();
        return AST::Action::None;
    }

    AST::Action FunctionHoister::OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.emplace_back();
        blocks.emplace_back(node);
        return AST::Action::None;
    }

    AST::Action FunctionHoister::OnExitBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.pop_back();
        blocks.pop_back();
        return AST::Action::None;
    }

    std::pair<AST::VarDecl*, size_t> FunctionHoister::GetVar(std::u16string_view name)
    {
        size_t level = vars.size();
        for (auto it = vars.rbegin(); it != vars.rend(); ++it) {
            if (it->find(name) != it->end()) {
                return { (*it)[name], level };
            }

            --level;
        }

        return { nullptr, 0 };
    }
}