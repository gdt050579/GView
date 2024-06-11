#include "js.hpp"
#include "ast.hpp"

#include <unordered_map>
#include <vector>
#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view HoistFunctions::GetName()
{
    return "Hoist Functions";
}
std::string_view HoistFunctions::GetDescription()
{
    return "Hoist functions.";
}
bool HoistFunctions::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class FunctionHoister : public AST::Plugin
{
    std::vector<std::unordered_map<std::u16string_view, AST::VarDecl*>> vars;

    std::stack<AST::FunDecl*> funStack;
    std::vector<AST::Block*> blocks;

  public:
    struct FunInfo {
        AST::Node* anchor = nullptr;
        size_t anchorLevel   = 0;

        FunInfo() = default;
    };

    std::unordered_map<AST::FunDecl*, FunInfo> funs;

    AST::Action OnEnterFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        funStack.push(node);
        funs[node] = {};

        return AST::Action::None;
    }

    AST::Action OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement)
    {
        vars[vars.size() - 1][node->name] = node;
        return AST::Action::None;
    }

    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
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

    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        funStack.pop();
        return AST::Action::None;
    }

    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.emplace_back();
        blocks.emplace_back(node);
        return AST::Action::None;
    }

    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement)
    {
        vars.pop_back();
        blocks.pop_back();
        return AST::Action::None;
    }

  private:
    std::pair<AST::VarDecl*, size_t> GetVar(std::u16string_view name)
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
};

GView::View::LexicalViewer::PluginAfterActionRequest HoistFunctions::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    FunctionHoister hoister;

    AST::PluginVisitor visitor(&hoister, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    size_t start = 0;

    for (auto& [fun, info] : hoister.funs) {
        size_t dest = 0;

        if (info.anchor == nullptr) {
            // Global scope
            dest = start;
        } else {
            dest = info.anchor->sourceStart + 1; // {
        }
        
        // Already defined in global scope
        if (dest > fun->sourceStart) {
            continue;
        }

        // The destination can overlap with the source
        std::u16string content = { ((std::u16string_view) data.editor).data() + fun->sourceStart, fun->sourceSize };

        data.editor.Insert(dest, content);
        data.editor.Delete(fun->sourceStart + fun->sourceSize, fun->sourceSize);

        if (info.anchor == nullptr) {
            start += fun->sourceSize;
        }
    }

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins