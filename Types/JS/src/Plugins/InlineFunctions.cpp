#include "js.hpp"
#include "ast.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view InlineFunctions::GetName()
{
    return "Inline Functions";
}
std::string_view InlineFunctions::GetDescription()
{
    return "Inline functions.";
}
bool InlineFunctions::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class DynamicPropagator : public AST::Plugin
{
    std::unordered_map<std::u16string_view, AST::Expr*> map;

  public:
    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement)
    {
        if (map.find(node->name) != map.end()) {
            replacement = map[node->name]->Clone();

            return AST::Action::Replace;
        }

        return AST::Action::None;
    }

    void AddVar(std::u16string_view name, AST::Expr* expr)
    {
        map[name] = expr;
    }
};

class FunctionInliner : public AST::Plugin
{
    struct FunInfo {
        AST::Expr* returnValue = nullptr;

        std::vector<AST::Identifier*> params;
    };

    std::vector<std::unordered_map<std::u16string_view, FunInfo>> funs;

  public:
    AST::Action OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        if (node->block && node->block->decls.size() == 1 && node->block->decls[0]->GetDeclType() == AST::DeclType::Stmt &&
            ((AST::Stmt*) node->block->decls[0])->GetStmtType() == AST::StmtType::Return) {
            auto ret = (AST::ReturnStmt*) node->block->decls[0];

            FunInfo info;
            info.params      = node->params;
            info.returnValue = ret->expr;

            funs[funs.size() - 1][node->name] = info;
        }

        return AST::Action::None;
    }

    AST::Action OnEnterCall(AST::Call* node, AST::Expr*& replacement)
    {
        if (node->callee->GetExprType() == AST::ExprType::Identifier) {
            auto id = (AST::Identifier*) node->callee;

            auto fun = GetFun(id->name);

            if (fun) {
                auto expr = fun->returnValue->Clone();

                DynamicPropagator propagator;

                if (fun->params.size() != node->args.size()) {
                    return AST::Action::None;
                }

                for (unsigned i = 0; i < fun->params.size(); ++i) {
                    propagator.AddVar(fun->params[i]->name, node->args[i]);
                }

                AST::PluginVisitor visitor(&propagator, nullptr);

                // Place the expr inside a block,
                // so that the block can do any required replacements.
                auto block = new AST::Block();
                auto stmt  = new AST::ExprStmt(expr);
                block->decls.push_back(stmt);

                AST::Node* rep;
                block->Accept(visitor, rep);

                for (unsigned i = 0; i < fun->params.size(); ++i) {
                    delete node->args[i];
                    node->args[i] = nullptr;
                }

                node->args.clear();

                expr       = stmt->expr;
                stmt->expr = nullptr;

                delete block;

                replacement = expr;
                return AST::Action::Replace;
            }
        }

        return AST::Action::None;
    }

    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        funs.emplace_back();
        return AST::Action::None;
    }

    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement)
    {
        funs.pop_back();
        return AST::Action::None;
    }

  private:
    FunInfo* GetFun(std::u16string_view name)
    {
        for (auto it = funs.rbegin(); it != funs.rend(); ++it) {
            if (it->find(name) != it->end()) {
                return &(*it)[name];
            }
        }

        return nullptr;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest InlineFunctions::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    FunctionInliner inliner;

    // return PluginAfterActionRequest::None;

    AST::PluginVisitor visitor(&inliner, &data.editor);

    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins