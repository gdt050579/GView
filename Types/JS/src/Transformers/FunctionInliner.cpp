#include "Transformers/FunctionInliner.hpp"
#include "Transformers/DynamicPropagator.hpp"

namespace GView::Type::JS::Transformer
{
AST::Action FunctionInliner::OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
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

AST::Action FunctionInliner::OnEnterCall(AST::Call* node, AST::Expr*& replacement)
{
    if (node->callee->GetExprType() == AST::ExprType::Identifier) {
        auto id = (AST::Identifier*) node->callee;

        auto fun = GetFun(id->name);

        if (fun) {
            auto expr = fun->returnValue->Clone();

            Transformers::DynamicPropagator propagator;

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

AST::Action FunctionInliner::OnEnterBlock(AST::Block* node, AST::Block*& replacement)
{
    funs.emplace_back();
    return AST::Action::None;
}

AST::Action FunctionInliner::OnExitBlock(AST::Block* node, AST::Block*& replacement)
{
    funs.pop_back();
    return AST::Action::None;
}

FunctionInliner::FunInfo* FunctionInliner::GetFun(std::u16string_view name)
{
    for (auto it = funs.rbegin(); it != funs.rend(); ++it) {
        if (it->find(name) != it->end()) {
            return &(*it)[name];
        }
    }

    return nullptr;
}
} // namespace GView::Types::JS::Transformer