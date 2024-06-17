#include "js.hpp"
#include "ast.hpp"

#include <stack>

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view RemoveDeadCode::GetName()
{
    return "Remove Dead Code";
}
std::string_view RemoveDeadCode::GetDescription()
{
    return "Remove dead code.";
}
bool RemoveDeadCode::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class DeadCodeRemover : public AST::Plugin
{
    bool dead   = false;

    AST::Action CheckDead()
    {
        if (dead) {
            return AST::Action::Remove;
        }

        return AST::Action::None;
    }

    bool IsConstIf(AST::IfStmt* node)
    {
        return (node->cond->GetExprType() == AST::ExprType::Constant);
    }

    bool IsConstWhile(AST::WhileStmt* node)
    {
        return (node->cond->GetExprType() == AST::ExprType::Constant);
    }

  public:
    AST::Action OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacemente)
    {
        return CheckDead();
    }
    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        return CheckDead();
    }
    AST::Action OnEnterIfStmt(AST::IfStmt* node, AST::Stmt*& replacement)
    {
        auto action = CheckDead();

        if (action != AST::Action::None) {
            return action;
        }

        if (IsConstIf(node)) {
            auto cond = (AST::Constant*) node->cond;
            if (cond->GetConstType() == AST::ConstType::Number) {
                if (((AST::Number*) cond)->value != 0) {
                    // if (true)

                    auto stmtTrue = node->stmtTrue;

                    // Prevent the parent from deleting stmtTrue since it will replace it
                    node->stmtTrue = nullptr;

                    replacement = stmtTrue;
                    return AST::Action::Replace_Revisit;
                } else {
                    // if (false)

                    if (node->stmtFalse) {
                        auto stmtFalse = node->stmtFalse;

                        // Prevent the parent from deleting stmtFalse since it will replace it
                        node->stmtFalse = nullptr;

                        replacement = stmtFalse;
                        return AST::Action::Replace_Revisit;
                    } else {
                        return AST::Action::Remove;
                    }
                }
            } else if (cond->GetConstType() == AST::ConstType::Bool) {
                if (((AST::Bool*) cond)->value) {
                    // if (true)

                    auto stmtTrue = node->stmtTrue;

                    // Prevent the parent from deleting stmtTrue since it will replace it
                    node->stmtTrue = nullptr;

                    replacement = stmtTrue;
                    return AST::Action::Replace_Revisit;
                } else {
                    // if (false)

                    if (node->stmtFalse) {
                        auto stmtFalse = node->stmtFalse;

                        // Prevent the parent from deleting stmtFalse since it will replace it
                        node->stmtFalse = nullptr;

                        replacement = stmtFalse;
                        return AST::Action::Replace_Revisit;
                    } else {
                        return AST::Action::Remove;
                    }
                }
            }
        }

        return AST::Action::None;
    }

    AST::Action OnEnterWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement)
    {
        auto action = CheckDead();

        if (action != AST::Action::None) {
            return action;
        }

        if (IsConstWhile(node)) {
            auto cond = (AST::Constant*) node->cond;
            if (cond->GetConstType() == AST::ConstType::Number) {
                if (((AST::Number*) cond)->value == 0) {
                    // while (false)
                    return AST::Action::Remove;
                }
            }
        }

        return AST::Action::None;
    }
    AST::Action OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement)
    {
        return CheckDead();
    }
    AST::Action OnEnterReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement)
    {
        return CheckDead();
    }
    AST::Action OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement)
    {
        return CheckDead();
    }

    virtual AST::Action OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement) override
    {
        if (dead) {
            // Since we exited from an If, 'dead' was set inside it
            // (otherwise the If would've been deleted in Enter)
            // If it's not a constant If, make sure to set dead=false to not delete stuff outside it
            if (!IsConstIf(node)) {
                dead = false;
            }
        }

        return AST::Action::None;
    }

    virtual AST::Action OnExitWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement) override
    {
        if (dead) {
            // Since we exited from a While, 'dead' was set inside it
            // (otherwise the While would've been deleted in Enter)
            // If it's not a constant While, make sure to set dead=false to not delete stuff outside it
            if (!IsConstWhile(node)) {
                dead = false;
            }
        }

        return AST::Action::None;
    }

    virtual AST::Action OnExitReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement) override
    {
        dead = true;

        return AST::Action::None;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest RemoveDeadCode::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    DeadCodeRemover remover;
    AST::PluginVisitor visitor(&remover, &data.editor);

    // TODO: instance should also handle the action for the script block
    AST::Node* _rep;
    i.script->Accept(visitor, _rep);

    {
        AST::DumpVisitor dump("_ast_after.json");
        i.script->AcceptConst(dump);
    }

    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins