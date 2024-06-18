#include "Transformers/DeadCodeRemover.hpp"

namespace GView::Type::JS::Transformer
{
    AST::Action DeadCodeRemover::CheckDead()
    {
        if (dead) {
            return AST::Action::Remove;
        }

        return AST::Action::None;
    }

    bool DeadCodeRemover::IsConstIf(AST::IfStmt* node)
    {
        return (node->cond->GetExprType() == AST::ExprType::Constant);
    }

    bool DeadCodeRemover::IsConstWhile(AST::WhileStmt* node)
    {
        return (node->cond->GetExprType() == AST::ExprType::Constant);
    }

    AST::Action DeadCodeRemover::OnExitFunDecl(AST::FunDecl* node, AST::Decl*& replacement)
    {
        dead = false;
        return AST::Action::None;
    }

    AST::Action DeadCodeRemover::OnEnterVarDeclList(AST::VarDeclList* node, AST::Decl*& replacement)
    {
        return CheckDead();
    }
    AST::Action DeadCodeRemover::OnEnterBlock(AST::Block* node, AST::Block*& replacement)
    {
        return CheckDead();
    }
    AST::Action DeadCodeRemover::OnEnterIfStmt(AST::IfStmt* node, AST::Stmt*& replacement)
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

    AST::Action DeadCodeRemover::OnEnterWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement)
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
    AST::Action DeadCodeRemover::OnEnterForStmt(AST::ForStmt* node, AST::Stmt*& replacement)
    {
        return CheckDead();
    }
    AST::Action DeadCodeRemover::OnEnterReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement)
    {
        return CheckDead();
    }
    AST::Action DeadCodeRemover::OnEnterExprStmt(AST::ExprStmt* node, AST::Stmt*& replacement)
    {
        return CheckDead();
    }

    AST::Action DeadCodeRemover::OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement)
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

    AST::Action DeadCodeRemover::OnExitWhileStmt(AST::WhileStmt* node, AST::Stmt*& replacement)
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

    AST::Action DeadCodeRemover::OnExitReturnStmt(AST::ReturnStmt* node, AST::Stmt*& replacement)
    {
        dead = true;

        return AST::Action::None;
    }
}