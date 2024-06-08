#pragma once

#include "ast.hpp"

#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <stack>

namespace GView::Type::JS::Transformers
{
class ConstPropagator : public AST::Plugin
{
    struct VarInfo {
        AST::Constant* value = nullptr;

        bool allocated = false;
        bool dirty     = false;

        void SetValue(AST::Constant* val, bool wasAllocated);

        AST::Constant* GetValue();

        AST::Constant* GetClone();

        ~VarInfo();
    };

    bool inAssignment = false;

    std::vector<std::unordered_map<std::u16string_view, VarInfo>> vars;
    std::unordered_set<std::u16string_view> dirty;

    AST::IfStmt* uncertainIf = nullptr; // Unknown condition in IfStmt, so don't propagate further

  public:
    AST::Action OnEnterVarDecl(AST::VarDecl* node, AST::Decl*& replacement);

    AST::Action OnEnterIdentifier(AST::Identifier* node, AST::Expr*& replacement);

    AST::Action OnEnterIfStmt(AST::IfStmt* node, AST::Stmt*& replacement);

    AST::Action OnExitIfStmt(AST::IfStmt* node, AST::Stmt*& replacement);

    AST::Action OnEnterBlock(AST::Block* node, AST::Block*& replacement);

    AST::Action OnExitBlock(AST::Block* node, AST::Block*& replacement);

    AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement);

    AST::Action OnExitBinop(AST::Binop* node, AST::Expr*& replacement);

  private:
    VarInfo* GetVarValue(std::u16string_view name);

    std::unordered_map<std::u16string_view, VarInfo>* GetVarScope(std::u16string_view name);

    static AST::Number* Clone(AST::Number* num);

    static AST::String* Clone(AST::String* str);

    static AST::Constant* Clone(AST::Constant* constant);

    uint32 GetOpFromAssignment(uint32 op);

    std::optional<int32> Eval(int32 left, int32 right, uint32 op);

    std::optional<std::u16string> Eval(int32 left, std::u16string_view right, uint32 op);

    std::optional<std::u16string> Eval(std::u16string_view left, int32 right, uint32 op);

    std::optional<std::u16string> Eval(std::u16string_view left, std::u16string_view right, uint32 op);
};
} // namespace GView::Type::JS::Transformers