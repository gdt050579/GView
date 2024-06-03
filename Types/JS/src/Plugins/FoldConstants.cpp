#include "js.hpp"
#include "ast.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;
using namespace GView::Type::JS;

std::string_view FoldConstants::GetName()
{
    return "Fold Constants";
}
std::string_view FoldConstants::GetDescription()
{
    return "Apply const folding.";
}
bool FoldConstants::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}

class ConstFolder : public AST::Plugin
{
  public:
    virtual AST::Action OnEnterBinop(AST::Binop* node, AST::Expr*& replacement) override
    {
        return FoldBinop(node, replacement);
    }

    virtual AST::Action OnExitBinop(AST::Binop* node, AST::Expr*& replacement) override
    {
        return FoldBinop(node, replacement);
    }

  private:
    AST::Expr* Fold(AST::Number* left, AST::Number* right, uint32 op)
    {
        auto leftVal  = left->value;
        auto rightVal = right->value;

        int32 result = 0;

        switch (op) {
        case TokenType::Operator_LogicOR: {
            result = leftVal || rightVal;
            break;
        }
        case TokenType::Operator_LogicAND: {
            result = leftVal && rightVal;
            break;
        }
        case TokenType::Operator_OR: {
            result = leftVal | rightVal;
            break;
        }
        case TokenType::Operator_XOR: {
            result = leftVal ^ rightVal;
            break;
        }
        case TokenType::Operator_AND: {
            result = leftVal & rightVal;
            break;
        }
        case TokenType::Operator_Equal:
        case TokenType::Operator_StrictEqual: {
            result = leftVal == rightVal;
            break;
        }
        case TokenType::Operator_Different:
        case TokenType::Operator_StrictDifferent: {
            result = leftVal != rightVal;
            break;
        }
        case TokenType::Operator_Smaller: {
            result = leftVal < rightVal;
            break;
        }
        case TokenType::Operator_SmallerOrEQ: {
            result = leftVal <= rightVal;
            break;
        }
        case TokenType::Operator_Bigger: {
            result = leftVal > rightVal;
            break;
        }
        case TokenType::Operator_BiggerOrEq: {
            result = leftVal >= rightVal;
            break;
        }
        case TokenType::Operator_LeftShift: {
            result = leftVal << rightVal;
            break;
        }
        case TokenType::Operator_RightShift: {
            result = leftVal >> rightVal;
            break;
        }
        case TokenType::Operator_SignRightShift: {
            result = leftVal >> rightVal;
            break;
        }
        case TokenType::Operator_Plus: {
            result = leftVal + rightVal;
            break;
        }
        case TokenType::Operator_Minus: {
            result = leftVal - rightVal;
            break;
        }
        case TokenType::Operator_Multiply: {
            result = leftVal * rightVal;
            break;
        }
        case TokenType::Operator_Division: {
            if (rightVal == 0) {
                return nullptr;
            }
            result = leftVal / rightVal;
            break;
        }
        case TokenType::Operator_Modulo: {
            if (rightVal == 0) {
                return nullptr;
            }
            result = leftVal & rightVal;
            break;
        }
        case TokenType::Operator_Exponential: {
            result = (int32) pow(leftVal, rightVal);
            break;
        }
        default: 
            {
            return nullptr;
        }
        }

        return new AST::Number(result);
    }

    AST::Expr* Fold(AST::Number* left, AST::String* right, uint32 op)
    {
        auto leftVal  = left->value;
        auto rightVal = right->value;

        switch (op) {
        case TokenType::Operator_Plus: {
            AppCUI::Utils::UnicodeStringBuilder builder;
            AppCUI::Utils::NumericFormatter fmt;
            
            builder.Add(fmt.ToDec(leftVal));
            builder.Add(rightVal);

            std::u16string result;
            builder.ToString(result);

            return new AST::String(result);
        }
        }

        return nullptr;
    }

    AST::Expr* Fold(AST::String* left, AST::Number* right, uint32 op)
    {
        auto leftVal  = left->value;
        auto rightVal = right->value;

        switch (op) {
        case TokenType::Operator_Plus: {
            AppCUI::Utils::UnicodeStringBuilder builder;
            AppCUI::Utils::NumericFormatter fmt;

            builder.Add(leftVal);
            builder.Add(fmt.ToDec(rightVal));

            std::u16string result;
            builder.ToString(result);

            return new AST::String(result);
        }
        }

        return nullptr;
    }

    AST::Expr* Fold(AST::String* left, AST::String* right, uint32 op)
    {
        auto leftVal  = left->value;
        auto rightVal = right->value;

        switch (op) {
        case TokenType::Operator_Plus: {
            return new AST::String(leftVal + rightVal);
        }
        }

        return nullptr;
    }

    AST::Expr* Fold(AST::Constant* left, AST::Constant* right, uint32 op)
    {
        auto leftType  = left->GetConstType();
        auto rightType = right->GetConstType();

        switch (leftType) {
        case AST::ConstType::Number: {
            switch (rightType) {
            case AST::ConstType::Number: {
                return Fold((AST::Number*) left, (AST::Number*) right, op);
            }
            case AST::ConstType::String: {
                return Fold((AST::Number*) left, (AST::String*) right, op);
            }
            }
            break;
        case AST::ConstType::String: {
            switch (rightType) {
            case AST::ConstType::Number: {
                return Fold((AST::String*) left, (AST::Number*) right, op);
            }
            case AST::ConstType::String: {
                return Fold((AST::String*) left, (AST::String*) right, op);
            }
            }
            break;
        }
        }
        }

        return nullptr;
    }

    AST::Action FoldBinop(AST::Binop* node, AST::Expr*& replacement)
    {
        auto left = node->left;

        while (left && left->GetExprType() == AST::ExprType::Grouping) {
            left = ((AST::Grouping*) left)->expr;
        }

        auto right = node->right;

        while (right && right->GetExprType() == AST::ExprType::Grouping) {
            right = ((AST::Grouping*) right)->expr;
        }

        if (left->GetExprType() == AST::ExprType::Constant && right->GetExprType() == AST::ExprType::Constant) {
            auto result = Fold((AST::Constant*) left, (AST::Constant*) right, node->type);

            if (result) {
                replacement = result;
                return AST::Action::Replace;
            }
        }

        return AST::Action::None;
    }
};

GView::View::LexicalViewer::PluginAfterActionRequest FoldConstants::Execute(GView::View::LexicalViewer::PluginData& data)
{
    AST::Instance i;
    i.Create(data.tokens);

    {
        AST::DumpVisitor dump("_ast.json");
        i.script->AcceptConst(dump);
    }

    // return PluginAfterActionRequest::None;

    ConstFolder folder;
    AST::PluginVisitor visitor(&folder, &data.editor);

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