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

bool IsNumber(AST::Expr* expr)
{
    return expr->GetExprType() == AST::ExprType::Constant && ((AST::Constant*) expr)->GetConstType() == AST::ConstType::Number;
}

bool IsString(AST::Expr* expr)
{
    return expr->GetExprType() == AST::ExprType::Constant && ((AST::Constant*) expr)->GetConstType() == AST::ConstType::String;
}

AST::Expr* EvalWindow(AST::Expr* member)
{
    switch (member->GetExprType()) {
    case AST::ExprType::Identifier: {
        return new AST::Identifier(((AST::Identifier*) member)->name);
    }
    case AST::ExprType::Constant: {
        if (((AST::Constant*) member)->GetConstType() == AST::ConstType::String) {
            return new AST::Identifier(((AST::String*) member)->value);
        }
        break;
    }
    }
    return nullptr;
}

AST::Expr* EvalStringFromCharCode(std::vector<AST::Expr*>& args)
{
    if (args.size() != 1 || !IsNumber(args[0])) {
        return nullptr;
    }

    auto num = ((AST::Number*) args[0])->value;

    std::u16string result;
    result += (char16_t) num;

    return new AST::String(result);
}

AST::Expr* EvalMathMin(std::vector<AST::Expr*>& args)
{
    if (args.size() == 0 || !IsNumber(args[0])) {
        return nullptr;
    }

    auto min = ((AST::Number*) args[0])->value;

    for (auto arg : args) {
        if (!IsNumber(arg)) {
            return nullptr;
        }

        auto val = ((AST::Number*) arg)->value;

        if (val < min) {
            min = val;
        }
    }

    return new AST::Number(min);
}

AST::Expr* EvalMathMax(std::vector<AST::Expr*>& args)
{
    if (args.size() == 0 || !IsNumber(args[0])) {
        return nullptr;
    }

    auto max = ((AST::Number*) args[0])->value;

    for (auto arg : args) {
        if (!IsNumber(arg)) {
            return nullptr;
        }

        auto val = ((AST::Number*) arg)->value;

        if (val > max) {
            max = val;
        }
    }

    return new AST::Number(max);
}

AST::Expr* EvalStringCharCodeAt(AST::String* str, std::vector<AST::Expr*>& args)
{
    if (args.size() != 1 || !IsNumber(args[0])) {
        return nullptr;
    }

    auto num = ((AST::Number*) args[0])->value;

    if (num < 0 || num >= str->value.size()) {
        return nullptr;
    }

    auto result = (int32) str->value[num];

    return new AST::Number(result);
}

AST::Expr* EvalStringCharAt(AST::String* str, std::vector<AST::Expr*>& args)
{
    if (args.size() != 1 || !IsNumber(args[0])) {
        return nullptr;
    }

    auto num = ((AST::Number*) args[0])->value;

    if (num < 0 || num >= str->value.size()) {
        return nullptr;
    }

    std::u16string result;
    result += str->value[num];

    return new AST::String(result);
}

AST::Expr* EvalStringReplaceAll(AST::String* str, std::vector<AST::Expr*>& args)
{
    if (args.size() != 2 || !IsString(args[0]) || !IsString(args[1])) {
        return nullptr;
    }

    auto old         = ((AST::String*) args[0])->value;
    auto replacement = ((AST::String*) args[1])->value;

    std::u16string result(str->value);

    size_t start = 0;

    while ((start = result.find(old, start)) != std::u16string::npos) {
        result.replace(start, old.size(), replacement);
        start += replacement.size();
    }

    return new AST::String(result);
}

typedef AST::Expr* (*MemberAccessFn)(AST::Expr*);
typedef AST::Expr* (*MemberAccessCallFn)(std::vector<AST::Expr*>&);
typedef AST::Expr* (*StringMemberAccessCallFn)(AST::String*, std::vector<AST::Expr*>&);

std::unordered_map<std::u16string_view, MemberAccessFn> constMemberAccess{ { u"window", EvalWindow } };
std::unordered_map<std::u16string_view, std::unordered_map<std::u16string_view, MemberAccessCallFn>> constMemberAccessCall{
    { u"String", { { u"fromCharCode", EvalStringFromCharCode } } }, { u"Math", { { u"min", EvalMathMin }, { u"max", EvalMathMax } } }
};

std::unordered_map<std::u16string_view, StringMemberAccessCallFn> constStringMemberAccessCall{ { u"charCodeAt", EvalStringCharCodeAt },
                                                                                               { u"charAt", EvalStringCharAt },
                                                                                               { u"replaceAll", EvalStringReplaceAll } };

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

    virtual AST::Action OnExitMemberAccess(AST::MemberAccess* node, AST::Expr*& replacement) override
    {
        auto obj = node->obj;

        if (obj->GetExprType() == AST::ExprType::Identifier) {
            auto entry = constMemberAccess.find(((AST::Identifier*) obj)->name);

            if (entry != constMemberAccess.end()) {
                replacement = (*entry).second(node->member);

                if (replacement != nullptr) {
                    return AST::Action::Replace;
                }

                return AST::Action::None;
            }
        }

        return AST::Action::None;
    }

    virtual AST::Action OnExitCall(AST::Call* node, AST::Expr*& replacement)
    {
        if (node->callee->GetExprType() == AST::ExprType::MemberAccess) {
            auto access = (AST::MemberAccess*) node->callee;

            std::u16string_view member;

            switch (access->member->GetExprType()) {
            case AST::ExprType::Identifier: {
                member = ((AST::Identifier*) access->member)->name;
                break;
            }
            case AST::ExprType::Constant: {
                if (((AST::Constant*) access->member)->GetConstType() != AST::ConstType::String) {
                    return AST::Action::None;
                }

                member = ((AST::String*) access->member)->value;
                break;
            }
            default: {
                return AST::Action::None;
            }
            }

            switch (access->obj->GetExprType()) {
            case AST::ExprType::Identifier: {
                auto obj = (AST::Identifier*) access->obj;

                auto entry = constMemberAccessCall.find(obj->name);

                if (entry == constMemberAccessCall.end()) {
                    return AST::Action::None;
                }

                auto memberEntry = (*entry).second.find(member);

                if (memberEntry == (*entry).second.end()) {
                    return AST::Action::None;
                }

                replacement = (*memberEntry).second(node->args);

                if (replacement != nullptr) {
                    return AST::Action::Replace;
                }
                return AST::Action::None;
            }
            case AST::ExprType::Constant: {
                if (((AST::Constant*) access->obj)->GetConstType() != AST::ConstType::String) {
                    return AST::Action::None;
                }

                auto obj = (AST::String*) access->obj;

                auto entry = constStringMemberAccessCall.find(member);

                if (entry == constStringMemberAccessCall.end()) {
                    return AST::Action::None;
                }

                replacement = (*entry).second(obj, node->args);

                if (replacement != nullptr) {
                    return AST::Action::Replace;
                }

                return AST::Action::None;
            }
            }
        }

        return AST::Action::None;
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
            result = leftVal % rightVal;
            break;
        }
        case TokenType::Operator_Exponential: {
            result = (int32) pow(leftVal, rightVal);
            break;
        }
        default: {
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